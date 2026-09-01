"""Scan orchestrator — sequences plugins through the scan pipeline.

The orchestrator is the central nervous system of redveil. It coordinates
plugin execution across the discovery → detect → validate → evidence →
assess pipeline, drives the lifecycle state machine, and emits events at
each transition so subscribers (renderers, loggers, reporters) can react.

The orchestrator is intentionally check-agnostic. All vulnerability
specifics live in plugins; the orchestrator only sequences them and emits
events. This separation keeps the framework extensible: adding a new check
requires no orchestrator changes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redveil.config import RedVeilConfig
from redveil.core.event_bus import Event, EventBus, EventType
from redveil.core.lifecycle import ScanContext, ScanState
from redveil.evidence.evidence import Evidence
from redveil.findings.confidence import Confidence
from redveil.findings.deduplicator import FindingDeduplicator
from redveil.findings.finding import Finding, FindingStatus
from redveil.plugins.base import (
    CheckDependencies,
    ValidationOutcome,
    ValidationResult,
)
from redveil.plugins.registry import Registry

if TYPE_CHECKING:
    from redveil.http.client import HttpClient


@dataclass
class OrchestratorDeps:
    """Wired-up dependencies for an orchestrator run.

    Carries the event bus, plugin registry, the orchestrator-owned HttpClient,
    and the RedVeilConfig. The HttpClient and ScopeController it wraps are
    passed into every check via ``bind()`` — plugins never instantiate their
    own. Keeping dependencies behind a dataclass makes the constructor stable
    as the framework grows (reporting sinks, evidence stores, etc.).
    """

    bus: EventBus
    registry: Registry
    config: RedVeilConfig
    http: HttpClient


class Orchestrator:
    """Runs the discover → detect → validate → evidence → assess pipeline
    across all registered checks.

    The orchestrator is intentionally check-agnostic. All vulnerability
    specifics live in plugins; the orchestrator only sequences them and
    emits events.
    """

    def __init__(self, deps: OrchestratorDeps, ctx: ScanContext):
        self._bus = deps.bus
        self._registry = deps.registry
        self._config = deps.config
        self._http = deps.http
        self._ctx = ctx
        # Evidence store: id -> Evidence. Kept on the orchestrator so it
        # survives the full scan and can be handed to the reporter.
        self._evidence: dict[str, Evidence] = {}
        # Deduplicator for findings discovered across checks
        self._dedup = FindingDeduplicator()
        # Behavior Engine: ApplicationModel + StateHistory. Built lazily
        # after the first pass (during run()).
        self._application_model = None
        self._behavior_model = None
        self._bind_all_checks()

    def _bind_all_checks(self) -> None:
        """Bind the orchestrator-owned dependencies into every registered check.

        Performed once at construction so checks can use ``self.deps`` in any
        phase. Subsequent calls to ``bind()`` (e.g. defensive calls inside
        ``_check_phase``) are no-ops because ``bind()`` is idempotent.
        """
        deps = CheckDependencies(
            http=self._http,
            scope=self._http._scope,
            config=self._config,
            context=self._ctx,
            application_model=self._application_model,
            behavior_model=self._behavior_model,
        )
        for check in self._registry.all():
            check.bind(deps)

    async def _build_application_model(self) -> None:
        """Build the ApplicationModel via AttackSurfaceMapper.

        Called once during the discovery phase. After the model is built,
        we re-bind all checks so they can read it via deps.application_model.
        """
        from redveil.attack_surface import AttackSurfaceMapper
        from redveil.behavior import BehaviorModel

        try:
            mapper = AttackSurfaceMapper(self._http, self._config)
            self._application_model = await mapper.build()
            self._behavior_model = BehaviorModel(
                application_model=self._application_model,
            )
            self._behavior_model.attach_http(self._http)
            self._bind_all_checks()
        except Exception as e:
            # Non-fatal: checks that don't need the model still work.
            self._bus.publish(Event(
                EventType.ERROR, source="attack_surface_mapper",
                data={"phase": "model_build", "error": str(e),
                      "type": type(e).__name__},
            ))

    @property
    def application_model(self):
        return self._application_model

    @property
    def evidence_store(self) -> dict[str, Evidence]:
        """Read-only view of the evidence captured so far."""
        return dict(self._evidence)

    async def run(self) -> ScanContext:
        """Execute the scan to completion.

        Drives the lifecycle through DISCOVERING -> DISCOVERY_COMPLETE ->
        CHECKING -> VALIDATING -> REPORTING -> COMPLETED. On any
        exception, transitions to FAILED, publishes an ERROR event, and
        re-raises so the caller can decide how to handle the failure.

        Always publishes SCAN_FINISHED on the way out (both success and
        failure paths), so subscribers can rely on it as the terminal
        signal.
        """
        await self._bus.publish(
            Event(
                EventType.SCAN_STARTED,
                source="orchestrator",
                data={"target": self._ctx.target_name, "run_id": self._ctx.run_id},
            )
        )

        try:
            await self._discovery_phase()
            self._ctx.transition(ScanState.DISCOVERY_COMPLETE)

            await self._check_phase()
            self._ctx.transition(ScanState.VALIDATING)

            await self._validate_phase()
            self._ctx.transition(ScanState.REPORTING)

            await self._report_phase()
            self._ctx.transition(ScanState.COMPLETED)

        except Exception as e:
            self._ctx.transition(ScanState.FAILED)
            await self._bus.publish(
                Event(
                    EventType.ERROR,
                    source="orchestrator",
                    data={
                        "phase": self._ctx.state.value,
                        "error": str(e),
                        "type": type(e).__name__,
                    },
                )
            )
            await self._bus.publish(
                Event(
                    EventType.SCAN_FINISHED,
                    source="orchestrator",
                    data={"findings": len(self._ctx.findings), "run_id": self._ctx.run_id},
                )
            )
            raise

        await self._bus.publish(
            Event(
                EventType.SCAN_FINISHED,
                source="orchestrator",
                data={"findings": len(self._ctx.findings), "run_id": self._ctx.run_id},
            )
        )
        return self._ctx

    async def _discovery_phase(self) -> None:
        """Run discover() on every registered check.

        Discovers endpoints, parameters, and other surface area. Plugins that
        don't implement discover() raise NotImplementedError, which is
        treated as "no-op for this phase".
        """
        self._ctx.transition(ScanState.DISCOVERING)
        await self._bus.publish(Event(EventType.DISCOVERY_STARTED, source="orchestrator"))
        # Build the ApplicationModel via AttackSurfaceMapper BEFORE running
        # any check.discover() so checks that consume the model have it ready.
        await self._build_application_model()
        for check in self._registry.all():
            try:
                await check.discover(self._ctx)  # type: ignore[arg-type]
            except NotImplementedError:
                pass
        await self._bus.publish(Event(EventType.DISCOVERY_ENDED, source="orchestrator"))

    async def _check_phase(self) -> None:
        """Run discover() on every registered check and emit candidates.

        Each check produces candidate findings, which are emitted as
        FINDING_DETECTED events. The actual validation/evidence/assess
        happens in the validate phase. This split keeps the discovery
        and the heavy lifting separable for future async parallelism.
        """
        self._ctx.transition(ScanState.CHECKING)
        # Defensive re-bind: checks should already have been bound at
        # construction time. If a plugin replaced itself in the registry
        # between init and run, we still want it to have its deps.
        deps = CheckDependencies(
            http=self._http,
            scope=self._http._scope,
            config=self._config,
            context=self._ctx,
        )
        for check in self._registry.all():
            if check._deps is None:  # type: ignore[attr-defined]
                check.bind(deps)
            await self._bus.publish(Event(EventType.CHECK_STARTED, source=check.id))
            try:
                candidates = await check.discover(self._ctx)  # type: ignore[arg-type]
            except NotImplementedError:
                candidates = []
            for candidate in candidates or []:
                await self._bus.publish(
                    Event(
                        EventType.FINDING_DETECTED,
                        source=check.id,
                        data={"candidate": str(candidate)},
                    )
                )
            await self._bus.publish(Event(EventType.CHECK_ENDED, source=check.id))

    async def _validate_phase(self) -> None:
        """Validate, collect evidence, and assess each candidate.

        For each check, we re-run discover() to get candidates, then for
        each candidate:
            1. validate()  -> ValidationResult
            2. (if confirmed/likely) collect_evidence()
            3. assess()    -> Finding
        Findings are deduplicated by fingerprint and appended to ctx.findings.

        Also emits VALIDATION_STARTED for any findings pre-populated into
        ctx.findings (preserves the Phase 1 contract used by tests and
        by callers that hand-construct findings).
        """
        # Backwards-compat: announce validation for any findings already in ctx.
        for pre in self._ctx.findings:
            await self._bus.publish(
                Event(
                    EventType.VALIDATION_STARTED,
                    source="orchestrator",
                    data={"finding_id": getattr(pre, "id", "?")},
                )
            )

        deps = CheckDependencies(
            http=self._http,
            scope=self._http._scope,
            config=self._config,
            context=self._ctx,
        )

        for check in self._registry.all():
            if check._deps is None:  # type: ignore[attr-defined]
                check.bind(deps)

            # Pull candidates for this check
            try:
                candidates = await check.discover(self._ctx)  # type: ignore[arg-type]
            except NotImplementedError:
                continue
            if not candidates:
                continue

            for candidate in candidates:
                candidate_id = getattr(candidate, "id", None) or str(candidate)
                await self._bus.publish(
                    Event(
                        EventType.VALIDATION_STARTED,
                        source=check.id,
                        data={"candidate_id": candidate_id, "finding_id": candidate_id},
                    )
                )

                # 1. Validate
                validation: ValidationResult | None = None
                try:
                    validation = await check.validate(self._ctx, candidate)  # type: ignore[arg-type]
                except NotImplementedError:
                    validation = None

                if validation is None:
                    # No validation required; we'll still try to assess().
                    validation = ValidationResult(
                        outcome=ValidationOutcome.LIKELY,
                        confidence="medium",
                        observation="no validation provided",
                    )

                outcome = validation.outcome
                await self._bus.publish(
                    Event(
                        EventType.VALIDATION_ENDED,
                        source=check.id,
                        data={
                            "candidate_id": candidate_id,
                            "outcome": outcome.value,
                            "confidence": validation.confidence,
                        },
                    )
                )

                if outcome is ValidationOutcome.FALSE_POSITIVE:
                    # Drop candidate
                    continue

                # 2. Collect evidence (from validate() result + collect_evidence())
                evidence: list[Evidence] = list(validation.evidence)
                try:
                    more = await check.collect_evidence(candidate)  # type: ignore[arg-type]
                except NotImplementedError:
                    more = []
                evidence.extend(more)

                # Store evidence and publish EVIDENCE_CAPTURED per item
                for ev in evidence:
                    self._evidence[ev.id] = ev
                    await self._bus.publish(
                        Event(
                            EventType.EVIDENCE_CAPTURED,
                            source=check.id,
                            data={
                                "evidence_id": ev.id,
                                "kind": ev.kind.value,
                                "endpoint": ev.endpoint,
                            },
                        )
                    )

                # 3. Assess (produce Finding)
                finding: Finding | None = None
                try:
                    finding = await check.assess(candidate)  # type: ignore[arg-type]
                except NotImplementedError:
                    finding = None

                if finding is None:
                    # Check didn't produce a Finding; skip
                    continue

                # Backfill evidence ids + status
                evidence_ids = list(set(finding.evidence_ids) | {ev.id for ev in evidence})
                # Map confidence string from validation into the enum if needed
                confidence_enum = finding.confidence
                try:
                    confidence_enum = Confidence(validation.confidence)
                except ValueError:
                    confidence_enum = finding.confidence

                status = (
                    FindingStatus.CONFIRMED
                    if outcome is ValidationOutcome.CONFIRMED
                    else FindingStatus.LIKELY
                    if outcome is ValidationOutcome.LIKELY
                    else FindingStatus.INCONCLUSIVE
                )

                finding = finding.model_copy(update={
                    "evidence_ids": evidence_ids,
                    "confidence": confidence_enum,
                    "status": status,
                })

                # Register the finding through the deduplicator
                merged = self._dedup.add(finding)
                if merged.id not in {f.id for f in self._ctx.findings}:
                    self._ctx.findings.append(merged)

                if outcome is ValidationOutcome.CONFIRMED:
                    await self._bus.publish(
                        Event(
                            EventType.FINDING_CONFIRMED,
                            source=check.id,
                            data={
                                "finding_id": merged.id,
                                "severity": merged.severity.value,
                                "confidence": merged.confidence.value,
                            },
                        )
                    )

    async def _report_phase(self) -> None:
        """Render the final report.

        Publishes a REPORT_GENERATED event carrying the finding count and
        the final deduplicated list. Report rendering (markdown/json/html)
        is a separate, pluggable step handled by the CLI / reporters.
        """
        await self._bus.publish(
            Event(
                EventType.REPORT_GENERATED,
                source="orchestrator",
                data={
                    "findings_count": len(self._ctx.findings),
                    "evidence_count": len(self._evidence),
                },
            )
        )
