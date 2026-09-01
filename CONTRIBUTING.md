# Contributing to redveil

Thanks for your interest in redveil! This project is a defensive security framework, and contributions are welcome.

## Code of Conduct

This project follows a simple rule: **be respectful**. We're all here to make security testing better for the good guys. Disagreements about design are fine; personal attacks are not.

## What to contribute

### Welcome
- New check plugins (e.g., XXE, SSTI, deserialization)
- Improvements to existing checks
- Bug fixes
- Documentation improvements
- New example scope files for specific scenarios
- Test coverage improvements
- Performance improvements

### Please discuss first
- Major architectural changes (open an issue before PR)
- Changes to the safety model (any change that might affect destructive behavior)
- Changes to the scope controller
- Changes to the event bus or plugin base

### Out of scope
- Adding actual exploit primitives (reverse shells, bind shells, RCE payloads)
- Hardcoded credentials
- Targets that hit private IP ranges as defaults

## Development setup

```bash
git clone https://github.com/FitzyPrjkt/Redveil.git
cd redveil
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -q
```

## Adding a new check plugin

1. Create a file in `src/redveil/checks/<your_check>.py`
2. Subclass `redveil.plugins.base.Check`
3. Implement `discover()`, `validate()`, `collect_evidence()`, `assess()`
4. Add a knowledge base entry in `src/redveil/knowledge/vuln_descriptions.py` (rich content: summary, technical, attack_scenario, impact, remediation, code_examples for 4+ frameworks)
5. Register the entry point in `pyproject.toml` under `[project.entry-points."redveil.checks"]`
6. Write tests in `tests/test_check_<your_check>.py`
7. Verify: `redveil list-checks` shows your new check, and `pytest tests/test_check_<your_check>.py` passes

Example skeleton:
```python
from redveil.plugins.base import Check, CheckCategory, CheckMeta, ValidationOutcome, ValidationResult
from redveil.findings.finding import Finding, CheckRef, TargetRef, FindingStatus
from redveil.findings.severity import Severity
from redveil.findings.confidence import Confidence
from redveil.evidence.evidence import Evidence, ObservationKind
from redveil.http.request import Request
from redveil.knowledge.vuln_descriptions import get_entry
from redveil.util.urls import join_url
from redveil.config import SafetyProfile


class MyCheck(Check):
    meta = CheckMeta(
        id="my-check",
        name="My Check",
        category=CheckCategory.XXX,  # appropriate category
        safety_profile=SafetyProfile.PASSIVE,  # or ACTIVE
        description="What this check does.",
    )

    async def discover(self, ctx):
        if not self.deps:
            return []
        # Make requests via self.deps.http.send(...)
        # Return list of candidate dicts
        return []

    async def validate(self, ctx, candidate):
        return ValidationResult(outcome=ValidationOutcome.CONFIRMED, confidence="high", observation="...")

    async def collect_evidence(self, candidate):
        # Return list[Evidence]
        return [...]

    async def assess(self, candidate):
        # Return Finding or None
        return Finding(...)
```

## Testing

- All new code needs tests
- Tests live in `tests/`
- Use `unittest.mock` + `AsyncMock` for HTTP mocking (see existing tests for examples)
- For end-to-end tests, use `tests/lab/` (a vulnerable Flask app for testing)
- Run tests: `pytest tests/ -q`
- Run specific test: `pytest tests/test_check_mycheck.py -v`

## Code style

- Python 3.12+
- Type hints everywhere
- Use `from __future__ import annotations`
- Async-first (use `async def` for I/O)
- Pydantic v2 for all models
- No global mutable state
- No hardcoded credentials
- No destructive payloads (see SAFETY rules above)

## Pull request process

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-new-check`)
3. Make your changes
4. Run tests (`pytest tests/ -q`) — must all pass
5. Run the linter (`ruff check src/ tests/`) — fix any errors
6. Add an entry to `CHANGELOG.md` under "Unreleased"
7. Submit the PR with a clear description of what changed and why
8. Reference any related issues

## Release process

Maintainers cut a release by:
1. Updating `CHANGELOG.md` with the version section
2. Tagging the commit (`git tag v0.x.0`)
3. Building the package (`python -m build`)
4. Publishing to PyPI (`twine upload dist/*`)

## Getting help

- Open an issue for bug reports or feature requests
- Email maintainers for security issues (see SECURITY.md)
- Discussions tab for open-ended questions
