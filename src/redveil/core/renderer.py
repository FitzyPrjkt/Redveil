"""Rich console subscriber that prints event-bus activity as colored lines.

The renderer is a passive subscriber: it does not emit events and does not
participate in scan logic. Plugins must NEVER call the renderer directly;
they emit events on the bus and the renderer reacts. This indirection keeps
the scan flow observable from any number of subscribers (logs, JSONL files,
web UIs) without coupling them to Rich.
"""

from __future__ import annotations

from rich.console import Console

from redveil.core.event_bus import Event, EventType

_STYLES: dict[EventType, str] = {
    EventType.SCAN_STARTED: "bold cyan",
    EventType.DISCOVERY_STARTED: "cyan",
    EventType.DISCOVERY_ENDED: "cyan",
    EventType.REQUEST_SENT: "dim",
    EventType.RESPONSE_RECEIVED: "dim",
    EventType.CHECK_STARTED: "yellow",
    EventType.CHECK_ENDED: "yellow",
    EventType.FINDING_DETECTED: "bold red",
    EventType.VALIDATION_STARTED: "magenta",
    EventType.VALIDATION_ENDED: "magenta",
    EventType.EVIDENCE_CAPTURED: "green",
    EventType.FINDING_CONFIRMED: "bold green",
    EventType.REPORT_GENERATED: "bold blue",
    EventType.SCAN_FINISHED: "bold cyan",
    EventType.ERROR: "bold red on white",
}


class RichRenderer:
    """Subscribes to the event bus and prints timestamped, color-coded lines.

    Example output:
        18:41:02  DISCOVERY        /api/profile
        18:41:03  CHECK            cors-policy
        18:41:03  FINDING          WPOC-0001
        18:41:05  CONFIRMED        MEDIUM / HIGH
    """

    # Keys to surface as "key=value" tokens in the detail column, in order.
    # Other keys in `event.data` are ignored to keep the line dense.
    _PREFERRED_KEYS: tuple[str, ...] = (
        "endpoint",
        "url",
        "finding_id",
        "target",
        "check_id",
        "severity",
        "confidence",
        "findings",
    )

    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    async def __call__(self, event: Event) -> None:
        """Render a single event to the console.

        Acts as the bus Subscriber signature: ``Callable[[Event], Awaitable[None]]``.
        """
        style = _STYLES.get(event.type, "white")
        ts = event.timestamp.strftime("%H:%M:%S")
        label = event.type.value.upper().replace("_", " ")
        detail_parts: list[str] = []
        for key in self._PREFERRED_KEYS:
            if key in event.data:
                detail_parts.append(f"{key}={event.data[key]}")
        detail = "  ".join(detail_parts) if detail_parts else ""
        self.console.print(f"[dim]{ts}[/dim]  [{style}]{label:<18}[/{style}] {detail}")
