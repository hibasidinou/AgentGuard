"""In-memory audit trail for demonstrations (not persistent or tamper-proof)."""
from collections import Counter
from datetime import datetime, timezone

_EVENTS: list[dict] = []


def record(actor_id: str, tool: str, target: str, allowed: bool, reason: str) -> dict:
    event = {
        "time": datetime.now(timezone.utc).isoformat(),
        "actor": actor_id,
        "tool": tool,
        "target": target,
        "allowed": allowed,
        "reason": reason,
    }
    _EVENTS.append(event)
    del _EVENTS[:-500]
    return event


def recent_events() -> list[dict]:
    return list(reversed(_EVENTS))


def alerts() -> list[dict]:
    """Flag actors with >=3 blocked operations in the last 20 events."""
    blocked = Counter(e["actor"] for e in _EVENTS[-20:] if not e["allowed"])
    return [
        {"actor": actor, "severity": "medium", "reason": "Repeated blocked actions", "count": count}
        for actor, count in blocked.items()
        if count >= 3
    ]
