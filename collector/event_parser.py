"""
event_parser.py — DeadlockDNA Event Parser (collector/)

Parses raw JSON lines from the eBPF observer into typed Event objects.
Handles malformed lines, unknown operations, and missing fields gracefully.
"""

import json
import logging
from typing import Optional
from graph.models import Event, Operation

logger = logging.getLogger(__name__)

_OP_MAP: dict[str, Operation] = {
    "LOCK_REQUEST":  Operation.LOCK_REQUEST,
    "LOCK_ACQUIRED": Operation.LOCK_ACQUIRED,
    "LOCK_RELEASED": Operation.LOCK_RELEASED,
}


def parse_line(line: str) -> Optional[Event]:
    """
    Parse one JSON line from the observer into an Event.

    Returns None (silently) for comments, blank lines, and tool banner lines.
    Returns None (with a warning log) for malformed lines.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Silently ignore known bpftrace banner / status lines
    if line.startswith("Attaching ") or line.startswith("Attached ") or line.startswith("Tracing "):
        return None

    try:
        data = json.loads(line)
    except json.JSONDecodeError as e:
        logger.warning("bad JSON: %s | %s", repr(line[:80]), e)
        return None

    if not isinstance(data, dict):
        logger.warning("JSON payload is not an object: %s", repr(line[:80]))
        return None

    required = ("timestamp_ns", "pid", "tid", "resource", "operation")
    missing = [f for f in required if f not in data]
    if missing:
        logger.warning("missing fields %s in: %s", missing, repr(line[:80]))
        return None

    op = _OP_MAP.get(data["operation"])
    if op is None:
        logger.warning("unknown operation %r", data["operation"])
        return None

    try:
        owner_tid = int(data["owner_tid"]) if "owner_tid" in data and data["owner_tid"] is not None else None
        return Event(
            timestamp_ns=int(data["timestamp_ns"]),
            pid=int(data["pid"]),
            tid=int(data["tid"]),
            resource=str(data["resource"]).strip(),
            operation=op,
            owner_tid=owner_tid,
        )
    except (ValueError, TypeError) as e:
        logger.warning("type error parsing event: %s | %s", repr(line[:80]), e)
        return None
