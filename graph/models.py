"""
models.py — DeadlockDNA Data Models (graph/)

Shared types used by the graph engine and the rest of the pipeline.
"""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, List, Optional


class Operation(Enum):
    LOCK_REQUEST  = auto()
    LOCK_ACQUIRED = auto()
    LOCK_RELEASED = auto()


@dataclass(frozen=True)
class Event:
    """Single synchronization event from the observer."""
    timestamp_ns: int
    pid: int
    tid: int
    resource: str           # hex futex address, e.g. "0x7ffd1234"
    operation: Operation
    owner_tid: Optional[int] = None

    @property
    def scoped_resource(self) -> str:
        return f"M@{self.pid}:{self.resource}"


@dataclass
class DeadlockResult:
    """A detected deadlock cycle in the Resource Allocation Graph."""
    detected: bool
    detection_ts_ns: int    # monotonic or relative ns when cycle was found
    formation_ts_ns: int    # event.timestamp_ns that completed the cycle
    cycle: List[str]        # node names, closing node repeated at end
    threads: List[int]      # TIDs in the cycle
    resources: List[str]    # scoped resource IDs in the cycle
    diagnosis: Optional[Any] = None       # Feature A: Explainable diagnosis
    fingerprint: Optional[str] = None     # Feature B: SHA-256 structural DNA
    occurrence_count: int = 1             # Feature B: Recurrence counter
    canonical_pattern: Optional[str] = None # Feature B: Role-based canonical pattern

    @property
    def latency_us(self) -> float:
        """Detection latency in microseconds."""
        diff = self.detection_ts_ns - self.formation_ts_ns
        return max(0.0, diff / 1_000.0)


# ── Node naming ────────────────────────────────────────────────────────────

def thread_node(tid: int) -> str:
    """'T5001'"""
    return f"T{tid}"

def resource_node(pid: int, resource: str) -> str:
    """'M@5000:0x7ffd1234'"""
    return f"M@{pid}:{resource}"
