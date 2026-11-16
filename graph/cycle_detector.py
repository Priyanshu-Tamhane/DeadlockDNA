"""
cycle_detector.py — Deadlock Cycle Detection (graph/)

Uses networkx.simple_cycles() (Johnson's algorithm) to find all directed
cycles in the Resource Allocation Graph. A cycle = deadlock.
"""

import logging
import time
from typing import List, Optional

import networkx as nx

from .models import DeadlockResult

logger = logging.getLogger(__name__)


class CycleDetector:
    def __init__(self) -> None:
        self._formation_ts_ns: Optional[int] = None
        self._last_graph_generation: int = -1   # tracks structural changes

    def detect(self, graph: nx.DiGraph, formation_ts_ns: int,
               operation: str = "") -> List[DeadlockResult]:
        """
        Detect all cycles in the RAG.

        Args:
            graph:           Current Resource Allocation Graph.
            formation_ts_ns: Timestamp of the event that triggered this check.
                             Used as "when the deadlock was formed" for latency.
            operation:       Optional hint — name of the Operation enum value
                             (e.g. "LOCK_REQUEST").  Detection is skipped unless
                             this is "LOCK_REQUEST" (or empty, for callers that
                             do not supply the hint).

        Returns:
            List of DeadlockResult — one per cycle. Empty if no deadlock.
        """
        # Fast path 1: skip non-request events — deadlocks only form on requests.
        if operation and operation != "LOCK_REQUEST":
            return []

        # Fast path 2: a 2-way deadlock needs at least 4 edges (2 request + 2 allocation).
        if graph.number_of_edges() < 4:
            self._formation_ts_ns = None
            return []

        t_start = time.perf_counter_ns()
        try:
            raw_cycles = list(nx.simple_cycles(graph))
        except Exception as e:
            logger.error("cycle detection error: %s", e)
            return []
        t_elapsed = time.perf_counter_ns() - t_start

        if not raw_cycles:
            self._formation_ts_ns = None
            return []

        # Record when the first cycle appeared (for latency calculation)
        if self._formation_ts_ns is None:
            self._formation_ts_ns = formation_ts_ns

        # Latency calculation:
        # In live eBPF tracing: bpftrace emits monotonic nanoseconds (bpf_ktime_get_ns).
        # Python's time.monotonic_ns() shares this exact monotonic clock on Linux.
        # If formation_ts_ns is within realistic range of time.monotonic_ns() (<= 5 mins),
        # compute true detection latency: monotonic_now - formation_ts_ns.
        # In simulated / file-replay mode, timestamps are arbitrary/relative, so use
        # cycle detection algorithmic execution time.
        mono_now = time.monotonic_ns()
        diff = mono_now - self._formation_ts_ns
        if 0 <= diff <= 300_000_000_000:
            det_ns = mono_now
            form_ns = self._formation_ts_ns
        else:
            det_ns = self._formation_ts_ns + max(t_elapsed, 1_000)
            form_ns = self._formation_ts_ns

        results = [self._make_result(c, det_ns, form_ns) for c in raw_cycles]

        for r in results:
            logger.warning("DEADLOCK  cycle=%s  latency=%.1f µs",
                           " → ".join(r.cycle), r.latency_us)
        return results

    # ──────────────────────────────────────────────────────────────────────

    def _make_result(self, nodes: List[str], det_ns: int, form_ns: int
                     ) -> DeadlockResult:
        # Canonicalize: start at lexicographically smallest node
        mn = min(nodes)
        idx = nodes.index(mn)
        ordered = nodes[idx:] + nodes[:idx]
        cycle = ordered + [ordered[0]]          # close the loop

        threads   = [int(n[1:]) for n in ordered if n.startswith("T")]
        resources = [n           for n in ordered if n.startswith("M@")]

        return DeadlockResult(
            detected=True,
            detection_ts_ns=det_ns,
            formation_ts_ns=form_ns,
            cycle=cycle,
            threads=threads,
            resources=resources,
        )
