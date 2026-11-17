"""
cycle_detector.py — Deadlock Cycle Detection (graph/)

Uses networkx.simple_cycles() (Johnson's algorithm) with strict timeout
protection, cycle capping, and O(V + E) DFS fallback (nx.find_cycle) to find
directed cycles in the Resource Allocation Graph. A cycle = deadlock.
"""

import logging
import threading
import time
from typing import List, Optional, Tuple

import networkx as nx

from .models import DeadlockResult

logger = logging.getLogger(__name__)


def find_cycles_bounded(
    graph: nx.DiGraph,
    timeout_sec: float = 0.5,
    max_cycles: int = 100,
) -> Tuple[List[List[str]], bool]:
    """
    Safely discovers directed cycles within timeout_sec and max_cycles limits.
    If Johnson's algorithm times out on complex or dense graphs, falls back
    to O(V + E) DFS cycle finding (nx.find_cycle) to guarantee prompt detection.
    """
    # Fast path: check if graph is a DAG in O(V + E) time
    if nx.is_directed_acyclic_graph(graph):
        return [], False

    raw_cycles: List[List[str]] = []
    error_occurred = False

    def _worker() -> None:
        nonlocal error_occurred
        try:
            for cycle in nx.simple_cycles(graph):
                raw_cycles.append(cycle)
                if len(raw_cycles) >= max_cycles:
                    break
        except Exception as ex:
            error_occurred = True
            logger.error("error inside simple_cycles: %s", ex)

    th = threading.Thread(target=_worker, daemon=True)
    th.start()
    th.join(timeout=timeout_sec)

    timed_out = th.is_alive()
    if timed_out:
        logger.warning(
            "nx.simple_cycles timed out after %.2fs (%d cycles found so far); evaluating fallback",
            timeout_sec, len(raw_cycles)
        )

    # If no cycles were retrieved before timeout/error, fall back to O(V + E) find_cycle
    if not raw_cycles:
        try:
            edges = list(nx.find_cycle(graph, orientation="original"))
            if edges:
                fallback_cycle = [u for u, v in edges]
                raw_cycles.append(fallback_cycle)
                logger.info("fallback find_cycle located cycle: %s", fallback_cycle)
        except (nx.NetworkXNoCycle, Exception) as ex:
            logger.debug("no cycle found via fallback: %s", ex)

    return raw_cycles, timed_out


class CycleDetector:
    def __init__(self, timeout_sec: float = 0.5, max_cycles: int = 100) -> None:
        self.timeout_sec = timeout_sec
        self.max_cycles = max_cycles
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
        raw_cycles, timed_out = find_cycles_bounded(
            graph,
            timeout_sec=self.timeout_sec,
            max_cycles=self.max_cycles,
        )
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

        threads   = [int(n[1:]) for n in ordered if n.startswith("T") and n[1:].isdigit()]
        resources = [n           for n in ordered if not (n.startswith("T") and n[1:].isdigit())]

        return DeadlockResult(
            detected=True,
            detection_ts_ns=det_ns,
            formation_ts_ns=form_ns,
            cycle=cycle,
            threads=threads,
            resources=resources,
        )
