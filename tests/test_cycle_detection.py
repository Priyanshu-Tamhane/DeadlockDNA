"""
tests/test_cycle_detection.py — Unit tests for CycleDetector

Tests cycle detection correctness without eBPF or root.
"""

import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1]))

import pytest
from graph.models import Operation
from graph.rag import ResourceAllocationGraph
from graph.cycle_detector import CycleDetector


def make_event(tid, resource, op, ts=1, pid=1000):
    from graph.models import Event
    return Event(timestamp_ns=ts, pid=pid, tid=tid,
                 resource=resource, operation=op)

REQ = Operation.LOCK_REQUEST
ACQ = Operation.LOCK_ACQUIRED
REL = Operation.LOCK_RELEASED

L1, L2, L3 = "0x1000", "0x2000", "0x3000"


def build_rag(*events) -> ResourceAllocationGraph:
    rag = ResourceAllocationGraph()
    for ev in events:
        rag.process_event(ev)
    return rag


class TestNoDeadlock:
    def test_empty_graph_no_cycle(self):
        rag = build_rag()
        det = CycleDetector()
        assert det.detect(rag.get_graph(), 1) == []

    def test_single_holder_no_cycle(self):
        """T1 holds L1 — no cycle."""
        rag = build_rag(make_event(1, L1, ACQ))
        det = CycleDetector()
        assert det.detect(rag.get_graph(), 1) == []

    def test_linear_wait_no_cycle(self):
        """T1 holds L1, T2 waits for L1 — NOT a deadlock (no cycle)."""
        rag = build_rag(
            make_event(1, L1, ACQ),
            make_event(2, L1, REQ),
        )
        det = CycleDetector()
        result = det.detect(rag.get_graph(), 1)
        assert result == [], "Linear wait must not be reported as deadlock"

    def test_sequential_lock_unlock_no_cycle(self):
        """T1 acquires and releases L1 — graph is empty, no cycle."""
        rag = build_rag(
            make_event(1, L1, ACQ),
            make_event(1, L1, REL),
        )
        det = CycleDetector()
        assert det.detect(rag.get_graph(), 1) == []


class TestTwoWayDeadlock:
    def _setup(self):
        rag = build_rag(
            make_event(1, L1, ACQ),
            make_event(2, L2, ACQ),
            make_event(1, L2, REQ),
            make_event(2, L1, REQ),
        )
        return rag

    def test_cycle_detected(self):
        rag = self._setup()
        det = CycleDetector()
        results = det.detect(rag.get_graph(), ts := 100)
        assert len(results) == 1
        assert results[0].detected is True

    def test_cycle_contains_correct_nodes(self):
        rag = self._setup()
        det = CycleDetector()
        result = det.detect(rag.get_graph(), 100)[0]
        cycle_set = set(result.cycle)
        assert "T1" in cycle_set
        assert "T2" in cycle_set
        assert "M@1000:0x1000" in cycle_set
        assert "M@1000:0x2000" in cycle_set

    def test_cycle_closes(self):
        """Cycle list must start and end with the same node."""
        rag = self._setup()
        det = CycleDetector()
        result = det.detect(rag.get_graph(), 100)[0]
        assert result.cycle[0] == result.cycle[-1]

    def test_threads_extracted(self):
        rag = self._setup()
        det = CycleDetector()
        result = det.detect(rag.get_graph(), 100)[0]
        assert set(result.threads) == {1, 2}

    def test_latency_non_negative(self):
        rag = self._setup()
        det = CycleDetector()
        form_ts = time.monotonic_ns() - 1_000_000  # 1ms ago
        result = det.detect(rag.get_graph(), form_ts)[0]
        assert result.latency_us >= 0

    def test_synthetic_replay_latency_reasonable(self):
        rag = self._setup()
        det = CycleDetector()
        # Simulated relative timestamp (e.g. 4.0s)
        form_ts = 4_000_000_000
        result = det.detect(rag.get_graph(), form_ts)[0]
        # Must be realistic execution time (< 100,000 µs), not 56 years
        assert 0 <= result.latency_us < 100_000


class TestThreeWayDeadlock:
    def _setup(self):
        return build_rag(
            make_event(1, L1, ACQ),
            make_event(2, L2, ACQ),
            make_event(3, L3, ACQ),
            make_event(1, L2, REQ),
            make_event(2, L3, REQ),
            make_event(3, L1, REQ),
        )

    def test_cycle_detected(self):
        rag = self._setup()
        det = CycleDetector()
        results = det.detect(rag.get_graph(), 100)
        assert len(results) >= 1

    def test_cycle_contains_all_threads(self):
        rag = self._setup()
        det = CycleDetector()
        result = det.detect(rag.get_graph(), 100)[0]
        assert set(result.threads) == {1, 2, 3}


class TestCycleReset:
    def test_cycle_gone_after_release(self):
        """If the deadlock is resolved (release), no cycle should be reported."""
        rag = ResourceAllocationGraph()
        det = CycleDetector()

        rag.process_event(make_event(1, L1, ACQ))
        rag.process_event(make_event(2, L2, ACQ))
        rag.process_event(make_event(1, L2, REQ))
        rag.process_event(make_event(2, L1, REQ))
        assert len(det.detect(rag.get_graph(), 100)) == 1

        # Resolve: T1 releases L1
        rag.process_event(make_event(1, L1, REL))
        result = det.detect(rag.get_graph(), 200)
        assert result == []
