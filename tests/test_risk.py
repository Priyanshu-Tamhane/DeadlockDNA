"""
test_risk.py — Unit Tests for Lock-Order Risk Analysis (Feature D)
DeadlockDNA — tests/

Tests lock-order graph construction, reentrancy handling, cycle detection,
evidence recording, SQLite persistence, and predictive risk identification.
"""

import sys
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from graph.models import Event, Operation, thread_node, resource_node
from graph.rag import ResourceAllocationGraph
from graph.cycle_detector import CycleDetector
from risk.lock_order_tracker import LockOrderTracker, LockOrderEvidence
from risk.risk_cycle_detector import RiskCycleDetector, LockOrderRisk
from risk.risk_store import RiskStore


def make_event(tid: int, resource: str, op: Operation, ts: int = 1000, pid: int = 5000) -> Event:
    return Event(timestamp_ns=ts, pid=pid, tid=tid, resource=resource, operation=op)

REQ = Operation.LOCK_REQUEST
ACQ = Operation.LOCK_ACQUIRED
REL = Operation.LOCK_RELEASED

PID = 5000
L1 = "0x1000"
L2 = "0x2000"
L3 = "0x3000"

R1 = resource_node(PID, L1)
R2 = resource_node(PID, L2)
R3 = resource_node(PID, L3)


# =====================================================================
# 1. Lock-Order Acquisition Tracking Tests
# =====================================================================

class TestLockOrderTracker:

    def test_single_lock_no_order_edges(self):
        """Acquiring and releasing a single lock produces no lock-order edges."""
        tracker = LockOrderTracker()
        tracker.process_event(make_event(1, L1, ACQ, ts=100))
        assert tracker.graph.number_of_edges() == 0
        assert tracker.get_held_locks(1) == {R1}

        tracker.process_event(make_event(1, L1, REL, ts=200))
        assert tracker.get_held_locks(1) == set()
        assert tracker.graph.number_of_edges() == 0

    def test_sequential_locks_no_nesting_no_edge(self):
        """Acquiring L1, releasing L1, then acquiring L2 creates NO edge because L1 was released."""
        tracker = LockOrderTracker()
        tracker.process_event(make_event(1, L1, ACQ, ts=100))
        tracker.process_event(make_event(1, L1, REL, ts=200))
        tracker.process_event(make_event(1, L2, ACQ, ts=300))
        tracker.process_event(make_event(1, L2, REL, ts=400))

        assert tracker.graph.number_of_edges() == 0

    def test_nested_locks_create_directed_edge(self):
        """Acquiring L2 while holding L1 creates directed edge L1 -> L2."""
        tracker = LockOrderTracker()
        tracker.process_event(make_event(1, L1, ACQ, ts=100))
        ev_list = tracker.process_event(make_event(1, L2, ACQ, ts=200))

        assert tracker.graph.has_edge(R1, R2)
        assert not tracker.graph.has_edge(R2, R1)
        assert len(ev_list) == 1
        ev = ev_list[0]
        assert ev.src_resource == R1
        assert ev.dst_resource == R2
        assert ev.thread_id == 1
        assert ev.first_seen_ns == 200

    def test_multiple_nested_locks_transitive(self):
        """Holding L1 and L2 while acquiring L3 creates L1 -> L3 and L2 -> L3."""
        tracker = LockOrderTracker()
        tracker.process_event(make_event(1, L1, ACQ, ts=10))
        tracker.process_event(make_event(1, L2, ACQ, ts=20))
        tracker.process_event(make_event(1, L3, ACQ, ts=30))

        edges = set(tracker.graph.edges())
        assert (R1, R2) in edges
        assert (R1, R3) in edges
        assert (R2, R3) in edges
        assert len(edges) == 3

    def test_reentrant_lock_does_not_create_self_edge(self):
        """Acquiring the same lock multiple times (reentrancy) must not create a self-loop (L1 -> L1)."""
        tracker = LockOrderTracker()
        tracker.process_event(make_event(1, L1, ACQ, ts=100))
        ev = tracker.process_event(make_event(1, L1, ACQ, ts=200))  # Reentrant

        assert len(ev) == 0
        assert not tracker.graph.has_edge(R1, R1)
        assert tracker.graph.number_of_edges() == 0

        # Unwinding reentrancy: first release decrements depth, lock still held
        tracker.process_event(make_event(1, L1, REL, ts=300))
        assert tracker.get_held_locks(1) == {R1}

        # Second release clears held lock
        tracker.process_event(make_event(1, L1, REL, ts=400))
        assert tracker.get_held_locks(1) == set()

    def test_request_events_are_ignored(self):
        """LOCK_REQUEST events do not infer lock acquisition and do not alter held locks."""
        tracker = LockOrderTracker()
        tracker.process_event(make_event(1, L1, REQ, ts=100))
        assert tracker.get_held_locks(1) == set()
        assert tracker.graph.number_of_edges() == 0


# =====================================================================
# 2. Lock-Order Cycle & Risk Detection Tests
# =====================================================================

class TestRiskCycleDetector:

    def test_safe_hierarchical_order_no_risk(self):
        """Consistent lock hierarchy (L1 -> L2 -> L3 across all threads) produces zero risks."""
        tracker = LockOrderTracker()
        # Thread 1: L1 -> L2
        tracker.process_event(make_event(1, L1, ACQ, ts=100))
        tracker.process_event(make_event(1, L2, ACQ, ts=150))
        tracker.process_event(make_event(1, L2, REL, ts=200))
        tracker.process_event(make_event(1, L1, REL, ts=250))

        # Thread 2: L2 -> L3
        tracker.process_event(make_event(2, L2, ACQ, ts=300))
        tracker.process_event(make_event(2, L3, ACQ, ts=350))
        tracker.process_event(make_event(2, L3, REL, ts=400))
        tracker.process_event(make_event(2, L2, REL, ts=450))

        detector = RiskCycleDetector()
        risks = detector.detect_risks(tracker.graph)
        assert len(risks) == 0

    def test_two_thread_inverted_order_detects_risk(self):
        """Thread 1 does L1 -> L2 while Thread 2 does L2 -> L1: circular lock order risk!"""
        tracker = LockOrderTracker()
        # Thread 1: acquires L1 then L2
        tracker.process_event(make_event(1, L1, ACQ, ts=100))
        tracker.process_event(make_event(1, L2, ACQ, ts=150))
        tracker.process_event(make_event(1, L2, REL, ts=200))
        tracker.process_event(make_event(1, L1, REL, ts=250))

        # Thread 2: acquires L2 then L1 (Inversion)
        tracker.process_event(make_event(2, L2, ACQ, ts=300))
        tracker.process_event(make_event(2, L1, ACQ, ts=350))
        tracker.process_event(make_event(2, L1, REL, ts=400))
        tracker.process_event(make_event(2, L2, REL, ts=450))

        detector = RiskCycleDetector()
        risks = detector.detect_risks(tracker.graph)

        assert len(risks) == 1
        risk = risks[0]
        assert risk.is_live_deadlock is False  # Must be flagged predictive
        assert set(risk.threads_involved) == {1, 2}
        assert risk.confidence == "complete"
        assert len(risk.evidence) == 2

        # Cycle path should be closed and start at lexicographically smaller resource
        assert risk.cycle[0] == risk.cycle[-1]
        assert risk.cycle[0] == min(R1, R2)

        text = risk.format_text()
        assert "LOCK-ORDER RISK DETECTED" in text
        assert "predictive risk warning" in text

    def test_three_way_circular_lock_order(self):
        """T1: L1->L2, T2: L2->L3, T3: L3->L1 produces a 3-resource risk cycle."""
        tracker = LockOrderTracker()
        # T1: L1 -> L2
        tracker.process_event(make_event(1, L1, ACQ, ts=10))
        tracker.process_event(make_event(1, L2, ACQ, ts=20))
        # T2: L2 -> L3
        tracker.process_event(make_event(2, L2, ACQ, ts=30))
        tracker.process_event(make_event(2, L3, ACQ, ts=40))
        # T3: L3 -> L1
        tracker.process_event(make_event(3, L3, ACQ, ts=50))
        tracker.process_event(make_event(3, L1, ACQ, ts=60))

        detector = RiskCycleDetector()
        risks = detector.detect_risks(tracker.graph)

        assert len(risks) == 1
        risk = risks[0]
        assert set(risk.threads_involved) == {1, 2, 3}
        assert len(risk.evidence) == 3


# =====================================================================
# 3. Persistent Risk Store Tests
# =====================================================================

class TestRiskStore:

    def test_store_edges_and_risks_in_memory(self):
        """Test recording edges, risks, and occurrence increment in SQLite."""
        store = RiskStore(":memory:")
        ev = LockOrderEvidence(
            src_resource=R1,
            dst_resource=R2,
            thread_id=1,
            pid=PID,
            first_seen_ns=100,
            last_seen_ns=150,
            count=1,
            session_id="run_1",
        )
        store.record_edge(ev)
        assert store.count_edges() == 1

        # Duplicate edge insertion increments count
        store.record_edge(ev)
        assert store.count_edges() == 1

        risk = LockOrderRisk(
            risk_id="risk-test-1",
            cycle=[R1, R2, R1],
            pattern=f"{R1} -> {R2} -> {R1}",
            evidence=[ev.to_dict()],
            threads_involved=[1],
            first_observed_ns=100,
            last_observed_ns=150,
            scope="single_run_concurrent",
            confidence="complete",
        )

        c1 = store.record_risk(risk)
        assert c1 == 1
        assert store.count_risks() == 1

        # Second occurrence increments count
        c2 = store.record_risk(risk)
        assert c2 == 2
        assert store.count_risks() == 1

        all_risks = store.get_all_risks()
        assert len(all_risks) == 1
        assert all_risks[0]["occurrence_count"] == 2
        assert all_risks[0]["pattern"] == risk.pattern

        store.close()

    def test_load_into_tracker(self):
        """Edges stored in SQLite can be reloaded into a fresh LockOrderTracker."""
        store = RiskStore(":memory:")
        ev1 = LockOrderEvidence(R1, R2, 1, PID, 100, 100, 1, "s1")
        ev2 = LockOrderEvidence(R2, R1, 2, PID, 200, 200, 1, "s2")
        store.record_edge(ev1)
        store.record_edge(ev2)

        fresh_tracker = LockOrderTracker()
        loaded = store.load_into_tracker(fresh_tracker)
        assert loaded == 2

        # Cycle detector should detect the risk from the reloaded edges!
        detector = RiskCycleDetector()
        risks = detector.detect_risks(fresh_tracker.graph)
        assert len(risks) == 1
        assert risks[0].scope == "cross_session"

        store.close()


# =====================================================================
# 4. End-to-End: Distinction Between Live Deadlock and Lock-Order Risk
# =====================================================================

class TestEndToEndRiskVsDeadlock:

    def test_benign_run_detects_risk_without_live_deadlock(self):
        """
        Crucial requirement: When Thread 1 runs (L1 -> L2) and finishes cleanly,
        and Thread 2 runs later (L2 -> L1) and finishes cleanly:
        - The RAG has NO cycles (no active deadlock occurred).
        - But the LockOrderTracker detects an AB/BA hierarchy risk!
        """
        rag = ResourceAllocationGraph()
        rag_detector = CycleDetector()

        log_tracker = LockOrderTracker()
        risk_detector = RiskCycleDetector()

        # Thread 1: safely takes L1, then L2, then releases both
        t1_events = [
            make_event(1, L1, ACQ, ts=100),
            make_event(1, L2, ACQ, ts=110),
            make_event(1, L2, REL, ts=120),
            make_event(1, L1, REL, ts=130),
        ]
        for e in t1_events:
            rag.process_event(e)
            log_tracker.process_event(e)
            # No live deadlock
            assert len(rag_detector.detect(rag.get_graph(), e.timestamp_ns)) == 0

        # At this point, RAG is completely empty because all locks were released!
        assert rag.is_empty()

        # Thread 2: safely takes L2, then L1, then releases both
        t2_events = [
            make_event(2, L2, ACQ, ts=200),
            make_event(2, L1, ACQ, ts=210),
            make_event(2, L1, REL, ts=220),
            make_event(2, L2, REL, ts=230),
        ]
        for e in t2_events:
            rag.process_event(e)
            log_tracker.process_event(e)
            # Still no live deadlock!
            assert len(rag_detector.detect(rag.get_graph(), e.timestamp_ns)) == 0

        # Live RAG is empty: zero live deadlocks
        assert rag.is_empty()
        live_deadlocks = rag_detector.detect(rag.get_graph(), 240)
        assert len(live_deadlocks) == 0

        # BUT: Lock-Order Risk analysis flags the latent AB vs BA danger!
        risks = risk_detector.detect_risks(log_tracker.graph)
        assert len(risks) == 1
        assert risks[0].is_live_deadlock is False
        assert set(risks[0].threads_involved) == {1, 2}

