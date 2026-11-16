"""
tests/test_rag.py — Unit tests for the Resource Allocation Graph

Tests all edge cases of the RAG engine without requiring eBPF or root.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1]))

import pytest
from graph.models import Event, Operation, thread_node, resource_node
from graph.rag import ResourceAllocationGraph


def make_event(tid, resource, op, ts=1, pid=1000):
    return Event(timestamp_ns=ts, pid=pid, tid=tid,
                 resource=resource, operation=op)

REQ  = Operation.LOCK_REQUEST
ACQ  = Operation.LOCK_ACQUIRED
REL  = Operation.LOCK_RELEASED

PID  = 1000
L1   = "0x1000"
L2   = "0x2000"
L3   = "0x3000"

T1   = thread_node(1)
T2   = thread_node(2)
T3   = thread_node(3)
R1   = resource_node(PID, L1)
R2   = resource_node(PID, L2)
R3   = resource_node(PID, L3)


class TestRequestEdge:
    def test_request_adds_edge(self):
        rag = ResourceAllocationGraph()
        rag.process_event(make_event(1, L1, REQ))
        assert (T1, R1) in rag.get_edges()

    def test_duplicate_request_no_duplicate_edge(self):
        rag = ResourceAllocationGraph()
        rag.process_event(make_event(1, L1, REQ))
        rag.process_event(make_event(1, L1, REQ))
        edges = [(s, d) for s, d in rag.get_edges() if s == T1 and d == R1]
        assert len(edges) == 1


class TestAcquisitionEdge:
    def test_acquire_adds_allocation_edge(self):
        rag = ResourceAllocationGraph()
        rag.process_event(make_event(1, L1, ACQ))
        assert (R1, T1) in rag.get_edges()

    def test_acquire_removes_request_edge(self):
        rag = ResourceAllocationGraph()
        rag.process_event(make_event(1, L1, REQ))
        rag.process_event(make_event(1, L1, ACQ))
        assert (T1, R1) not in rag.get_edges()
        assert (R1, T1) in rag.get_edges()

    def test_acquire_replaces_old_holder(self):
        """When T1 holds R1 and T2 also acquires R1, old edge is replaced."""
        rag = ResourceAllocationGraph()
        rag.process_event(make_event(1, L1, ACQ))
        rag.process_event(make_event(2, L1, ACQ))
        assert (R1, T1) not in rag.get_edges()
        assert (R1, T2) in rag.get_edges()


class TestReleaseEdge:
    def test_release_removes_allocation_edge(self):
        rag = ResourceAllocationGraph()
        rag.process_event(make_event(1, L1, ACQ))
        rag.process_event(make_event(1, L1, REL))
        assert (R1, T1) not in rag.get_edges()

    def test_release_cleans_up_isolated_nodes(self):
        rag = ResourceAllocationGraph()
        rag.process_event(make_event(1, L1, ACQ))
        rag.process_event(make_event(1, L1, REL))
        assert rag.is_empty()

    def test_release_without_prior_acquire_does_not_crash(self):
        """Graceful handling of spurious LOCK_RELEASED (fast-path unlock)."""
        rag = ResourceAllocationGraph()
        rag.process_event(make_event(1, L1, REL))   # should not crash
        assert rag.is_empty()


class TestNoStaleEdges:
    def test_acquire_release_acquire_release_cycle(self):
        """Repeated lock/unlock leaves no stale edges."""
        rag = ResourceAllocationGraph()
        for _ in range(3):
            rag.process_event(make_event(1, L1, ACQ))
            rag.process_event(make_event(1, L1, REL))
        assert rag.is_empty()

    def test_two_threads_sequential_no_edges(self):
        rag = ResourceAllocationGraph()
        rag.process_event(make_event(1, L1, ACQ))
        rag.process_event(make_event(1, L1, REL))
        rag.process_event(make_event(2, L1, ACQ))
        rag.process_event(make_event(2, L1, REL))
        assert rag.is_empty()


class TestUnrelatedThreads:
    def test_unrelated_threads_dont_share_edges(self):
        rag = ResourceAllocationGraph()
        # T1 holds L1, T2 holds L2 — independent
        rag.process_event(make_event(1, L1, ACQ))
        rag.process_event(make_event(2, L2, ACQ))
        edges = rag.get_edges()
        assert (R1, T1) in edges
        assert (R2, T2) in edges
        assert (R1, T2) not in edges
        assert (R2, T1) not in edges


class TestDeadlockState:
    def test_two_way_deadlock_edges(self):
        """Verify 2-way deadlock produces the expected 4 edges."""
        rag = ResourceAllocationGraph()
        rag.process_event(make_event(1, L1, ACQ))
        rag.process_event(make_event(2, L2, ACQ))
        rag.process_event(make_event(1, L2, REQ))
        rag.process_event(make_event(2, L1, REQ))
        edges = set(rag.get_edges())
        assert edges == {(R1, T1), (R2, T2), (T1, R2), (T2, R1)}

    def test_three_way_deadlock_edges(self):
        """Verify 3-way deadlock produces the expected 6 edges."""
        rag = ResourceAllocationGraph()
        rag.process_event(make_event(1, L1, ACQ))
        rag.process_event(make_event(2, L2, ACQ))
        rag.process_event(make_event(3, L3, ACQ))
        rag.process_event(make_event(1, L2, REQ))
        rag.process_event(make_event(2, L3, REQ))
        rag.process_event(make_event(3, L1, REQ))
        edges = set(rag.get_edges())
        assert edges == {(R1,T1),(R2,T2),(R3,T3),(T1,R2),(T2,R3),(T3,R1)}
