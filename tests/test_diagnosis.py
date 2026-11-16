"""
tests/test_diagnosis.py — Unit tests for Explainable Deadlock Diagnosis (Feature A)
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1]))

import pytest
from graph.models import Event, Operation, thread_node, resource_node
from graph.rag import ResourceAllocationGraph
from diagnosis.explainer import DeadlockExplainer, Confidence, EvidenceStatus


def make_event(tid, resource, op, ts=1000, pid=5000, owner_tid=None):
    return Event(timestamp_ns=ts, pid=pid, tid=tid,
                 resource=resource, operation=op, owner_tid=owner_tid)

REQ = Operation.LOCK_REQUEST
ACQ = Operation.LOCK_ACQUIRED
REL = Operation.LOCK_RELEASED


class TestExplainableDiagnosis:

    def test_two_thread_deadlock_explanation(self):
        """Standard 2-thread deadlock produces complete confidence explanation."""
        rag = ResourceAllocationGraph()
        rag.process_event(make_event(4101, "0x1000", ACQ, ts=100))
        rag.process_event(make_event(4102, "0x2000", ACQ, ts=200))
        rag.process_event(make_event(4101, "0x2000", REQ, ts=300))
        rag.process_event(make_event(4102, "0x1000", REQ, ts=400))

        # Cycle: M@5000:0x1000 -> T4101 -> M@5000:0x2000 -> T4102 -> M@5000:0x1000
        cycle = [
            "M@5000:0x1000", "T4101",
            "M@5000:0x2000", "T4102",
            "M@5000:0x1000"
        ]

        explainer = DeadlockExplainer()
        diag = explainer.explain(cycle, rag, timestamp_ns=400)

        assert diag.confidence == Confidence.COMPLETE.value
        assert "Two threads" in diag.summary
        assert len(diag.steps) == 2

        s1 = next(s for s in diag.steps if s.thread_id == 4101)
        assert s1.held_resource_id == "M@5000:0x1000"
        assert s1.resource_id == "M@5000:0x2000"
        assert s1.resource_owner_tid == 4102
        assert s1.acquire_timestamp_ns == 100
        assert s1.request_timestamp_ns == 300
        assert s1.evidence_status == "observed"

        s2 = next(s for s in diag.steps if s.thread_id == 4102)
        assert s2.held_resource_id == "M@5000:0x2000"
        assert s2.resource_id == "M@5000:0x1000"
        assert s2.resource_owner_tid == 4101
        assert s2.acquire_timestamp_ns == 200
        assert s2.request_timestamp_ns == 400
        assert s2.evidence_status == "observed"

        text = diag.format_text()
        assert "TID 4101 holds M@5000:0x1000 and waits for M@5000:0x2000" in text
        assert "Confidence: complete" in text

    def test_three_thread_deadlock_explanation(self):
        """3-thread cyclic wait produces sequential dependency steps."""
        rag = ResourceAllocationGraph()
        rag.process_event(make_event(1, "0x1000", ACQ, ts=10))
        rag.process_event(make_event(2, "0x2000", ACQ, ts=20))
        rag.process_event(make_event(3, "0x3000", ACQ, ts=30))
        rag.process_event(make_event(1, "0x2000", REQ, ts=40))
        rag.process_event(make_event(2, "0x3000", REQ, ts=50))
        rag.process_event(make_event(3, "0x1000", REQ, ts=60))

        cycle = [
            "M@5000:0x1000", "T1",
            "M@5000:0x2000", "T2",
            "M@5000:0x3000", "T3",
            "M@5000:0x1000"
        ]

        explainer = DeadlockExplainer()
        diag = explainer.explain(cycle, rag, timestamp_ns=60)

        assert diag.confidence == Confidence.COMPLETE.value
        assert "3 threads" in diag.summary
        assert len(diag.steps) == 3

        tids = [s.thread_id for s in diag.steps]
        assert tids == [1, 2, 3]

        assert diag.steps[0].resource_owner_tid == 2
        assert diag.steps[1].resource_owner_tid == 3
        assert diag.steps[2].resource_owner_tid == 1

    def test_inferred_ownership_lowers_confidence(self):
        """Inferred lock owner results in partial confidence and recorded limitation."""
        rag = ResourceAllocationGraph()
        # T1 acquires L1 directly
        rag.process_event(make_event(1, "0x1000", ACQ, ts=100))
        # T1 requests L2 and infers T2 as holder (without direct ACQ event for T2)
        rag.process_event(make_event(1, "0x2000", REQ, ts=150, owner_tid=2))
        # T2 requests L1
        rag.process_event(make_event(2, "0x1000", REQ, ts=200))

        cycle = [
            "M@5000:0x1000", "T1",
            "M@5000:0x2000", "T2",
            "M@5000:0x1000"
        ]

        explainer = DeadlockExplainer()
        diag = explainer.explain(cycle, rag, timestamp_ns=200)

        assert diag.confidence == Confidence.PARTIAL.value
        assert any("inferred" in lim.lower() for lim in diag.limitations)
        s2 = next(s for s in diag.steps if s.thread_id == 2)
        assert s2.evidence_status == "inferred"

    def test_missing_edge_gives_unknown_confidence(self):
        """If a cycle node is missing from RAG, confidence is unknown."""
        rag = ResourceAllocationGraph()
        # Empty graph, fake cycle
        cycle = [
            "M@5000:0x1000", "T1",
            "M@5000:0x2000", "T2",
            "M@5000:0x1000"
        ]

        explainer = DeadlockExplainer()
        diag = explainer.explain(cycle, rag, timestamp_ns=500)

        assert diag.confidence == Confidence.UNKNOWN.value
        assert len(diag.limitations) > 0

    def test_missing_timestamps_gives_partial_confidence(self):
        """Edges present without timestamps lowers confidence to partial."""
        rag = ResourceAllocationGraph()
        g = rag.get_graph()
        # Manually add edges without timestamp_ns
        g.add_edge("M@5000:0x1000", "T1", kind="allocation")
        g.add_edge("T1", "M@5000:0x2000", kind="request")
        g.add_edge("M@5000:0x2000", "T2", kind="allocation")
        g.add_edge("T2", "M@5000:0x1000", kind="request")

        cycle = [
            "M@5000:0x1000", "T1",
            "M@5000:0x2000", "T2",
            "M@5000:0x1000"
        ]

        explainer = DeadlockExplainer()
        diag = explainer.explain(cycle, rag, timestamp_ns=100)

        assert diag.confidence == Confidence.PARTIAL.value
        assert any("timestamp" in lim.lower() for lim in diag.limitations)

    def test_to_dict_matches_spec_schema(self):
        """to_dict() produces the schema outlined in Section 3 of the spec."""
        rag = ResourceAllocationGraph()
        rag.process_event(make_event(10, "0xaaaa", ACQ, ts=1))
        rag.process_event(make_event(20, "0xbbbb", ACQ, ts=2))
        rag.process_event(make_event(10, "0xbbbb", REQ, ts=3))
        rag.process_event(make_event(20, "0xaaaa", REQ, ts=4))

        cycle = ["M@5000:0xaaaa", "T10", "M@5000:0xbbbb", "T20", "M@5000:0xaaaa"]
        explainer = DeadlockExplainer()
        diag = explainer.explain(cycle, rag, timestamp_ns=4)

        d = diag.to_dict()
        assert "diagnosis_id" in d
        assert "cycle_nodes" in d
        assert "summary" in d
        assert "steps" in d
        assert "confidence" in d
        assert "limitations" in d
        assert len(d["steps"]) == 2

        s0 = d["steps"][0]
        assert "thread_id" in s0
        assert "action" in s0
        assert "resource_id" in s0
        assert "resource_owner_tid" in s0
        assert "evidence_status" in s0

    def test_empty_cycle(self):
        """Empty cycle handles gracefully without exception."""
        rag = ResourceAllocationGraph()
        explainer = DeadlockExplainer()
        diag = explainer.explain([], rag)
        assert diag.confidence == Confidence.UNKNOWN.value
        assert len(diag.steps) == 0
