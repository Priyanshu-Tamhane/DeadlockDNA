"""
diagnosis/explainer.py — Explainable Deadlock Diagnosis (Feature A)

Translates detected Resource Allocation Graph (RAG) cycles into human-readable,
evidence-backed diagnostic explanations adhering to Section 3 of the Feature
Expansion Specification.
"""

from dataclasses import dataclass, field
from enum import Enum
import time
from typing import List, Optional, Dict, Any

from graph.models import thread_node, resource_node
from .symbol_resolver import SymbolResolver, SymbolInfo


class Confidence(str, Enum):
    COMPLETE = "complete"  # All required edges are directly observed with timestamps
    PARTIAL = "partial"    # At least one edge/ownership is inferred or missing timestamps
    UNKNOWN = "unknown"    # The event stream cannot support a reliable explanation


class EvidenceStatus(str, Enum):
    OBSERVED = "observed"  # Explicitly observed via synchronization probe
    INFERRED = "inferred"  # Inferred (e.g. from futex owner TID without uprobe)
    MISSING = "missing"    # Expected dependency edge is missing from RAG


@dataclass
class DiagnosisStep:
    thread_id: int
    thread_node: str
    action: str = "waiting_for"
    resource_id: str = ""                   # Resource the thread is waiting for (T -> R)
    held_resource_id: Optional[str] = None  # Resource currently held by thread (R -> T)
    resource_owner_tid: Optional[int] = None # TID of the thread that owns resource_id
    evidence_status: str = "observed"       # "observed", "inferred", "missing"
    request_timestamp_ns: Optional[int] = None
    acquire_timestamp_ns: Optional[int] = None
    description: str = ""
    # Upgrade 1: Rich Source Symbols
    held_symbol: Optional[str] = None
    waiting_symbol: Optional[str] = None
    thread_function: Optional[str] = None
    source_location: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "thread_id": self.thread_id,
            "thread_node": self.thread_node,
            "action": self.action,
            "resource_id": self.resource_id,
            "held_resource_id": self.held_resource_id,
            "resource_owner_tid": self.resource_owner_tid,
            "evidence_status": self.evidence_status,
            "request_timestamp_ns": self.request_timestamp_ns,
            "acquire_timestamp_ns": self.acquire_timestamp_ns,
            "description": self.description,
            "held_symbol": self.held_symbol,
            "waiting_symbol": self.waiting_symbol,
            "thread_function": self.thread_function,
            "source_location": self.source_location,
        }


@dataclass
class DiagnosisResult:
    diagnosis_id: str
    cycle_nodes: List[str]
    summary: str
    steps: List[DiagnosisStep]
    confidence: str                        # "complete", "partial", "unknown"
    evidence: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "diagnosis_id": self.diagnosis_id,
            "cycle_nodes": self.cycle_nodes,
            "summary": self.summary,
            "steps": [s.to_dict() for s in self.steps],
            "confidence": self.confidence,
            "evidence": self.evidence,
            "limitations": self.limitations,
        }

    def format_text(self) -> str:
        lines = ["Deadlock candidate detected\n"]
        for s in self.steps:
            held = s.held_resource_id or "unknown resource"
            owner = f" (owned by TID {s.resource_owner_tid})" if s.resource_owner_tid else ""
            lines.append(f"TID {s.thread_id} holds {held} and waits for {s.resource_id}{owner}.")
        lines.append("\nDependency cycle:")
        lines.append(" -> ".join(self.cycle_nodes))
        lines.append("\nEvidence:")
        for ev in self.evidence:
            lines.append(f"- {ev}")
        if self.limitations:
            lines.append("\nLimitations:")
            for lim in self.limitations:
                lines.append(f"- {lim}")
        lines.append(f"\nConfidence: {self.confidence}")
        return "\n".join(lines)


class DeadlockExplainer:
    """
    Produces structured, evidence-backed diagnostic explanations from RAG cycles.
    """

    def __init__(self, symbol_resolver: Optional[SymbolResolver] = None) -> None:
        self.symbol_resolver = symbol_resolver or SymbolResolver()

    def explain(self, cycle: List[str], rag: Any,
                timestamp_ns: Optional[int] = None,
                pid: Optional[int] = None) -> DiagnosisResult:
        """
        Explain a detected deadlock cycle.

        Args:
            cycle: The canonical node cycle (e.g. ['T1', 'M@...', 'T2', 'M@...', 'T1']).
            rag: The ResourceAllocationGraph instance containing current edge state.
            timestamp_ns: Optional timestamp of the event that completed the cycle.

        Returns:
            DiagnosisResult structured object.
        """
        diag_id = f"diag-{timestamp_ns or int(time.time() * 1_000_000)}"

        if not cycle or len(cycle) < 4:
            return DiagnosisResult(
                diagnosis_id=diag_id,
                cycle_nodes=cycle or [],
                summary="Insufficient cycle nodes to construct a diagnosis.",
                steps=[],
                confidence=Confidence.UNKNOWN.value,
                evidence=[],
                limitations=["Cycle path is empty or malformed."],
            )

        # Remove the closing duplicate node if present
        nodes = cycle[:-1] if cycle[0] == cycle[-1] else list(cycle)
        num_nodes = len(nodes)

        # Obtain the underlying graph object
        graph = rag.get_graph() if hasattr(rag, "get_graph") else rag

        # Identify all thread node positions in the alternating bipartite cycle
        thread_indices = [i for i, n in enumerate(nodes) if n.startswith("T")]

        steps: List[DiagnosisStep] = []
        evidence: List[str] = []
        limitations: List[str] = []
        has_inferred = False
        has_missing = False
        has_missing_ts = False

        for idx in thread_indices:
            t_node = nodes[idx]
            try:
                tid = int(t_node[1:])
            except ValueError:
                tid = 0

            # In a directed bipartite cycle:
            # - The node immediately preceding T is the resource T holds (R_held -> T)
            # - The node immediately following T is the resource T is waiting for (T -> R_wait)
            # - The node following R_wait is the thread that holds R_wait (R_wait -> T_owner)
            r_held = nodes[(idx - 1) % num_nodes]
            r_wait = nodes[(idx + 1) % num_nodes]
            t_owner = nodes[(idx + 2) % num_nodes]

            try:
                owner_tid = int(t_owner[1:]) if t_owner.startswith("T") else None
            except ValueError:
                owner_tid = None

            # 1. Inspect request edge: T -> R_wait
            req_exists = graph.has_edge(t_node, r_wait)
            req_data = graph[t_node][r_wait] if req_exists else {}
            req_ts = req_data.get("timestamp_ns")
            req_src = req_data.get("source", "futex")

            # 2. Inspect allocation edge: R_held -> T
            alloc_exists = graph.has_edge(r_held, t_node)
            alloc_data = graph[r_held][t_node] if alloc_exists else {}
            alloc_ts = alloc_data.get("timestamp_ns")
            is_inferred = alloc_data.get("inferred", False)
            alloc_src = alloc_data.get("source", "pthread_mutex_lock")

            step_status = "observed"
            if not req_exists or not alloc_exists:
                step_status = "missing"
                has_missing = True
                limitations.append(
                    f"Edge between {t_node} and {r_wait if not req_exists else r_held} is missing from active graph."
                )
            elif is_inferred:
                step_status = "inferred"
                has_inferred = True
                limitations.append(
                    f"Ownership of {r_held} by {t_node} was inferred rather than directly observed via uprobe."
                )

            if req_ts is None:
                has_missing_ts = True
            if alloc_ts is None:
                has_missing_ts = True

            # Resolve rich symbols for Upgrade 1
            sym_held = self.symbol_resolver.resolve_resource(r_held, pid)
            sym_wait = self.symbol_resolver.resolve_resource(r_wait, pid)
            t_func = self.symbol_resolver.resolve_thread_function(tid, pid)
            owner_func = self.symbol_resolver.resolve_thread_function(owner_tid, pid) if owner_tid else None

            # Format descriptive step string
            owner_str = f" (owned by TID {owner_tid} [{owner_func}])" if owner_tid is not None else ""
            desc = (
                f"Thread {tid} ('{t_func}') holds {r_held} [{sym_held.display_str}] "
                f"and is waiting for {r_wait} [{sym_wait.display_str}]{owner_str}."
            )

            step = DiagnosisStep(
                thread_id=tid,
                thread_node=t_node,
                action="waiting_for",
                resource_id=r_wait,
                held_resource_id=r_held,
                resource_owner_tid=owner_tid,
                evidence_status=step_status,
                request_timestamp_ns=req_ts,
                acquire_timestamp_ns=alloc_ts,
                description=desc,
                held_symbol=sym_held.display_str,
                waiting_symbol=sym_wait.display_str,
                thread_function=t_func,
                source_location=sym_wait.location_str,
            )
            steps.append(step)

            # Record human-readable evidence points
            if req_exists:
                if req_ts is not None:
                    evidence.append(f"{t_node} requested {r_wait} at timestamp {req_ts} ({req_src}).")
                else:
                    evidence.append(f"{t_node} requested {r_wait} (timestamp unavailable).")
            else:
                evidence.append(f"{t_node} -> {r_wait} request edge missing from current graph.")

            if alloc_exists:
                if is_inferred:
                    evidence.append(f"{r_held} is inferred as owned by {t_node} from futex word.")
                elif alloc_ts is not None:
                    evidence.append(f"{r_held} is recorded as owned by {t_node} (acquired at {alloc_ts}, {alloc_src}).")
                else:
                    evidence.append(f"{r_held} is recorded as owned by {t_node}.")
            else:
                evidence.append(f"{r_held} -> {t_node} allocation edge missing from current graph.")

        if has_missing_ts and not has_missing and not has_inferred:
            limitations.append("One or more event timestamps were unavailable in graph edge metadata.")

        # Determine overall confidence
        if has_missing or not steps:
            confidence = Confidence.UNKNOWN.value
        elif has_inferred or has_missing_ts:
            confidence = Confidence.PARTIAL.value
        else:
            confidence = Confidence.COMPLETE.value

        # Generate summary
        num_threads = len(steps)
        if num_threads == 2:
            summary = "Two threads are waiting on resources owned by each other."
        elif num_threads > 2:
            summary = f"{num_threads} threads are involved in a circular wait dependency chain."
        else:
            summary = "Deadlock cycle detected."

        return DiagnosisResult(
            diagnosis_id=diag_id,
            cycle_nodes=cycle,
            summary=summary,
            steps=steps,
            confidence=confidence,
            evidence=evidence,
            limitations=limitations,
        )
