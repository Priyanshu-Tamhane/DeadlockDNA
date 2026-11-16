"""
risk/risk_cycle_detector.py — Lock-Order Cycle & Hierarchy Risk Detection (Feature D)

Finds circular dependencies in the Lock Order Graph (LOG) using Johnson's algorithm.
Distinguishes potential lock-order risks (predictive hierarchy inversions) from live deadlocks.
"""

from dataclasses import dataclass, field
import hashlib
import json
import logging
import time
from typing import Dict, List, Optional, Set, Tuple
import networkx as nx

from .lock_order_tracker import LockOrderEvidence

logger = logging.getLogger(__name__)


@dataclass
class LockOrderRisk:
    """A detected circular dependency in the Lock Order Graph."""
    risk_id: str
    cycle: List[str]                           # Resource cycle e.g. ['M@1:0x1', 'M@1:0x2', 'M@1:0x1']
    pattern: str                               # Formatted string: "M@1:0x1 -> M@1:0x2 -> M@1:0x1"
    evidence: List[Dict]                       # Edge-by-edge evidence
    threads_involved: List[int]                # Unique TIDs that contributed to the cycle
    first_observed_ns: int
    last_observed_ns: int
    scope: str                                 # "single_run_concurrent" or "cross_session"
    confidence: str = "complete"               # "complete", "partial"
    is_live_deadlock: bool = False             # MUST BE FALSE: Lock order risk is predictive, not a live hang

    def to_dict(self) -> Dict:
        return {
            "risk_id": self.risk_id,
            "cycle": self.cycle,
            "pattern": self.pattern,
            "evidence": self.evidence,
            "threads_involved": self.threads_involved,
            "first_observed_ns": self.first_observed_ns,
            "last_observed_ns": self.last_observed_ns,
            "scope": self.scope,
            "confidence": self.confidence,
            "is_live_deadlock": self.is_live_deadlock,
            "warning": (
                "POTENTIAL LOCK-ORDER RISK: Observed acquisition orders violate strict lock hierarchy. "
                "This indicates an AB/BA locking pattern that can deadlock under concurrent scheduling."
            ),
        }

    def format_text(self) -> str:
        lines = [
            "⚠  LOCK-ORDER RISK DETECTED (Hierarchy Inversion)",
            f"Pattern: {self.pattern}",
            f"Scope  : {self.scope} (Threads: {', '.join(f'T{t}' for t in self.threads_involved)})",
            f"Confidence: {self.confidence.upper()}",
            "Observed Evidence:",
        ]
        for ev in self.evidence:
            lines.append(
                f"  • {ev['src_resource']} -> {ev['dst_resource']} observed by TID {ev['thread_id']} "
                f"(count: {ev['count']}x, last seen: {ev['last_seen_ns']})"
            )
        lines.append("Note: This is a predictive risk warning, not a confirmed active deadlock.")
        return "\n".join(lines)


class RiskCycleDetector:
    """
    Detects directed cycles in the Lock Order Graph and reports structured risk warnings.
    """

    def __init__(self) -> None:
        pass

    def detect_risks(self, log_graph: nx.DiGraph) -> List[LockOrderRisk]:
        """
        Analyzes the Lock Order Graph for directed cycles.

        Args:
            log_graph: Directed graph of lock-to-lock acquisition orders.

        Returns:
            List of LockOrderRisk objects. Empty if lock order is strictly hierarchical (DAG).
        """
        if log_graph.number_of_edges() < 2:
            return []

        try:
            raw_cycles = list(nx.simple_cycles(log_graph))
        except Exception as e:
            logger.error("Error analyzing lock order cycles: %s", e)
            return []

        if not raw_cycles:
            return []

        risks: List[LockOrderRisk] = []
        for raw in raw_cycles:
            risk = self._build_risk(raw, log_graph)
            if risk is not None:
                risks.append(risk)

        return risks

    def _build_risk(self, raw_cycle: List[str], graph: nx.DiGraph) -> Optional[LockOrderRisk]:
        if len(raw_cycle) < 2:
            return None

        # Canonicalize: rotate to start with lexicographically smallest resource
        min_node = min(raw_cycle)
        idx = raw_cycle.index(min_node)
        ordered = raw_cycle[idx:] + raw_cycle[:idx]
        closed_cycle = ordered + [ordered[0]]
        pattern_str = " -> ".join(closed_cycle)

        # Generate deterministic risk ID based on canonical pattern
        risk_id = "risk-" + hashlib.sha256(pattern_str.encode("utf-8")).hexdigest()[:16]

        evidence_list: List[Dict] = []
        tids: Set[int] = set()
        sessions: Set[str] = set()
        first_ns: Optional[int] = None
        last_ns: Optional[int] = None
        has_partial = False

        num_nodes = len(ordered)
        for i in range(num_nodes):
            src = ordered[i]
            dst = ordered[(i + 1) % num_nodes]

            if graph.has_edge(src, dst):
                edge_data = graph[src][dst]
                ev: Optional[LockOrderEvidence] = edge_data.get("evidence")
                if ev:
                    ev_dict = ev.to_dict()
                    evidence_list.append(ev_dict)
                    tids.add(ev.thread_id)
                    sessions.add(ev.session_id)
                    first_ns = ev.first_seen_ns if first_ns is None else min(first_ns, ev.first_seen_ns)
                    last_ns = ev.last_seen_ns if last_ns is None else max(last_ns, ev.last_seen_ns)
                else:
                    evidence_list.append({"src_resource": src, "dst_resource": dst, "note": "unspecified"})
                    has_partial = True
            else:
                has_partial = True

        scope = "cross_session" if len(sessions) > 1 else "single_run_concurrent"
        confidence = "partial" if has_partial else "complete"

        return LockOrderRisk(
            risk_id=risk_id,
            cycle=closed_cycle,
            pattern=pattern_str,
            evidence=evidence_list,
            threads_involved=sorted(list(tids)),
            first_observed_ns=first_ns or 0,
            last_observed_ns=last_ns or 0,
            scope=scope,
            confidence=confidence,
            is_live_deadlock=False,
        )

