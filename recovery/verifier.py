"""
recovery/verifier.py — Post-Recovery Verification Engine (Feature E)

Verifies the outcome of recovery actions:
- Checks if the Resource Allocation Graph (RAG) circular wait cycle was broken.
- Checks target process/thread state.
- Records side effects honestly adhering to Section 7 of the Feature Expansion Spec.
"""

from dataclasses import dataclass, field
import os
from typing import List, Optional, Dict, Any

from graph.rag import ResourceAllocationGraph


@dataclass
class VerificationResult:
    """Outcome of recovery verification."""
    resolved: bool
    cycle_broken: bool
    process_state: str                          # "running", "terminated", "unmonitored"
    side_effects: List[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resolved": self.resolved,
            "cycle_broken": self.cycle_broken,
            "process_state": self.process_state,
            "side_effects": self.side_effects,
            "summary": self.summary,
        }

    def format_text(self) -> str:
        status = "RESOLVED" if self.resolved else "UNRESOLVED"
        lines = [
            f"Recovery Verification: {status}",
            f"Cycle Broken  : {self.cycle_broken}",
            f"Process State : {self.process_state}",
            f"Summary       : {self.summary}",
        ]
        if self.side_effects:
            lines.append("Side Effects Recorded:")
            for s in self.side_effects:
                lines.append(f"  - {s}")
        return "\n".join(lines)


class RecoveryVerifier:
    """
    Verifies whether a recovery action successfully broke the circular wait.
    """

    def verify(self, original_cycle: List[str],
               rag: ResourceAllocationGraph,
               target_pid: Optional[int] = None) -> VerificationResult:
        """
        Verifies if the specified cycle is broken in the given RAG.

        Args:
            original_cycle: List of cycle nodes (e.g. ['T1', 'M1', 'T2', 'M2', 'T1']).
            rag: Current ResourceAllocationGraph.
            target_pid: Optional PID of target process.

        Returns:
            VerificationResult detailing whether the cycle is broken.
        """
        graph = rag.get_graph()
        side_effects: List[str] = []

        # 1. Check if any edge in original cycle was removed
        nodes = original_cycle[:-1] if original_cycle[0] == original_cycle[-1] else list(original_cycle)
        num_nodes = len(nodes)
        intact_edges = 0
        broken_edges = 0

        for i in range(num_nodes):
            src = nodes[i]
            dst = nodes[(i + 1) % num_nodes]
            if graph.has_edge(src, dst):
                intact_edges += 1
            else:
                broken_edges += 1

        cycle_broken = broken_edges > 0 or intact_edges == 0

        # 2. Check process liveness if PID is provided
        process_state = "unmonitored"
        if target_pid is not None and target_pid > 0:
            try:
                os.kill(target_pid, 0)
                process_state = "running"
            except OSError:
                process_state = "terminated"
                side_effects.append(f"Target process {target_pid} terminated.")

        if rag.is_empty():
            side_effects.append("Resource Allocation Graph is now empty (all locks released).")

        resolved = cycle_broken

        if resolved:
            summary = f"Deadlock cycle successfully resolved ({broken_edges} cycle edge(s) broken)."
        else:
            summary = "Deadlock cycle remains intact in the active graph."

        return VerificationResult(
            resolved=resolved,
            cycle_broken=cycle_broken,
            process_state=process_state,
            side_effects=side_effects,
            summary=summary,
        )

