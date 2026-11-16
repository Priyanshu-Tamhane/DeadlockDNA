"""
recovery/candidate.py — Recovery Actions and Candidates (Feature E)

Defines recovery action types, candidate models, and factors for cost-aware recovery
recommendations adhering to Section 7 of the Feature Expansion Specification.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, Any


class ActionType(str, Enum):
    """Types of potential recovery actions."""
    ALERT_OPERATOR = "alert_operator"                     # Safe operator notification / incident log
    COOPERATIVE_CANCEL_THREAD = "cooperative_cancel"       # Signal cooperative thread cancellation in disposable test
    GRACEFUL_PROCESS_RESTART = "graceful_restart"         # SIGTERM / orderly shutdown of disposable test child
    UNSAFE_MUTEX_UNLOCK = "unsafe_mutex_unlock"           # Strictly INELIGIBLE: violates POSIX invariants
    FORCE_KILL_PROCESS = "force_kill_process"             # Strictly INELIGIBLE for production workloads


@dataclass
class CandidateFactors:
    """Normalized factor inputs (0.0 to 1.0) for transparent scoring."""
    test_disposability: float = 0.0           # 1.0 if disposable test workload, 0.0 for production
    cooperative_shutdown_support: float = 0.0 # 1.0 if application has clean signal handler
    reversibility: float = 1.0                # 1.0 if action is non-destructive / reversible
    estimated_state_loss: float = 0.0         # 0.0 for stateless / zero loss, up to 1.0 for loss of in-flight work
    application_criticality: float = 1.0      # 1.0 for critical application, 0.0 for ephemeral test

    def to_dict(self) -> Dict[str, float]:
        return {
            "test_disposability": round(self.test_disposability, 2),
            "cooperative_shutdown_support": round(self.cooperative_shutdown_support, 2),
            "reversibility": round(self.reversibility, 2),
            "estimated_state_loss": round(self.estimated_state_loss, 2),
            "application_criticality": round(self.application_criticality, 2),
        }


@dataclass
class RecoveryCandidate:
    """A concrete recovery recommendation candidate."""
    candidate_id: str
    action_type: ActionType
    target_id: str                              # Target TID, PID, or "system"
    target_type: str                            # "thread", "process", "operator"
    is_eligible: bool                           # Whether safety policy allows this action
    ineligibility_reason: Optional[str] = None  # Explanation if ineligible
    factors: CandidateFactors = field(default_factory=CandidateFactors)
    score: float = 0.0                          # Computed heuristic score
    ranking_rationale: str = ""                 # Human-readable explanation of ranking
    requires_disposable: bool = True            # Whether action is strictly restricted to test workloads

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "action_type": self.action_type.value,
            "target_id": self.target_id,
            "target_type": self.target_type,
            "is_eligible": self.is_eligible,
            "ineligibility_reason": self.ineligibility_reason,
            "factors": self.factors.to_dict(),
            "score": round(self.score, 3),
            "ranking_rationale": self.ranking_rationale,
            "requires_disposable": self.requires_disposable,
        }

    def format_summary(self) -> str:
        status = "ELIGIBLE" if self.is_eligible else "INELIGIBLE"
        base = f"[{status}] {self.action_type.value} -> target: {self.target_id} (score: {self.score:.2f})"
        if not self.is_eligible and self.ineligibility_reason:
            base += f"\n    Reason for rejection: {self.ineligibility_reason}"
        elif self.ranking_rationale:
            base += f"\n    Rationale: {self.ranking_rationale}"
        return base

