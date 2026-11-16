"""
recovery/policy.py — Safety Policies and Candidate Generation (Feature E)

Enforces strict safety boundaries and generates eligible recovery candidates.
Prevents unsafe mutex unlocking, disallows destructive actions on production processes,
and generates structured RecoveryPlans adhering to Section 7 of the Feature Expansion Specification.
"""

from dataclasses import dataclass, field
import logging
from typing import List, Optional, Dict, Any

from graph.models import DeadlockResult
from .candidate import ActionType, CandidateFactors, RecoveryCandidate
from .scoring import ScoringConfig, rank_candidates, DEFAULT_SCORING_CONFIG

logger = logging.getLogger(__name__)


@dataclass
class RecoveryPlan:
    """Complete diagnostic and ranked recovery plan for a detected deadlock."""
    plan_id: str
    cycle: List[str]
    is_disposable_workload: bool
    all_candidates: List[RecoveryCandidate]
    eligible_candidates: List[RecoveryCandidate]
    rejected_candidates: List[RecoveryCandidate]
    top_recommendation: Optional[RecoveryCandidate]
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "cycle": self.cycle,
            "is_disposable_workload": self.is_disposable_workload,
            "eligible_candidates": [c.to_dict() for c in self.eligible_candidates],
            "rejected_candidates": [c.to_dict() for c in self.rejected_candidates],
            "top_recommendation": self.top_recommendation.to_dict() if self.top_recommendation else None,
            "summary": self.summary,
        }

    def format_text(self) -> str:
        lines = [
            f"=== Deadlock Recovery Plan (Plan ID: {self.plan_id}) ===",
            f"Workload Type: {'Disposable Test Workload' if self.is_disposable_workload else 'Production / Non-Disposable'}",
            f"Summary      : {self.summary}\n",
            "Top Recommended Action:",
        ]
        if self.top_recommendation:
            lines.append(f"  ★ {self.top_recommendation.format_summary()}\n")
        else:
            lines.append("  (No eligible automated action available; manual intervention required)\n")

        if self.eligible_candidates:
            lines.append("All Eligible Options:")
            for c in self.eligible_candidates:
                lines.append(f"  • {c.format_summary()}")
            lines.append("")

        if self.rejected_candidates:
            lines.append("Rejected Unsafe Options:")
            for c in self.rejected_candidates:
                lines.append(f"  ✗ {c.format_summary()}")

        return "\n".join(lines)


class RecoveryPolicyEngine:
    """
    Evaluates detected deadlocks and generates transparent, safety-gated recovery plans.
    """

    def __init__(self, scoring_config: ScoringConfig = DEFAULT_SCORING_CONFIG) -> None:
        self.scoring_config = scoring_config

    def evaluate_deadlock(self, deadlock: DeadlockResult,
                          pid: Optional[int] = None,
                          is_disposable_workload: bool = False) -> RecoveryPlan:
        """
        Generates a ranked RecoveryPlan for a detected deadlock.

        Args:
            deadlock: The detected DeadlockResult.
            pid: Optional process ID of the deadlocked application.
            is_disposable_workload: True only if the target is a disposable test workload.

        Returns:
            RecoveryPlan with eligible and rejected candidates.
        """
        plan_id = f"plan-{deadlock.formation_ts_ns}"
        candidates: List[RecoveryCandidate] = []

        target_pid_str = str(pid) if pid else "unknown"

        # -------------------------------------------------------------
        # 1. ALWAYS ELIGIBLE: Alert Operator / Log Incident
        # -------------------------------------------------------------
        alert_cand = RecoveryCandidate(
            candidate_id=f"{plan_id}-alert",
            action_type=ActionType.ALERT_OPERATOR,
            target_id="operator",
            target_type="operator",
            is_eligible=True,
            factors=CandidateFactors(
                test_disposability=1.0 if is_disposable_workload else 0.0,
                cooperative_shutdown_support=1.0,
                reversibility=1.0,
                estimated_state_loss=0.0,
                application_criticality=0.0 if is_disposable_workload else 0.8,
            ),
            requires_disposable=False,
        )
        candidates.append(alert_cand)

        # -------------------------------------------------------------
        # 2. STRICTLY INELIGIBLE: Arbitrary External Mutex Unlocking
        # -------------------------------------------------------------
        unsafe_unlock_cand = RecoveryCandidate(
            candidate_id=f"{plan_id}-unsafe-unlock",
            action_type=ActionType.UNSAFE_MUTEX_UNLOCK,
            target_id="all-cycle-locks",
            target_type="resource",
            is_eligible=False,
            ineligibility_reason=(
                "POSIX mutex ownership invariants forbid unlocking another thread's mutex from an "
                "external process; forced manipulation causes severe undefined behavior and memory corruption."
            ),
            factors=CandidateFactors(reversibility=0.0, estimated_state_loss=1.0),
            requires_disposable=False,
        )
        candidates.append(unsafe_unlock_cand)

        # -------------------------------------------------------------
        # 3. STRICTLY INELIGIBLE: Force Kill Process (SIGKILL)
        # -------------------------------------------------------------
        force_kill_cand = RecoveryCandidate(
            candidate_id=f"{plan_id}-force-kill",
            action_type=ActionType.FORCE_KILL_PROCESS,
            target_id=target_pid_str,
            target_type="process",
            is_eligible=False,
            ineligibility_reason=(
                "Uncontrolled force-kill (SIGKILL) is disallowed by policy to prevent database/file dirty state "
                "and uncollected system resources. Orderly cancellation must be used."
            ),
            factors=CandidateFactors(reversibility=0.0, estimated_state_loss=0.8),
            requires_disposable=True,
        )
        candidates.append(force_kill_cand)

        # -------------------------------------------------------------
        # 4. CONDITIONAL: Cooperative Thread Cancellation in Cycle
        # -------------------------------------------------------------
        for tid in deadlock.threads:
            tid_eligible = is_disposable_workload
            reason = None if tid_eligible else "Thread cancellation blocked on non-disposable target to prevent state corruption."
            thread_cand = RecoveryCandidate(
                candidate_id=f"{plan_id}-cancel-T{tid}",
                action_type=ActionType.COOPERATIVE_CANCEL_THREAD,
                target_id=f"T{tid}",
                target_type="thread",
                is_eligible=tid_eligible,
                ineligibility_reason=reason,
                factors=CandidateFactors(
                    test_disposability=1.0 if is_disposable_workload else 0.0,
                    cooperative_shutdown_support=1.0 if is_disposable_workload else 0.0,
                    reversibility=0.5,
                    estimated_state_loss=0.1 if is_disposable_workload else 0.9,
                    application_criticality=0.0 if is_disposable_workload else 0.9,
                ),
                requires_disposable=True,
            )
            candidates.append(thread_cand)

        # -------------------------------------------------------------
        # 5. CONDITIONAL: Graceful Process Restart (SIGTERM)
        # -------------------------------------------------------------
        proc_eligible = is_disposable_workload and pid is not None and pid > 0
        proc_reason = None if proc_eligible else "Process shutdown disallowed on non-disposable workload."
        proc_cand = RecoveryCandidate(
            candidate_id=f"{plan_id}-restart-pid-{target_pid_str}",
            action_type=ActionType.GRACEFUL_PROCESS_RESTART,
            target_id=target_pid_str,
            target_type="process",
            is_eligible=proc_eligible,
            ineligibility_reason=proc_reason,
            factors=CandidateFactors(
                test_disposability=1.0 if is_disposable_workload else 0.0,
                cooperative_shutdown_support=0.8 if is_disposable_workload else 0.2,
                reversibility=0.0,
                estimated_state_loss=0.2 if is_disposable_workload else 0.8,
                application_criticality=0.0 if is_disposable_workload else 0.9,
            ),
            requires_disposable=True,
        )
        candidates.append(proc_cand)

        # Rank all candidates using transparent scoring
        ranked = rank_candidates(candidates, self.scoring_config)

        eligible = [c for c in ranked if c.is_eligible]
        rejected = [c for c in ranked if not c.is_eligible]
        top = eligible[0] if eligible else None

        if is_disposable_workload:
            summary = (
                f"Evaluated {len(candidates)} recovery options for disposable test workload. "
                f"Top recommendation is '{top.action_type.value}' ({top.target_id}) with score {top.score:.2f}."
            )
        else:
            summary = (
                f"Evaluated {len(candidates)} recovery options for production workload. "
                f"Automated destructive actions blocked by policy; top recommendation is safe operator alert."
            )

        return RecoveryPlan(
            plan_id=plan_id,
            cycle=deadlock.cycle,
            is_disposable_workload=is_disposable_workload,
            all_candidates=ranked,
            eligible_candidates=eligible,
            rejected_candidates=rejected,
            top_recommendation=top,
            summary=summary,
        )

