"""
test_recovery.py — Unit Tests for Cost-Aware Recovery Recommendations (Feature E)
DeadlockDNA — tests/

Tests recovery candidate generation, transparent heuristic scoring, safety policies,
safe executor gating, and post-recovery cycle verification adhering to Section 7 of the spec.
"""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from graph.models import DeadlockResult, Event, Operation, thread_node, resource_node
from graph.rag import ResourceAllocationGraph
from recovery.candidate import ActionType, CandidateFactors, RecoveryCandidate
from recovery.scoring import (
    ScoringConfig,
    calculate_score,
    generate_ranking_rationale,
    rank_candidates,
    DEFAULT_SCORING_CONFIG,
)
from recovery.policy import RecoveryPolicyEngine, RecoveryPlan
from recovery.executor import RecoveryExecutor, ExecutionResult
from recovery.verifier import RecoveryVerifier, VerificationResult


def make_dummy_deadlock(threads=(5001, 5002), resources=("0x1000", "0x2000"), pid=5000) -> DeadlockResult:
    r1 = resource_node(pid, resources[0])
    r2 = resource_node(pid, resources[1])
    t1 = thread_node(threads[0])
    t2 = thread_node(threads[1])
    cycle = [r1, t1, r2, t2, r1]
    return DeadlockResult(
        detected=True,
        detection_ts_ns=1000,
        formation_ts_ns=900,
        cycle=cycle,
        threads=list(threads),
        resources=[r1, r2],
    )


# =====================================================================
# 1. Candidate Modeling & Scoring Engine Tests
# =====================================================================

class TestScoringEngine:

    def test_calculate_score_disposable_vs_production(self):
        """Disposable test workload with cooperative support scores much higher than critical prod."""
        disp_factors = CandidateFactors(
            test_disposability=1.0,
            cooperative_shutdown_support=1.0,
            reversibility=0.5,
            estimated_state_loss=0.0,
            application_criticality=0.0,
        )
        disp_score = calculate_score(disp_factors)

        prod_factors = CandidateFactors(
            test_disposability=0.0,
            cooperative_shutdown_support=0.0,
            reversibility=0.0,
            estimated_state_loss=1.0,
            application_criticality=1.0,
        )
        prod_score = calculate_score(prod_factors)

        assert disp_score > 0.6
        assert prod_score <= -0.3
        assert disp_score > prod_score

    def test_ranking_places_eligible_first_by_score(self):
        """rank_candidates sorts eligible candidates descending, followed by rejected candidates."""
        c_ineligible = RecoveryCandidate(
            candidate_id="c_ineligible",
            action_type=ActionType.UNSAFE_MUTEX_UNLOCK,
            target_id="res",
            target_type="resource",
            is_eligible=False,
            ineligibility_reason="Unsafe",
        )
        c_low = RecoveryCandidate(
            candidate_id="c_low",
            action_type=ActionType.GRACEFUL_PROCESS_RESTART,
            target_id="pid",
            target_type="process",
            is_eligible=True,
            factors=CandidateFactors(estimated_state_loss=0.8, application_criticality=0.5),
        )
        c_high = RecoveryCandidate(
            candidate_id="c_high",
            action_type=ActionType.ALERT_OPERATOR,
            target_id="op",
            target_type="operator",
            is_eligible=True,
            factors=CandidateFactors(reversibility=1.0, estimated_state_loss=0.0, application_criticality=0.0),
        )

        ranked = rank_candidates([c_ineligible, c_low, c_high])

        assert ranked[0].candidate_id == "c_high"
        assert ranked[1].candidate_id == "c_low"
        assert ranked[2].candidate_id == "c_ineligible"
        assert ranked[2].score == -1.0

    def test_ranking_rationale_explains_score(self):
        """Rationale provides plain-text factor explanations."""
        cand = RecoveryCandidate(
            candidate_id="c1",
            action_type=ActionType.ALERT_OPERATOR,
            target_id="op",
            target_type="operator",
            is_eligible=True,
            factors=CandidateFactors(reversibility=1.0),
        )
        cand.score = calculate_score(cand.factors)
        rationale = generate_ranking_rationale(cand)

        assert "reversibility" in rationale
        assert f"Score {cand.score:.2f}" in rationale


# =====================================================================
# 2. Safety Policy Engine Tests
# =====================================================================

class TestRecoveryPolicyEngine:

    def test_production_mode_blocks_destructive_actions(self):
        """In production mode (default), automated kills/cancellations are blocked; alert is top."""
        engine = RecoveryPolicyEngine()
        dl = make_dummy_deadlock()

        plan = engine.evaluate_deadlock(dl, pid=5000, is_disposable_workload=False)

        assert plan.is_disposable_workload is False
        assert plan.top_recommendation is not None
        assert plan.top_recommendation.action_type == ActionType.ALERT_OPERATOR

        # Unsafe mutex unlock and force kill must be rejected
        rejected_types = {c.action_type for c in plan.rejected_candidates}
        assert ActionType.UNSAFE_MUTEX_UNLOCK in rejected_types
        assert ActionType.FORCE_KILL_PROCESS in rejected_types
        assert ActionType.COOPERATIVE_CANCEL_THREAD in rejected_types
        assert ActionType.GRACEFUL_PROCESS_RESTART in rejected_types

    def test_disposable_mode_enables_cooperative_options(self):
        """In disposable test mode, thread cancellation and graceful restart become eligible."""
        engine = RecoveryPolicyEngine()
        dl = make_dummy_deadlock()

        plan = engine.evaluate_deadlock(dl, pid=5000, is_disposable_workload=True)

        assert plan.is_disposable_workload is True
        eligible_types = {c.action_type for c in plan.eligible_candidates}

        assert ActionType.ALERT_OPERATOR in eligible_types
        assert ActionType.COOPERATIVE_CANCEL_THREAD in eligible_types
        assert ActionType.GRACEFUL_PROCESS_RESTART in eligible_types

        # Unsafe mutex unlock must STILL be rejected unconditionally!
        rejected_types = {c.action_type for c in plan.rejected_candidates}
        assert ActionType.UNSAFE_MUTEX_UNLOCK in rejected_types

    def test_unsafe_mutex_unlock_always_has_ineligibility_reason(self):
        """Verify the invariant message forbidding external mutex unlocking."""
        engine = RecoveryPolicyEngine()
        dl = make_dummy_deadlock()
        plan = engine.evaluate_deadlock(dl, pid=5000, is_disposable_workload=True)

        unlock_cand = next(c for c in plan.rejected_candidates if c.action_type == ActionType.UNSAFE_MUTEX_UNLOCK)
        assert "POSIX mutex ownership invariants forbid" in unlock_cand.ineligibility_reason


# =====================================================================
# 3. Recovery Executor Safety Tests
# =====================================================================

class TestRecoveryExecutor:

    def test_executor_disabled_by_default(self):
        """Default executor configuration forbids executing any destructive action."""
        executor = RecoveryExecutor(execution_enabled=False)
        cand = RecoveryCandidate(
            candidate_id="c1",
            action_type=ActionType.GRACEFUL_PROCESS_RESTART,
            target_id="1234",
            target_type="process",
            is_eligible=True,
        )
        res = executor.execute(cand, target_pid=1234)

        assert res.executed is False
        assert res.success is False
        assert "disabled by default" in res.message

    def test_non_whitelisted_pid_is_blocked(self):
        """Even with execution enabled, non-whitelisted PIDs cannot be signaled."""
        executor = RecoveryExecutor(execution_enabled=True)
        cand = RecoveryCandidate(
            candidate_id="c1",
            action_type=ActionType.GRACEFUL_PROCESS_RESTART,
            target_id="9999",
            target_type="process",
            is_eligible=True,
        )
        res = executor.execute(cand, target_pid=9999)

        assert res.executed is False
        assert res.success is False
        assert "not registered in the disposable" in res.message

    def test_operator_alert_executes_safely(self):
        """Operator alert executes without requiring process signaling."""
        executor = RecoveryExecutor(execution_enabled=True)
        cand = RecoveryCandidate(
            candidate_id="c1",
            action_type=ActionType.ALERT_OPERATOR,
            target_id="operator",
            target_type="operator",
            is_eligible=True,
        )
        res = executor.execute(cand)

        assert res.executed is True
        assert res.success is True
        assert "Incident notification" in res.message

    def test_graceful_shutdown_on_real_disposable_subprocess(self):
        """Tests cooperative SIGTERM shutdown on a known disposable test process."""
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        pid = proc.pid

        executor = RecoveryExecutor(execution_enabled=True)
        executor.register_disposable_pid(pid)

        cand = RecoveryCandidate(
            candidate_id="test_restart",
            action_type=ActionType.GRACEFUL_PROCESS_RESTART,
            target_id=str(pid),
            target_type="process",
            is_eligible=True,
        )

        res = executor.execute(cand, target_pid=pid, timeout_sec=3.0)

        assert res.executed is True
        assert res.success is True
        assert "terminated cleanly" in res.message

        # Process should be dead
        proc.wait(timeout=2.0)
        assert proc.returncode is not None


# =====================================================================
# 4. Recovery Verifier Tests
# =====================================================================

class TestRecoveryVerifier:

    def test_verifier_detects_resolved_cycle(self):
        """When an edge in the cycle is released, verifier confirms the cycle is broken."""
        rag = ResourceAllocationGraph()
        # T1 acquires L1, T2 acquires L2, T1 requests L2, T2 requests L1
        rag.process_event(Event(1, 5000, 1, "0x1000", Operation.LOCK_ACQUIRED))
        rag.process_event(Event(2, 5000, 2, "0x2000", Operation.LOCK_ACQUIRED))
        rag.process_event(Event(3, 5000, 1, "0x2000", Operation.LOCK_REQUEST))
        rag.process_event(Event(4, 5000, 2, "0x1000", Operation.LOCK_REQUEST))

        orig_cycle = ["M@5000:0x1000", "T1", "M@5000:0x2000", "T2", "M@5000:0x1000"]
        verifier = RecoveryVerifier()

        # Before resolution: cycle is intact
        v_before = verifier.verify(orig_cycle, rag)
        assert v_before.resolved is False
        assert v_before.cycle_broken is False

        # T1 releases L1 (breaking allocation edge)
        rag.process_event(Event(5, 5000, 1, "0x1000", Operation.LOCK_RELEASED))

        # After resolution: cycle is broken!
        v_after = verifier.verify(orig_cycle, rag)
        assert v_after.resolved is True
        assert v_after.cycle_broken is True
        assert "resolved" in v_after.summary.lower()

