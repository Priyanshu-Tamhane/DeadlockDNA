"""
recovery/executor.py — Safe Recovery Action Executor (Feature E)

Safely coordinates recovery execution adhering strictly to Section 7 of the Feature Expansion Spec:
- Execution is strictly DISABLED BY DEFAULT (recommendation-only mode).
- Execution is gated by an explicit whitelist of disposable test child PIDs.
- Unsafe external mutex unlocking is unconditionally rejected.
- Honest reporting of successful, timed-out, or rejected execution attempts.
"""

from dataclasses import dataclass
import logging
import os
from pathlib import Path
import signal
import time
from typing import Optional, Set

from .candidate import ActionType, RecoveryCandidate

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    """The honest outcome of a recovery action execution attempt."""
    candidate_id: str
    action_type: str
    target_id: str
    executed: bool                              # Whether an action was actually dispatched
    success: bool                               # Whether the action succeeded
    message: str                                # Explanation of the result
    elapsed_ms: float = 0.0                     # Execution duration in milliseconds


class RecoveryExecutor:
    """
    Safely executes approved recovery recommendations on explicitly disposable test workloads.
    """

    def __init__(self, execution_enabled: bool = False) -> None:
        # Safety gate 1: Disabled by default
        self.execution_enabled = execution_enabled
        # Safety gate 2: Explicit whitelist of disposable PIDs
        self.allowed_pids: Set[int] = set()

    def register_disposable_pid(self, pid: int) -> None:
        """Explicitly whitelists a known disposable test child process."""
        if pid > 0:
            self.allowed_pids.add(pid)

    def unregister_disposable_pid(self, pid: int) -> None:
        """Removes a process from the disposable whitelist."""
        self.allowed_pids.discard(pid)

    def execute(self, candidate: RecoveryCandidate,
                target_pid: Optional[int] = None,
                timeout_sec: float = 2.0) -> ExecutionResult:
        """
        Attempts execution of a recovery candidate under strict safety constraints.
        """
        t0 = time.perf_counter()

        # Gate 1: Check if execution is globally enabled
        if not self.execution_enabled:
            return ExecutionResult(
                candidate_id=candidate.candidate_id,
                action_type=candidate.action_type.value,
                target_id=candidate.target_id,
                executed=False,
                success=False,
                message="Execution disabled by default (running in safe recommendation-only mode).",
                elapsed_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # Gate 2: Check candidate eligibility
        if not candidate.is_eligible:
            return ExecutionResult(
                candidate_id=candidate.candidate_id,
                action_type=candidate.action_type.value,
                target_id=candidate.target_id,
                executed=False,
                success=False,
                message=f"Action rejected by safety policy: {candidate.ineligibility_reason}",
                elapsed_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # Action: Operator Alert (always permitted)
        if candidate.action_type == ActionType.ALERT_OPERATOR:
            logger.info("RECOVERY OPERATOR ALERT dispatched for target %s", candidate.target_id)
            return ExecutionResult(
                candidate_id=candidate.candidate_id,
                action_type=candidate.action_type.value,
                target_id=candidate.target_id,
                executed=True,
                success=True,
                message="Incident notification successfully dispatched to operator log.",
                elapsed_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # Gate 3: Destructive/process actions strictly require whitelisted disposable PID
        if target_pid is None or target_pid not in self.allowed_pids:
            return ExecutionResult(
                candidate_id=candidate.candidate_id,
                action_type=candidate.action_type.value,
                target_id=candidate.target_id,
                executed=False,
                success=False,
                message=(
                    f"Process {target_pid} is not registered in the disposable test workload whitelist. "
                    "Safety policy strictly blocks execution on non-disposable processes."
                ),
                elapsed_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # Action: Cooperative Graceful Restart / Termination (SIGTERM)
        if candidate.action_type == ActionType.GRACEFUL_PROCESS_RESTART:
            return self._execute_graceful_shutdown(candidate, target_pid, timeout_sec, t0)

        # Action: Cooperative Thread Cancellation
        if candidate.action_type == ActionType.COOPERATIVE_CANCEL_THREAD:
            return self._execute_cooperative_thread_cancel(candidate, target_pid, t0)

        return ExecutionResult(
            candidate_id=candidate.candidate_id,
            action_type=candidate.action_type.value,
            target_id=candidate.target_id,
            executed=False,
            success=False,
            message=f"Unsupported action type: {candidate.action_type.value}",
            elapsed_ms=(time.perf_counter() - t0) * 1000.0,
        )

    def _execute_graceful_shutdown(self, candidate: RecoveryCandidate,
                                   pid: int, timeout_sec: float, t0: float) -> ExecutionResult:
        try:
            # Check if process is alive
            os.kill(pid, 0)
        except OSError:
            return ExecutionResult(
                candidate_id=candidate.candidate_id,
                action_type=candidate.action_type.value,
                target_id=str(pid),
                executed=False,
                success=True,
                message=f"Target process {pid} is already terminated.",
                elapsed_ms=(time.perf_counter() - t0) * 1000.0,
            )

        logger.info("Sending SIGTERM to disposable test PID %d", pid)
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as e:
            return ExecutionResult(
                candidate_id=candidate.candidate_id,
                action_type=candidate.action_type.value,
                target_id=str(pid),
                executed=True,
                success=False,
                message=f"Failed to signal PID {pid}: {e}",
                elapsed_ms=(time.perf_counter() - t0) * 1000.0,
            )

        # Wait for graceful termination
        deadline = time.monotonic() + timeout_sec
        while time.monotonic() < deadline:
            # Try waitpid with WNOHANG in case this process is parent
            try:
                wpid, _ = os.waitpid(pid, os.WNOHANG)
                if wpid == pid:
                    self.allowed_pids.discard(pid)
                    return ExecutionResult(
                        candidate_id=candidate.candidate_id,
                        action_type=candidate.action_type.value,
                        target_id=str(pid),
                        executed=True,
                        success=True,
                        message=f"Disposable process {pid} terminated cleanly upon cooperative SIGTERM.",
                        elapsed_ms=(time.perf_counter() - t0) * 1000.0,
                    )
            except ChildProcessError:
                pass

            # Check /proc/<pid>/status for zombie status
            proc_status = Path(f"/proc/{pid}/status")
            if proc_status.exists():
                try:
                    content = proc_status.read_text()
                    if "State:\tZ" in content:
                        self.allowed_pids.discard(pid)
                        return ExecutionResult(
                            candidate_id=candidate.candidate_id,
                            action_type=candidate.action_type.value,
                            target_id=str(pid),
                            executed=True,
                            success=True,
                            message=f"Disposable process {pid} terminated cleanly upon cooperative SIGTERM.",
                            elapsed_ms=(time.perf_counter() - t0) * 1000.0,
                        )
                except OSError:
                    pass

            try:
                os.kill(pid, 0)
                time.sleep(0.05)
            except OSError:
                # Process exited cleanly
                self.allowed_pids.discard(pid)
                return ExecutionResult(
                    candidate_id=candidate.candidate_id,
                    action_type=candidate.action_type.value,
                    target_id=str(pid),
                    executed=True,
                    success=True,
                    message=f"Disposable process {pid} terminated cleanly upon cooperative SIGTERM.",
                    elapsed_ms=(time.perf_counter() - t0) * 1000.0,
                )

        # If process did not exit, report honestly without uncontrolled escalation
        return ExecutionResult(
            candidate_id=candidate.candidate_id,
            action_type=candidate.action_type.value,
            target_id=str(pid),
            executed=True,
            success=False,
            message=(
                f"Disposable process {pid} did not exit within {timeout_sec:.1f}s. "
                "Recovery was unsuccessful; safety policy forbids uncontrolled force escalation."
            ),
            elapsed_ms=(time.perf_counter() - t0) * 1000.0,
        )

    def _execute_cooperative_thread_cancel(self, candidate: RecoveryCandidate,
                                           pid: int, t0: float) -> ExecutionResult:
        # Attempt to signal the specific thread via tgkill(2). The target_id is a TID
        # with a "T" prefix (e.g. "T12345"). We strip the prefix and call tgkill via
        # ctypes so the signal goes to the thread, not the whole process group.
        # Fallback: if ctypes/libc is unavailable or tgkill fails, send SIGTERM to the process.
        tid_str = candidate.target_id.lstrip("T")
        try:
            tid = int(tid_str)
        except ValueError:
            tid = None

        signaled = False
        message = ""
        if tid is not None:
            try:
                import ctypes
                libc = ctypes.CDLL("libc.so.6", use_errno=True)
                # tgkill(tgid, tid, sig) — tgid is the process id
                ret = libc.tgkill(pid, tid, signal.SIGUSR1)
                if ret == 0:
                    signaled = True
                    message = (f"Cooperative cancellation signal (SIGUSR1) delivered via tgkill"
                               f" to thread TID {tid} in PID {pid}.")
                else:
                    errno_val = ctypes.get_errno()
                    raise OSError(errno_val, f"tgkill returned {ret}, errno={errno_val}")
            except OSError as e:
                message = (f"tgkill to TID {tid} failed ({e}); thread-level signaling requires ptrace."
                           f" Falling back to process SIGTERM on PID {pid}.")
        else:
            message = (f"Could not parse TID from target_id '{candidate.target_id}';"
                       f" falling back to process SIGTERM on PID {pid}.")

        if not signaled:
            # Fallback: process-level SIGTERM
            try:
                os.kill(pid, signal.SIGTERM)
                signaled = True
                message += " Process SIGTERM sent."
            except OSError as e2:
                return ExecutionResult(
                    candidate_id=candidate.candidate_id,
                    action_type=candidate.action_type.value,
                    target_id=candidate.target_id,
                    executed=True,
                    success=False,
                    message=f"{message} Fallback SIGTERM also failed: {e2}",
                    elapsed_ms=(time.perf_counter() - t0) * 1000.0,
                )

        return ExecutionResult(
            candidate_id=candidate.candidate_id,
            action_type=candidate.action_type.value,
            target_id=candidate.target_id,
            executed=True,
            success=signaled,
            message=message,
            elapsed_ms=(time.perf_counter() - t0) * 1000.0,
        )
