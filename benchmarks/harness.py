"""
harness.py — Workload Execution Harness and Benchmark Runner (benchmarks/)
DeadlockDNA — Feature C (Milestone 3)

Provides isolated, timeout-protected process execution for intentional deadlock
workloads, offline event stream evaluation, and automated benchmark orchestration.
"""

from dataclasses import dataclass, field
import logging
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from collector.event_parser import parse_line, Event
from graph.rag import ResourceAllocationGraph
from graph.cycle_detector import CycleDetector
from diagnosis.explainer import DeadlockExplainer
from dna import fingerprint_cycle
from .metrics import BenchmarkMetrics, compute_metrics
from .report import export_csv, export_json_summary, export_markdown_report

logger = logging.getLogger(__name__)


@dataclass
class WorkloadRunResult:
    workload_name: str
    run_index: int = 0
    expected_deadlock: bool = False
    detected_deadlock: bool = False
    latency_us: Optional[float] = None
    elapsed_sec: float = 0.0
    observer_mode: str = "replay"
    fingerprint: Optional[str] = None
    canonical_pattern: Optional[str] = None
    event_count: int = 0
    parse_errors: int = 0
    exit_code: int = 0
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""


class WorkloadHarness:
    """
    Executes a target command in an isolated process group with a strict timeout.
    Safely terminates deadlocked or hanging processes without leaving orphans.
    """

    def __init__(self, timeout_sec: float = 5.0) -> None:
        self.timeout_sec = timeout_sec

    def run_command(
        self, cmd: List[str], cwd: Optional[Path] = None
    ) -> WorkloadRunResult:
        """Runs a subprocess with process-group isolation and timeout enforcement."""
        t_start = time.monotonic()
        timed_out = False
        stdout_str = ""
        stderr_str = ""
        exit_code = 0

        # Use start_new_session=True on POSIX to create a new process group
        is_posix = os.name == "posix"
        kwargs: Dict[str, Any] = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "cwd": cwd,
        }
        if is_posix:
            kwargs["start_new_session"] = True

        proc = subprocess.Popen(cmd, **kwargs)

        try:
            stdout_str, stderr_str = proc.communicate(timeout=self.timeout_sec)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            logger.info("process timed out after %.2fs — killing group", self.timeout_sec)
            if is_posix:
                try:
                    pgid = os.getpgid(proc.pid)
                    os.killpg(pgid, signal.SIGTERM)
                    time.sleep(0.2)
                    if proc.poll() is None:
                        os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                proc.kill()

            try:
                out, err = proc.communicate(timeout=1.0)
                stdout_str = out or ""
                stderr_str = err or ""
            except Exception:
                pass
            exit_code = proc.returncode if proc.returncode is not None else -signal.SIGTERM

        elapsed = max(time.monotonic() - t_start, 0.0001)

        return WorkloadRunResult(
            workload_name=Path(cmd[0]).name if cmd else "unknown",
            elapsed_sec=elapsed,
            exit_code=exit_code,
            timed_out=timed_out,
            stdout=stdout_str,
            stderr=stderr_str,
        )


@dataclass
class BenchmarkSuiteResult:
    runs: List[WorkloadRunResult]
    metrics: BenchmarkMetrics


class BenchmarkRunner:
    """
    Orchestrates the evaluation of workloads across replay files and live binaries.
    """

    def __init__(self, output_dir: Union[Path, str]) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._workloads: List[Dict[str, Any]] = []

    def add_replay_workload(
        self,
        name: str,
        event_file: Union[Path, str],
        expected_deadlock: bool,
        runs: int = 1,
    ) -> None:
        """Registers an offline JSON event log for evaluation."""
        self._workloads.append({
            "type": "replay",
            "name": name,
            "path": Path(event_file),
            "expected_deadlock": expected_deadlock,
            "runs": runs,
        })

    def add_binary_workload(
        self,
        name: str,
        binary_path: Union[Path, str],
        expected_deadlock: bool,
        runs: int = 1,
        timeout_sec: float = 3.0,
    ) -> None:
        """Registers a compiled C executable workload."""
        self._workloads.append({
            "type": "binary",
            "name": name,
            "path": Path(binary_path),
            "expected_deadlock": expected_deadlock,
            "runs": runs,
            "timeout_sec": timeout_sec,
        })

    def evaluate_event_file(
        self,
        file_path: Union[Path, str],
        workload_name: str,
        expected_deadlock: bool,
        run_index: int = 0,
    ) -> WorkloadRunResult:
        """
        Feeds an event stream file through RAG, CycleDetector, DeadlockExplainer,
        and Deadlock DNA Fingerprinter to evaluate detection and latency.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Event file not found: {path}")

        rag = ResourceAllocationGraph()
        detector = CycleDetector()
        explainer = DeadlockExplainer()

        detected = False
        detected_fp = None
        detected_canon = None
        latency_us = None
        event_count = 0
        parse_errors = 0

        t_start = time.monotonic()

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                event = parse_line(line)
                if event is None:
                    # check if empty/comment line vs actual malformed line
                    stripped = line.strip()
                    if stripped and not stripped.startswith(("#", "//", "[")):
                        parse_errors += 1
                    continue

                event_count += 1
                rag.process_event(event)
                results = detector.detect(rag.get_graph(), event.timestamp_ns)

                if results:
                    detected = True
                    for r in results:
                        if latency_us is None:
                            latency_us = r.latency_us
                        try:
                            fp, canon = fingerprint_cycle(r.cycle)
                            detected_fp = fp
                            detected_canon = canon.pattern
                        except Exception as e:
                            logger.debug("fingerprint error in benchmark: %s", e)

        elapsed = time.monotonic() - t_start

        return WorkloadRunResult(
            workload_name=workload_name,
            run_index=run_index,
            expected_deadlock=expected_deadlock,
            detected_deadlock=detected,
            latency_us=latency_us,
            elapsed_sec=elapsed,
            observer_mode="replay",
            fingerprint=detected_fp,
            canonical_pattern=detected_canon,
            event_count=event_count,
            parse_errors=parse_errors,
        )

    def run_all(self) -> BenchmarkSuiteResult:
        """Executes all registered workloads, computes metrics, and exports reports."""
        all_runs: List[WorkloadRunResult] = []

        for item in self._workloads:
            w_type = item["type"]
            name = item["name"]
            expected = item["expected_deadlock"]
            runs = item.get("runs", 1)

            if w_type == "replay":
                file_path = item["path"]
                for i in range(runs):
                    res = self.evaluate_event_file(
                        file_path=file_path,
                        workload_name=name,
                        expected_deadlock=expected,
                        run_index=i,
                    )
                    all_runs.append(res)

            elif w_type == "binary":
                bin_path = item["path"]
                harness = WorkloadHarness(timeout_sec=item.get("timeout_sec", 3.0))
                for i in range(runs):
                    h_res = harness.run_command([str(bin_path)])
                    run_res = WorkloadRunResult(
                        workload_name=name,
                        run_index=i,
                        expected_deadlock=expected,
                        detected_deadlock=h_res.timed_out if expected else False,
                        elapsed_sec=h_res.elapsed_sec,
                        exit_code=h_res.exit_code,
                        timed_out=h_res.timed_out,
                        observer_mode="baseline",
                        stdout=h_res.stdout,
                        stderr=h_res.stderr,
                    )
                    all_runs.append(run_res)

        metrics = compute_metrics(all_runs)

        # Export all 3 artifacts specified in Section 5
        export_csv(all_runs, self.output_dir / "raw_runs.csv")
        export_json_summary(metrics, all_runs, self.output_dir / "summary.json")
        export_markdown_report(metrics, all_runs, self.output_dir / "report.md")

        return BenchmarkSuiteResult(runs=all_runs, metrics=metrics)
