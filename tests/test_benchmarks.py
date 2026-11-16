"""
test_benchmarks.py — Unit and Integration Tests for DeadlockDNA Benchmark Suite
DeadlockDNA — tests/

Tests the benchmarking engine specified in Feature C (Milestone 3):
- Safe workload execution harness (timeouts, cleanup, non-deadlocking & deadlocking)
- Benchmark metrics computation (detection rate, false-positive rate, latency percentiles, overhead)
- Fingerprint consistency across runs
- Result exporters (CSV, JSON summary, Markdown report)
- Offline and replay benchmark evaluation
"""

import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import pytest

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from benchmarks.harness import (
    WorkloadHarness,
    WorkloadRunResult,
    BenchmarkRunner,
)
from benchmarks.metrics import (
    BenchmarkMetrics,
    compute_metrics,
    compute_latency_stats,
    compute_overhead_percent,
    compute_fingerprint_consistency,
)
from benchmarks.report import (
    export_csv,
    export_json_summary,
    export_markdown_report,
    gather_environment_info,
)


# =====================================================================
# 1. Workload Harness & Process Safety Tests
# =====================================================================

class TestWorkloadHarness:
    """Tests the safe execution harness with process containment and timeouts."""

    def test_clean_process_execution(self):
        """A normal fast command should succeed within timeout and record elapsed time."""
        harness = WorkloadHarness(timeout_sec=5.0)
        # Using python -c as a portable quick command
        result = harness.run_command([sys.executable, "-c", "import sys; sys.exit(0)"])
        assert result.exit_code == 0
        assert not result.timed_out
        assert result.elapsed_sec > 0.0

    def test_deadlock_timeout_and_cleanup(self):
        """A hanging process must be cleanly killed on timeout without blocking."""
        harness = WorkloadHarness(timeout_sec=0.5)
        t_start = time.monotonic()
        # Hanging command: sleep 30
        result = harness.run_command([sys.executable, "-c", "import time; time.sleep(30)"])
        t_elapsed = time.monotonic() - t_start

        assert result.timed_out is True
        assert result.exit_code != 0
        # Ensure timeout fired promptly (~0.5s, well under 5s)
        assert t_elapsed < 3.0

    def test_harness_captures_stdout_stderr(self):
        """Harness should capture stdout and stderr for diagnostic logs."""
        harness = WorkloadHarness(timeout_sec=5.0)
        code = 'import sys; print("out_msg"); sys.stderr.write("err_msg\\n")'
        result = harness.run_command([sys.executable, "-c", code])
        assert "out_msg" in result.stdout
        assert "err_msg" in result.stderr


# =====================================================================
# 2. Benchmark Metrics Computation Tests
# =====================================================================

class TestBenchmarkMetrics:
    """Tests computation of detection rate, false positives, latency, and overhead."""

    def test_metrics_perfect_detection(self):
        """5 true deadlocks detected, 5 non-deadlocks not detected -> perfect scores."""
        runs = [
            WorkloadRunResult(
                workload_name="dl_workload",
                run_index=i,
                expected_deadlock=True,
                detected_deadlock=True,
                latency_us=150.0 + i * 10,
                elapsed_sec=0.1,
                observer_mode="replay",
                fingerprint="fp_abc123",
            )
            for i in range(5)
        ] + [
            WorkloadRunResult(
                workload_name="safe_workload",
                run_index=i,
                expected_deadlock=False,
                detected_deadlock=False,
                latency_us=None,
                elapsed_sec=0.08,
                observer_mode="replay",
                fingerprint=None,
            )
            for i in range(5)
        ]

        metrics = compute_metrics(runs)
        assert metrics.detection_success_rate == 1.0
        assert metrics.false_positive_rate == 0.0
        assert metrics.false_negative_count == 0
        assert metrics.true_positive_count == 5
        assert metrics.true_negative_count == 5
        assert metrics.total_deadlock_workloads == 5
        assert metrics.total_non_deadlock_workloads == 5
        assert metrics.median_latency_us is not None
        assert 150.0 <= metrics.median_latency_us <= 190.0

    def test_metrics_with_false_positives_and_negatives(self):
        """Tests rate calculations when false positives and false negatives exist."""
        runs = [
            # 2 true deadlocks: 1 detected, 1 missed
            WorkloadRunResult("dl_test", 0, True, True, 100.0, 0.1, "replay", "fp1"),
            WorkloadRunResult("dl_test", 1, True, False, None, 0.1, "replay", None),
            # 2 non-deadlocks: 1 correctly clean, 1 false alarm
            WorkloadRunResult("safe_test", 0, False, False, None, 0.1, "replay", None),
            WorkloadRunResult("safe_test", 1, False, True, 50.0, 0.1, "replay", "fp2"),
        ]

        metrics = compute_metrics(runs)
        assert metrics.detection_success_rate == 0.5  # 1 out of 2
        assert metrics.false_negative_count == 1
        assert metrics.false_positive_rate == 0.5     # 1 out of 2
        assert metrics.false_positive_count == 1

    def test_compute_latency_stats(self):
        """Tests median, p95, min, and max latency calculations."""
        latencies = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0]
        stats = compute_latency_stats(latencies)
        assert stats["min"] == 10.0
        assert stats["max"] == 100.0
        assert stats["median"] == 55.0
        assert stats["p95"] >= 90.0

    def test_compute_latency_stats_empty(self):
        """Empty latency list should return zeroes or None gracefully."""
        stats = compute_latency_stats([])
        assert stats["median"] is None
        assert stats["p95"] is None
        assert stats["min"] is None
        assert stats["max"] is None

    def test_compute_overhead_percent(self):
        """Overhead = ((observed_time - baseline_time) / baseline_time) * 100."""
        baseline_times = [1.0, 1.0, 1.0]
        observed_times = [1.1, 1.15, 1.05]
        overhead = compute_overhead_percent(baseline_times, observed_times)
        # Median observed is 1.1, baseline is 1.0 -> 10.0% overhead
        assert round(overhead, 1) == 10.0

    def test_compute_fingerprint_consistency(self):
        """Tests consistency calculation for equivalent deadlock runs."""
        # All matching fingerprints
        runs_identical = [
            WorkloadRunResult("dl_2way", i, True, True, 100.0, 0.1, "replay", "hash_deadlock_a")
            for i in range(10)
        ]
        assert compute_fingerprint_consistency(runs_identical) == 1.0

        # Mixed fingerprints (8 matching, 2 different)
        runs_divergent = runs_identical[:8] + [
            WorkloadRunResult("dl_2way", 8, True, True, 100.0, 0.1, "replay", "hash_other"),
            WorkloadRunResult("dl_2way", 9, True, True, 100.0, 0.1, "replay", "hash_other"),
        ]
        assert compute_fingerprint_consistency(runs_divergent) == 0.8


# =====================================================================
# 3. Report & Artifact Generation Tests
# =====================================================================

class TestBenchmarkReports:
    """Tests writing raw CSV, summary JSON, and Markdown reports."""

    @pytest.fixture
    def sample_runs_and_metrics(self):
        runs = [
            WorkloadRunResult(
                workload_name="targets/test_2way",
                run_index=0,
                expected_deadlock=True,
                detected_deadlock=True,
                latency_us=245.5,
                elapsed_sec=0.15,
                observer_mode="replay",
                fingerprint="a9b8c7d6e5",
                canonical_pattern="THREAD_0->RESOURCE_0->THREAD_1->RESOURCE_1->THREAD_0",
                event_count=8,
                parse_errors=0,
            ),
            WorkloadRunResult(
                workload_name="benchmarks/workload_contention",
                run_index=0,
                expected_deadlock=False,
                detected_deadlock=False,
                latency_us=None,
                elapsed_sec=0.12,
                observer_mode="replay",
                fingerprint=None,
                canonical_pattern=None,
                event_count=12,
                parse_errors=0,
            ),
        ]
        metrics = compute_metrics(runs)
        return runs, metrics

    def test_export_csv(self, sample_runs_and_metrics, tmp_path):
        runs, _ = sample_runs_and_metrics
        csv_file = tmp_path / "raw_runs.csv"
        export_csv(runs, csv_file)

        assert csv_file.exists()
        with open(csv_file, mode="r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) == 2
            assert rows[0]["workload"] == "targets/test_2way"
            assert rows[0]["expected_deadlock"] == "True"
            assert rows[0]["detected_deadlock"] == "True"
            assert float(rows[0]["latency_us"]) == 245.5
            assert rows[0]["fingerprint"] == "a9b8c7d6e5"

    def test_export_json_summary(self, sample_runs_and_metrics, tmp_path):
        runs, metrics = sample_runs_and_metrics
        json_file = tmp_path / "summary.json"
        export_json_summary(metrics, runs, json_file)

        assert json_file.exists()
        with open(json_file, mode="r", encoding="utf-8") as f:
            data = json.load(f)
            assert "environment" in data
            assert "metrics" in data
            assert data["metrics"]["detection_success_rate"] == 1.0
            assert data["metrics"]["false_positive_rate"] == 0.0

    def test_export_markdown_report(self, sample_runs_and_metrics, tmp_path):
        runs, metrics = sample_runs_and_metrics
        report_file = tmp_path / "report.md"
        export_markdown_report(metrics, runs, report_file)

        assert report_file.exists()
        content = report_file.read_text(encoding="utf-8")
        assert "# DeadlockDNA Benchmark & Evaluation Report" in content
        assert "## Environment" in content
        assert "## Results Summary" in content
        assert "## Limitations" in content


# =====================================================================
# 4. End-to-End Benchmark Execution (Replay & Synthetic Workloads)
# =====================================================================

class TestBenchmarkRunnerE2E:
    """Tests executing the benchmark runner end-to-end in offline/replay mode."""

    def test_runner_evaluates_event_fixtures(self, tmp_path):
        """Runner evaluates sample event logs, computes metrics, and produces reports."""
        sample_path = PROJECT_ROOT / "tests" / "sample_events.json"
        assert sample_path.exists(), "tests/sample_events.json missing"

        runner = BenchmarkRunner(output_dir=tmp_path)
        # Evaluate sample deadlock event stream
        run_res = runner.evaluate_event_file(
            file_path=sample_path,
            workload_name="sample_2way_deadlock",
            expected_deadlock=True,
            run_index=0,
        )

        assert run_res.detected_deadlock is True
        assert run_res.fingerprint is not None
        assert run_res.latency_us is not None
        assert run_res.latency_us >= 0.0

    def test_runner_full_suite_generates_all_artifacts(self, tmp_path):
        """Running the benchmark suite writes raw_runs.csv, summary.json, and report.md."""
        runner = BenchmarkRunner(output_dir=tmp_path)
        sample_path = PROJECT_ROOT / "tests" / "sample_events.json"

        # Register workloads (using event replay mode for reliable offline testing)
        runner.add_replay_workload(
            name="2way_mutex_deadlock",
            event_file=sample_path,
            expected_deadlock=True,
            runs=3,
        )

        summary = runner.run_all()

        assert (tmp_path / "raw_runs.csv").exists()
        assert (tmp_path / "summary.json").exists()
        assert (tmp_path / "report.md").exists()
        assert summary.metrics.detection_success_rate == 1.0
        assert summary.metrics.fingerprint_consistency == 1.0

