"""
run_benchmarks.py — DeadlockDNA Benchmark Runner CLI (benchmarks/)
DeadlockDNA — Feature C (Milestone 3)

Runs reproducible evaluation suites across test workloads, measuring:
- Detection success rate & false positive rate
- Detection latency (median, p95)
- Observer runtime overhead
- Deadlock DNA fingerprint consistency
- Event loss & parse errors

Outputs raw CSV rows, JSON summary metrics, and Markdown reports.
"""

import argparse
from pathlib import Path
import subprocess
import sys
import time

# Ensure project root is on sys.path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from benchmarks.harness import BenchmarkRunner, WorkloadHarness
from benchmarks.metrics import compute_metrics, compute_overhead_percent
from benchmarks.report import (
    export_csv,
    export_json_summary,
    export_markdown_report,
    gather_environment_info,
)


def compile_workloads() -> bool:
    """Compiles all C targets and benchmark workloads."""
    print("[benchmarks] Compiling targets and workloads...")
    c_files = [
        (_ROOT / "targets" / "test_2way.c", _ROOT / "targets" / "test_2way"),
        (_ROOT / "targets" / "test_3way.c", _ROOT / "targets" / "test_3way"),
        (_ROOT / "targets" / "test_semaphore.c", _ROOT / "targets" / "test_semaphore"),
        (_ROOT / "benchmarks" / "workloads" / "workload_no_lock.c", _ROOT / "benchmarks" / "workloads" / "workload_no_lock"),
        (_ROOT / "benchmarks" / "workloads" / "workload_single_mutex.c", _ROOT / "benchmarks" / "workloads" / "workload_single_mutex"),
        (_ROOT / "benchmarks" / "workloads" / "workload_contention.c", _ROOT / "benchmarks" / "workloads" / "workload_contention"),
        (_ROOT / "benchmarks" / "workloads" / "workload_stress.c", _ROOT / "benchmarks" / "workloads" / "workload_stress"),
    ]

    for src, bin_path in c_files:
        if not src.exists():
            continue
        cmd = ["gcc", "-Wall", "-Wextra", "-pthread", "-O0", "-g", str(src), "-o", str(bin_path)]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            print(f"[benchmarks] Compilation failed for {src}:\n{res.stderr}", file=sys.stderr)
            return False

    print("[benchmarks] All C workloads compiled successfully.")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DeadlockDNA — Automated Benchmark & Evaluation Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--runs", type=int, default=5,
        help="Number of iterations per workload (default: 5)"
    )
    parser.add_argument(
        "--timeout", type=float, default=2.0,
        help="Timeout in seconds for deadlocking programs (default: 2.0s)"
    )
    parser.add_argument(
        "--output-dir", type=str, default=str(_ROOT / "benchmarks" / "results"),
        help="Directory to save raw_runs.csv, summary.json, and report.md"
    )
    parser.add_argument(
        "--mode", choices=["all", "replay", "binary"], default="all",
        help="Execution mode (all, replay, or binary)"
    )
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("  DeadlockDNA Benchmark Suite (Milestone 3)")
    print("=" * 60)

    # 1. Compile C workloads if needed
    if args.mode in ("all", "binary"):
        if not compile_workloads():
            print("[benchmarks] ERROR: Workload compilation failed", file=sys.stderr)
            sys.exit(1)

    runner = BenchmarkRunner(output_dir=out_dir)

    # 2. Register Replay Workloads
    if args.mode in ("all", "replay"):
        sample_dl = _ROOT / "tests" / "sample_events.json"
        sample_clean = _ROOT / "tests" / "sample_clean_events.json"
        sample_sqlite = _ROOT / "tests" / "sample_sqlite_events.json"
        sample_memcached = _ROOT / "tests" / "sample_memcached_events.json"
        if sample_dl.exists():
            runner.add_replay_workload(
                name="replay_2way_deadlock",
                event_file=sample_dl,
                expected_deadlock=True,
                runs=args.runs,
            )
        if sample_clean.exists():
            runner.add_replay_workload(
                name="replay_clean_sequential",
                event_file=sample_clean,
                expected_deadlock=False,
                runs=args.runs,
            )
        if sample_sqlite.exists():
            runner.add_replay_workload(
                name="replay_sqlite_heavy_workload",
                event_file=sample_sqlite,
                expected_deadlock=False,
                runs=args.runs,
            )
        if sample_memcached.exists():
            runner.add_replay_workload(
                name="replay_memcached_striped_locks",
                event_file=sample_memcached,
                expected_deadlock=False,
                runs=args.runs,
            )

    # 3. Register Binary Workloads
    if args.mode in ("all", "binary"):
        bin_dir = _ROOT / "benchmarks" / "workloads"
        targets_dir = _ROOT / "targets"

        safe_binaries = [
            ("workload_no_lock", bin_dir / "workload_no_lock"),
            ("workload_single_mutex", bin_dir / "workload_single_mutex"),
            ("workload_contention", bin_dir / "workload_contention"),
            ("workload_stress", bin_dir / "workload_stress"),
        ]
        for name, path in safe_binaries:
            if path.exists():
                runner.add_binary_workload(
                    name=name,
                    binary_path=path,
                    expected_deadlock=False,
                    runs=args.runs,
                    timeout_sec=args.timeout,
                )

        dl_binaries = [
            ("target_test_2way", targets_dir / "test_2way"),
            ("target_test_3way", targets_dir / "test_3way"),
        ]
        for name, path in dl_binaries:
            if path.exists():
                runner.add_binary_workload(
                    name=name,
                    binary_path=path,
                    expected_deadlock=True,
                    runs=args.runs,
                    timeout_sec=args.timeout,
                )

    print(f"[benchmarks] Running registered workloads ({args.runs} runs each)...")
    suite_res = runner.run_all()
    m = suite_res.metrics

    print("\n" + "=" * 60)
    print("  Benchmark Results Summary")
    print("=" * 60)
    print(f"Total Runs:                 {m.total_runs}")
    print(f"Detection Success Rate:     {m.detection_success_rate * 100:.1f}% ({m.true_positive_count}/{m.total_deadlock_workloads})")
    print(f"False-Positive Rate:        {m.false_positive_rate * 100:.1f}% ({m.false_positive_count}/{m.total_non_deadlock_workloads})")
    print(f"False Negatives:            {m.false_negative_count}")
    if m.median_latency_us is not None:
        print(f"Median Detection Latency:   {m.median_latency_us:.1f} µs")
        print(f"p95 Detection Latency:      {m.p95_latency_us:.1f} µs")
    print(f"Fingerprint Consistency:    {m.fingerprint_consistency * 100:.1f}%")
    print(f"Parse Errors / Event Loss:  {m.total_parse_errors}")
    print("=" * 60)
    print(f"Artifacts exported to: {out_dir}")
    print(f"  - CSV Raw Data:   {out_dir / 'raw_runs.csv'}")
    print(f"  - JSON Summary:   {out_dir / 'summary.json'}")
    print(f"  - Markdown Report: {out_dir / 'report.md'}")
    print("=" * 60)


if __name__ == "__main__":
    main()

