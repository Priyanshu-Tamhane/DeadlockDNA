"""
report.py — Benchmark Report Exporter (benchmarks/)
DeadlockDNA — Feature C (Milestone 3)

Generates raw CSV data, JSON summary metrics, and formatted Markdown reports
detailing test environment, detection rates, latency percentiles, and limitations.
"""

import csv
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import shutil
import subprocess
from typing import Any, Dict, Sequence

from .metrics import BenchmarkMetrics


def gather_environment_info() -> Dict[str, str]:
    """Collects system, kernel, CPU, Python, and bpftrace environment details."""
    cpu_info = platform.processor() or "Unknown"
    # Read /proc/cpuinfo on Linux for friendly CPU model name if available
    cpu_file = Path("/proc/cpuinfo")
    if cpu_file.exists():
        try:
            for line in cpu_file.read_text(encoding="utf-8").splitlines():
                if "model name" in line:
                    cpu_info = line.split(":", 1)[1].strip()
                    break
        except Exception:
            pass

    bpftrace_ver = "Not installed"
    if shutil.which("bpftrace"):
        try:
            res = subprocess.run(
                ["bpftrace", "--version"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            bpftrace_ver = res.stdout.strip() or res.stderr.strip()
        except Exception:
            bpftrace_ver = "Installed (version probe timed out)"

    return {
        "os": platform.system(),
        "release": platform.release(),
        "kernel": platform.uname().release,
        "platform": platform.platform(),
        "cpu": cpu_info,
        "python_version": platform.python_version(),
        "bpftrace_setup": bpftrace_ver,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


def export_csv(runs: Sequence, file_path: Path | str) -> None:
    """Exports raw execution rows to CSV."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "workload",
        "run_index",
        "observer_mode",
        "expected_deadlock",
        "detected_deadlock",
        "latency_us",
        "elapsed_sec",
        "event_count",
        "parse_errors",
        "fingerprint",
        "canonical_pattern",
    ]

    with open(path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in runs:
            writer.writerow({
                "workload": getattr(r, "workload_name", ""),
                "run_index": getattr(r, "run_index", 0),
                "observer_mode": getattr(r, "observer_mode", ""),
                "expected_deadlock": getattr(r, "expected_deadlock", False),
                "detected_deadlock": getattr(r, "detected_deadlock", False),
                "latency_us": getattr(r, "latency_us", ""),
                "elapsed_sec": getattr(r, "elapsed_sec", 0.0),
                "event_count": getattr(r, "event_count", 0),
                "parse_errors": getattr(r, "parse_errors", 0),
                "fingerprint": getattr(r, "fingerprint", "") or "",
                "canonical_pattern": getattr(r, "canonical_pattern", "") or "",
            })


def export_json_summary(
    metrics: BenchmarkMetrics, runs: Sequence, file_path: Path | str
) -> None:
    """Exports structured metrics summary and environment metadata to JSON."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    summary_data = {
        "environment": gather_environment_info(),
        "metrics": asdict(metrics),
        "runs": [
            {
                "workload": getattr(r, "workload_name", ""),
                "run_index": getattr(r, "run_index", 0),
                "observer_mode": getattr(r, "observer_mode", ""),
                "expected_deadlock": getattr(r, "expected_deadlock", False),
                "detected_deadlock": getattr(r, "detected_deadlock", False),
                "latency_us": getattr(r, "latency_us", None),
                "elapsed_sec": getattr(r, "elapsed_sec", None),
                "fingerprint": getattr(r, "fingerprint", None),
                "canonical_pattern": getattr(r, "canonical_pattern", None),
            }
            for r in runs
        ],
    }

    with open(path, mode="w", encoding="utf-8") as f:
        json.dump(summary_data, f, indent=2)


def export_markdown_report(
    metrics: BenchmarkMetrics, runs: Sequence, file_path: Path | str
) -> None:
    """Exports a human-readable Markdown evaluation report."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    env = gather_environment_info()

    lines = [
        "# DeadlockDNA Benchmark & Evaluation Report",
        "",
        "Empirical evaluation of runtime deadlock detection quality, latency, overhead, and stability.",
        "",
        "---",
        "",
        "## Environment",
        f"- **OS / Kernel**: `{env['os']} {env['kernel']}` (`{env['platform']}`)",
        f"- **CPU**: `{env['cpu']}`",
        f"- **Python Version**: `{env['python_version']}`",
        f"- **bpftrace Setup**: `{env['bpftrace_setup']}`",
        f"- **Timestamp (UTC)**: `{env['timestamp_utc']}`",
        "",
        "---",
        "",
        "## Results Summary",
        "",
        "| Metric | Measured Value |",
        "|---|:---:|",
        f"| **Total Benchmark Runs** | {metrics.total_runs} |",
        f"| **Detection Success Rate** | {metrics.detection_success_rate * 100:.1f}% ({metrics.true_positive_count}/{metrics.total_deadlock_workloads}) |",
        f"| **False-Positive Rate** | {metrics.false_positive_rate * 100:.1f}% ({metrics.false_positive_count}/{metrics.total_non_deadlock_workloads}) |",
        f"| **False Negatives** | {metrics.false_negative_count} |",
        f"| **Median Detection Latency** | {f'{metrics.median_latency_us:.1f} µs' if metrics.median_latency_us is not None else 'N/A'} |",
        f"| **p95 Detection Latency** | {f'{metrics.p95_latency_us:.1f} µs' if metrics.p95_latency_us is not None else 'N/A'} |",
        f"| **Min / Max Latency** | {f'{metrics.min_latency_us:.1f} µs / {metrics.max_latency_us:.1f} µs' if metrics.min_latency_us is not None else 'N/A'} |",
        f"| **Observer Runtime Overhead** | {f'{metrics.observer_overhead_percent:.1f}%' if metrics.observer_overhead_percent is not None else 'N/A'} |",
        f"| **Fingerprint Consistency** | {metrics.fingerprint_consistency * 100:.1f}% |",
        f"| **Parse Errors / Event Loss** | {metrics.total_parse_errors} |",
        "",
        "---",
        "",
        "## Detailed Workload Runs",
        "",
        "| Workload | Run | Mode | Expected | Detected | Latency (µs) | Elapsed (s) | Fingerprint |",
        "|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|",
    ]

    for r in runs:
        lat_str = f"{r.latency_us:.1f}" if getattr(r, "latency_us", None) is not None else "-"
        fp_str = f"`{r.fingerprint[:10]}...`" if getattr(r, "fingerprint", None) else "-"
        lines.append(
            f"| `{r.workload_name}` | {r.run_index} | {r.observer_mode} | "
            f"{'YES' if r.expected_deadlock else 'NO'} | "
            f"{'YES' if r.detected_deadlock else 'NO'} | "
            f"{lat_str} | {r.elapsed_sec:.3f} | {fp_str} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## Limitations",
        "- **Coverage Scope**: Probes rely on Linux kernel futex syscalls or pthread uprobes. Uncontended mutex operations completing entirely in userspace fastpaths do not generate kernel events.",
        "- **WSL2 Clock Domains**: Monotonic timestamps from Linux kernels and Python `time.monotonic_ns()` share the same reference, but simulated replay timestamps are relative and use execution time.",
        "- **Address Identity**: Mutex memory addresses are observation-scoped and normalized during Deadlock DNA canonicalization.",
        "- **Target Workloads**: Evaluation results reflect controlled synthetic workloads; arbitrary multi-runtime applications may exhibit different event throughputs.",
        "",
    ])

    path.write_text("\n".join(lines), encoding="utf-8")

