"""
benchmarks — DeadlockDNA Benchmarking and Evaluation Package
Feature C (Milestone 3)
"""

from .harness import (
    WorkloadHarness,
    WorkloadRunResult,
    BenchmarkRunner,
)
from .metrics import (
    BenchmarkMetrics,
    compute_metrics,
    compute_latency_stats,
    compute_overhead_percent,
    compute_fingerprint_consistency,
)
from .report import (
    export_csv,
    export_json_summary,
    export_markdown_report,
    gather_environment_info,
)

__all__ = [
    "WorkloadHarness",
    "WorkloadRunResult",
    "BenchmarkRunner",
    "BenchmarkMetrics",
    "compute_metrics",
    "compute_latency_stats",
    "compute_overhead_percent",
    "compute_fingerprint_consistency",
    "export_csv",
    "export_json_summary",
    "export_markdown_report",
    "gather_environment_info",
]

