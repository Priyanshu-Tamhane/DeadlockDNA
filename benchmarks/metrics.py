"""
metrics.py — Benchmark Metrics Computation (benchmarks/)
DeadlockDNA — Feature C (Milestone 3)

Computes reproducible detection latency, success rates, false-positive rates,
observer overhead, event parser metrics, and fingerprint consistency.
"""

from dataclasses import dataclass
import math
import statistics
from typing import Dict, List, Optional, Sequence


@dataclass
class BenchmarkMetrics:
    total_runs: int
    total_deadlock_workloads: int
    total_non_deadlock_workloads: int
    true_positive_count: int
    true_negative_count: int
    false_positive_count: int
    false_negative_count: int
    detection_success_rate: float
    false_positive_rate: float
    median_latency_us: Optional[float]
    p95_latency_us: Optional[float]
    min_latency_us: Optional[float]
    max_latency_us: Optional[float]
    observer_overhead_percent: Optional[float]
    fingerprint_consistency: float
    total_parse_errors: int
    total_events_processed: int


def compute_latency_stats(latencies: Sequence[float]) -> Dict[str, Optional[float]]:
    """
    Computes min, max, median, and 95th percentile (p95) latency.
    Returns dict with keys 'min', 'max', 'median', 'p95'.
    """
    valid = [float(x) for x in latencies if x is not None and not math.isnan(x)]
    if not valid:
        return {"min": None, "max": None, "median": None, "p95": None}

    sorted_vals = sorted(valid)
    n = len(sorted_vals)
    med = statistics.median(sorted_vals)

    # 95th percentile (nearest rank or linear interpolation)
    if n == 1:
        p95 = sorted_vals[0]
    else:
        # standard index: 0.95 * (n - 1)
        rank = 0.95 * (n - 1)
        low = int(math.floor(rank))
        high = int(math.ceil(rank))
        weight = rank - low
        p95 = sorted_vals[low] * (1.0 - weight) + sorted_vals[high] * weight

    return {
        "min": sorted_vals[0],
        "max": sorted_vals[-1],
        "median": float(med),
        "p95": float(p95),
    }


def compute_overhead_percent(
    baseline_times: Sequence[float], observed_times: Sequence[float]
) -> float:
    """
    Calculates observer runtime overhead percentage comparing median runtimes:
      overhead = ((median_observed - median_baseline) / median_baseline) * 100.0
    """
    if not baseline_times or not observed_times:
        return 0.0

    med_base = statistics.median(baseline_times)
    med_obs = statistics.median(observed_times)

    if med_base <= 0:
        return 0.0

    return ((med_obs - med_base) / med_base) * 100.0


def compute_fingerprint_consistency(runs: Sequence) -> float:
    """
    Calculates the ratio of the most frequent structural fingerprint
    over total detected deadlocks.
    """
    fp_counts: Dict[str, int] = {}
    total = 0

    for r in runs:
        if getattr(r, "detected_deadlock", False) and getattr(r, "fingerprint", None):
            fp = r.fingerprint
            fp_counts[fp] = fp_counts.get(fp, 0) + 1
            total += 1

    if total == 0:
        return 1.0

    max_count = max(fp_counts.values())
    return max_count / total


def compute_metrics(
    runs: Sequence,
    baseline_times: Optional[Sequence[float]] = None,
) -> BenchmarkMetrics:
    """
    Computes aggregate benchmark metrics across all run results.
    """
    total_runs = len(runs)
    total_dl = sum(1 for r in runs if r.expected_deadlock)
    total_non_dl = sum(1 for r in runs if not r.expected_deadlock)

    tp = sum(1 for r in runs if r.expected_deadlock and r.detected_deadlock)
    fn = sum(1 for r in runs if r.expected_deadlock and not r.detected_deadlock)
    tn = sum(1 for r in runs if not r.expected_deadlock and not r.detected_deadlock)
    fp = sum(1 for r in runs if not r.expected_deadlock and r.detected_deadlock)

    det_rate = (tp / total_dl) if total_dl > 0 else 1.0
    fp_rate = (fp / total_non_dl) if total_non_dl > 0 else 0.0

    latencies = [
        r.latency_us for r in runs
        if r.detected_deadlock and r.latency_us is not None
    ]
    lat_stats = compute_latency_stats(latencies)

    observed_times = [
        r.elapsed_sec for r in runs
        if r.elapsed_sec is not None and r.elapsed_sec > 0
        and getattr(r, "observer_mode", "") not in ("unobserved_baseline", "baseline")
    ]
    if not observed_times and baseline_times:
        observed_times = [r.elapsed_sec for r in runs if r.elapsed_sec is not None and r.elapsed_sec > 0]

    overhead = (
        compute_overhead_percent(baseline_times, observed_times)
        if baseline_times and observed_times
        else None
    )

    consistency = compute_fingerprint_consistency(runs)

    total_parse_errors = sum(getattr(r, "parse_errors", 0) for r in runs)
    total_events = sum(getattr(r, "event_count", 0) for r in runs)

    return BenchmarkMetrics(
        total_runs=total_runs,
        total_deadlock_workloads=total_dl,
        total_non_deadlock_workloads=total_non_dl,
        true_positive_count=tp,
        true_negative_count=tn,
        false_positive_count=fp,
        false_negative_count=fn,
        detection_success_rate=det_rate,
        false_positive_rate=fp_rate,
        median_latency_us=lat_stats["median"],
        p95_latency_us=lat_stats["p95"],
        min_latency_us=lat_stats["min"],
        max_latency_us=lat_stats["max"],
        observer_overhead_percent=overhead,
        fingerprint_consistency=consistency,
        total_parse_errors=total_parse_errors,
        total_events_processed=total_events,
    )

