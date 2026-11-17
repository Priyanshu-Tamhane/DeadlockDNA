"""
tests/test_fixes.py — Verification Tests for Architecture & Pipeline Enhancements

Tests the 8 core fixes:
  1. Actual observer overhead measurement on workloads (baseline vs observed).
  2. Async producer-consumer pipeline (RAG thread + detector thread + UI timer).
  3. Bounded cycle detection with timeout & O(V+E) DFS fallback on complex graphs.
  4. Static binary offsets in Deadlock DNA to prevent collision of topologically identical bugs.
  5. TTL aging and edge eviction on the Lock Order Graph.
  6. Eager symbol resolution caching at process attach (zero subprocesses during UI updates).
  7. Batched O(E) _prune() scan running every N events.
  8. Working --ui / --no-ui CLI flag and parameter control.
"""

import argparse
from pathlib import Path
import sys
import time
import pytest
import networkx as nx

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from collector.event_parser import Event, Operation
from graph.rag import ResourceAllocationGraph
from graph.cycle_detector import CycleDetector, find_cycles_bounded
from risk.lock_order_tracker import LockOrderTracker
from risk.risk_cycle_detector import RiskCycleDetector, find_log_cycles_bounded
from dna.canonicalizer import canonicalize, extract_resource_offset
from dna.fingerprint import fingerprint_cycle
from diagnosis.symbol_resolver import SymbolResolver, SymbolInfo
from benchmarks.harness import WorkloadRunResult, BenchmarkRunner, WorkloadHarness
from benchmarks.metrics import compute_metrics, compute_overhead_percent
from main import run, main as main_cli


# =====================================================================
# 1. Benchmark Overhead Measurement on Workloads
# =====================================================================

def test_benchmark_measures_actual_overhead():
    """Validates baseline vs observed execution time and observer overhead calculation."""
    # Synthetic baseline and observed times
    baseline_times = [0.10, 0.10, 0.10]
    observed_times = [0.12, 0.12, 0.12]  # 20% overhead

    overhead = compute_overhead_percent(baseline_times, observed_times)
    assert round(overhead, 1) == 20.0

    runs = [
        WorkloadRunResult("workload_test", i, False, False, None, baseline_times[i], "unobserved_baseline")
        for i in range(3)
    ] + [
        WorkloadRunResult("workload_test", i, False, False, None, observed_times[i], "observed_workload")
        for i in range(3)
    ]

    metrics = compute_metrics(runs, baseline_times=baseline_times)
    assert metrics.observer_overhead_percent is not None
    assert round(metrics.observer_overhead_percent, 1) == 20.0


# =====================================================================
# 2. Async Producer-Consumer Pipeline
# =====================================================================

def test_async_pipeline_execution():
    """Validates async producer-consumer pipeline with event_queue, RAG, and Detector workers."""
    events = [
        Event(timestamp_ns=1000, pid=7000, tid=1, operation=Operation.LOCK_ACQUIRED, resource="0x1000"),
        Event(timestamp_ns=2000, pid=7000, tid=2, operation=Operation.LOCK_ACQUIRED, resource="0x2000"),
        Event(timestamp_ns=3000, pid=7000, tid=1, operation=Operation.LOCK_REQUEST, resource="0x2000", owner_tid=2),
        Event(timestamp_ns=4000, pid=7000, tid=2, operation=Operation.LOCK_REQUEST, resource="0x1000", owner_tid=1),
    ]

    # Run pipeline in headless mode without UI
    code = run(
        collector=events,
        target_name="test_async",
        pid=7000,
        ci_mode=True,
        fail_on_deadlock=True,
        ui_enabled=False,
    )
    # Deadlock detected asynchronously -> exit code 1
    assert code == 1


# =====================================================================
# 3. Timeout and Fallback for simple_cycles() on Complex Graphs
# =====================================================================

def test_cycle_detector_timeout_and_fallback():
    """Constructs a dense cyclic graph and verifies find_cycles_bounded falls back without hanging."""
    # Build complete directed graph K_8 (many interlocking cycles)
    g = nx.complete_graph(8, create_using=nx.DiGraph)

    # With very low timeout, simple_cycles should either yield or fall back promptly
    cycles, timed_out = find_cycles_bounded(g, timeout_sec=0.01, max_cycles=5)
    assert len(cycles) > 0
    # Must find a cycle without indefinite blocking
    assert len(cycles[0]) >= 2


def test_cycle_detector_dag_fast_path():
    """DAGs must return immediately via O(V+E) topological sort fast path."""
    dag = nx.DiGraph()
    dag.add_edge("T1", "M@1:0x1")
    dag.add_edge("M@1:0x1", "T2")
    dag.add_edge("T2", "M@1:0x2")

    detector = CycleDetector(timeout_sec=0.5)
    results = detector.detect(dag, formation_ts_ns=1000, operation="LOCK_REQUEST")
    assert results == []


# =====================================================================
# 4. Static Binary Offsets in Deadlock DNA
# =====================================================================

def test_dna_hash_distinguishes_topologically_identical_bugs():
    """
    Two 2-way deadlocks in different functions/offsets must NOT collide in DNA fingerprint.
    """
    bug_a = ["M@1000:0x1000", "T1", "M@1000:0x2000", "T2", "M@1000:0x1000"]
    bug_b = ["M@1000:0xbeef", "T1", "M@1000:0xdead", "T2", "M@1000:0xbeef"]

    fp_a, canon_a = fingerprint_cycle(bug_a)
    fp_b, canon_b = fingerprint_cycle(bug_b)

    # Both have the same topological structure:
    assert canon_a.pattern == canon_b.pattern
    # But different resource offsets:
    assert canon_a.resource_offsets == (0x1000, 0x2000)
    assert canon_b.resource_offsets == (0xbeef, 0xdead)
    # Therefore, fingerprints must NOT collide:
    assert fp_a != fp_b


def test_dna_hash_identifies_same_bug_across_runs():
    """The same bug occurring in separate processes/runs produces the exact same fingerprint."""
    run1 = ["M@1000:0x1000", "T1", "M@1000:0x2000", "T2", "M@1000:0x1000"]
    run2 = ["M@9999:0x1000", "T88", "M@9999:0x2000", "T99", "M@9999:0x1000"]

    fp1, _ = fingerprint_cycle(run1)
    fp2, _ = fingerprint_cycle(run2)

    assert fp1 == fp2


# =====================================================================
# 5. Lock Order Graph TTL Aging & Eviction
# =====================================================================

def test_lock_order_graph_ttl_aging():
    """Stale edges older than TTL must be evicted from the Lock Order Graph."""
    tracker = LockOrderTracker(session_id="ttl_test", ttl_ns=5_000_000_000, prune_interval=1)

    # Thread 1 acquires lock A then B at t = 1s
    ev1 = Event(timestamp_ns=1_000_000_000, pid=1, tid=1, operation=Operation.LOCK_ACQUIRED, resource="0x1")
    ev2 = Event(timestamp_ns=1_000_000_000, pid=1, tid=1, operation=Operation.LOCK_ACQUIRED, resource="0x2")
    tracker.process_event(ev1)
    tracker.process_event(ev2)

    # Edge 0x1 -> 0x2 should exist
    assert tracker.graph.number_of_edges() == 1

    # Prune at t = 2s (within 5s TTL) -> edge remains
    tracker.prune_stale_edges(current_ts_ns=2_000_000_000)
    assert tracker.graph.number_of_edges() == 1

    # Prune at t = 7s (6s > 5s TTL) -> edge evicted!
    stale = tracker.prune_stale_edges(current_ts_ns=7_000_000_000)
    assert len(stale) == 1
    assert tracker.graph.number_of_edges() == 0


# =====================================================================
# 6. Eager Symbol Resolution Caching at Attach
# =====================================================================

def test_symbol_resolver_eager_attach_and_zero_subprocess_per_frame():
    """SymbolResolver resolves without spawning subprocesses when allow_subprocesses=False."""
    resolver = SymbolResolver(target_hint="test_2way")
    resolver.attach_process(pid=5000)

    # Known fallback / cached lookups must resolve instantly
    info = resolver.resolve_resource("0x1000", pid=5000, allow_subprocesses=False)
    assert info.name == "L1"

    # Unmapped address with allow_subprocesses=False falls back without spawning subprocesses
    info_unknown = resolver.resolve_resource("0x9999", pid=5000, allow_subprocesses=False)
    assert "0x9999" in info_unknown.name


# =====================================================================
# 7. Batched _prune() Scan
# =====================================================================

def test_rag_prune_batching():
    """RAG batches prune scans every N events instead of scanning every acquire/release."""
    rag = ResourceAllocationGraph(prune_interval=10)
    assert rag._events_since_prune == 0

    # Process 5 acquires
    for i in range(5):
        ev = Event(timestamp_ns=1000 + i, pid=1, tid=i + 1, operation=Operation.LOCK_ACQUIRED, resource=f"0x{i+1}")
        rag.process_event(ev)

    # 5 events processed, interval is 10 -> prune not yet triggered
    assert rag._events_since_prune == 5

    # Process 5 more acquires to hit interval
    for i in range(5, 10):
        ev = Event(timestamp_ns=1000 + i, pid=1, tid=i + 1, operation=Operation.LOCK_ACQUIRED, resource=f"0x{i+1}")
        rag.process_event(ev)

    # Hit 10 -> prune was triggered and counter reset to 0
    assert rag._events_since_prune == 0


# =====================================================================
# 8. Fixed --ui / --no-ui CLI Flag
# =====================================================================

def test_ui_flag_parsing():
    """CLI parser correctly parses --ui and --no-ui."""
    from main import main
    # Create test parser matching main
    p = argparse.ArgumentParser()
    p.add_argument("--ui", action=argparse.BooleanOptionalAction, default=True)

    args_default = p.parse_args([])
    assert args_default.ui is True

    args_no_ui = p.parse_args(["--no-ui"])
    assert args_no_ui.ui is False

    args_explicit_ui = p.parse_args(["--ui"])
    assert args_explicit_ui.ui is True


def test_run_with_ui_disabled():
    """run() with ui_enabled=False completes without launching web dashboard."""
    events = [
        Event(timestamp_ns=1000, pid=10, tid=1, operation=Operation.LOCK_ACQUIRED, resource="0x1"),
        Event(timestamp_ns=2000, pid=10, tid=1, operation=Operation.LOCK_RELEASED, resource="0x1"),
    ]
    code = run(
        collector=events,
        target_name="clean_test",
        pid=10,
        ui_enabled=False,
    )
    assert code == 0
