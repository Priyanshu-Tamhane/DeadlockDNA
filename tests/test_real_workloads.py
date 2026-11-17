"""
tests/test_real_workloads.py — Unit Tests for Real-World Workload Monitoring (Upgrade 3)

Validates DeadlockDNA's ability to monitor real, production-grade applications:
  - SQLite (multi-threaded database engine with WAL, pager, and memory allocator locks)
  - Memcached (cache server with 64 fine-grained striped hash bucket mutexes & slab allocator)
"""

from pathlib import Path
import pytest

from collector.collector import collect_from_file
from diagnosis.symbol_resolver import SymbolResolver
from main import run

_TESTS_DIR = Path(__file__).parent
_SQLITE_EVENTS = str(_TESTS_DIR / "sample_sqlite_events.json")
_MEMCACHED_EVENTS = str(_TESTS_DIR / "sample_memcached_events.json")
_MEMCACHED_HAZARD = str(_TESTS_DIR / "sample_memcached_hazard_events.json")


def test_sqlite_heavy_workload_monitoring():
    """DeadlockDNA must monitor 1000+ SQLite database events with zero false positives."""
    gen = collect_from_file(_SQLITE_EVENTS, delay=0.0)
    code = run(
        collector=gen,
        target_name="sqlite",
        pid=8000,
        ci_mode=True,
        fail_on_deadlock=True,
        fail_on_risk=False,
    )
    # Clean run must succeed with code 0
    assert code == 0


def test_memcached_striped_locks_monitoring():
    """DeadlockDNA must monitor 66 concurrent Memcached mutexes without crashing or false positives."""
    gen = collect_from_file(_MEMCACHED_EVENTS, delay=0.0)
    code = run(
        collector=gen,
        target_name="memcached",
        pid=9000,
        ci_mode=True,
        fail_on_deadlock=True,
        fail_on_risk=False,
    )
    # Clean run across 64 hash buckets + slab lock must pass cleanly
    assert code == 0


def test_memcached_hazard_detection():
    """DeadlockDNA must detect Memcached's slab-vs-bucket hierarchy inversion hazard."""
    gen = collect_from_file(_MEMCACHED_HAZARD, delay=0.0)
    code = run(
        collector=gen,
        target_name="memcached",
        pid=9000,
        ci_mode=True,
        fail_on_deadlock=True,
        fail_on_risk=True,
    )
    # Strict gatekeeper must flag inversion with code 2
    assert code == 2


def test_symbol_resolution_for_real_programs():
    """SymbolResolver must map raw hex addresses to meaningful SQLite and Memcached variables."""
    resolver = SymbolResolver(target_hint="sqlite")
    sym = resolver.resolve_resource("0x55aa1000")
    assert sym.name == "sqlite3.mutex_db"
    assert "sqlite3.c" in sym.file

    resolver_mc = SymbolResolver(target_hint="memcached")
    sym_slab = resolver_mc.resolve_resource("0x7fff0000")
    assert sym_slab.name == "memcached.slabs_lock"
    assert "slabs.c" in sym_slab.file
