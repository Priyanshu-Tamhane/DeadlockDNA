"""
scripts/generate_real_workload_traces.py — Real-World Workload Trace Generator

Generates high-fidelity event traces for:
  1. tests/sample_sqlite_events.json (Heavy concurrent database workload: WAL, pager, memory mutexes)
  2. tests/sample_memcached_events.json (Heavy concurrent web cache: 64 hash buckets, slabs_lock)
  3. tests/sample_memcached_hazard_events.json (Memcached with AB/BA lock order hierarchy hazard)
"""

import json
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def generate_sqlite_trace(out_path: Path, num_events: int = 1200) -> None:
    """Simulates multi-threaded SQLite database engine events."""
    events = []
    pid = 8000
    threads = [8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008]

    # Mutexes in SQLite
    conn_mutex = "0x55aa1000"       # Database connection handle mutex
    pager_mutex = "0x55aa2000"      # Pager / btree cache mutex
    wal_mutex = "0x55aa3000"        # Write-Ahead Log index mutex
    mem_mutex = "0x55aa4000"        # Global memory allocator mutex

    ts = 1700000000000000000

    # Interleaved transactions
    for i in range(num_events // 8):
        t = threads[i % len(threads)]

        # 1. Thread acquires connection mutex
        events.append({"timestamp_ns": ts, "pid": pid, "tid": t, "resource": conn_mutex, "operation": "LOCK_ACQUIRED"})
        ts += 500

        # 2. Allocates memory for query plan
        events.append({"timestamp_ns": ts, "pid": pid, "tid": t, "resource": mem_mutex, "operation": "LOCK_ACQUIRED"})
        ts += 300
        events.append({"timestamp_ns": ts, "pid": pid, "tid": t, "resource": mem_mutex, "operation": "LOCK_RELEASED"})
        ts += 200

        # 3. Pager cache access
        events.append({"timestamp_ns": ts, "pid": pid, "tid": t, "resource": pager_mutex, "operation": "LOCK_ACQUIRED"})
        ts += 600

        # 4. If writer, also touches WAL mutex
        if i % 3 == 0:
            events.append({"timestamp_ns": ts, "pid": pid, "tid": t, "resource": wal_mutex, "operation": "LOCK_ACQUIRED"})
            ts += 400
            events.append({"timestamp_ns": ts, "pid": pid, "tid": t, "resource": wal_mutex, "operation": "LOCK_RELEASED"})
            ts += 300

        events.append({"timestamp_ns": ts, "pid": pid, "tid": t, "resource": pager_mutex, "operation": "LOCK_RELEASED"})
        ts += 400
        events.append({"timestamp_ns": ts, "pid": pid, "tid": t, "resource": conn_mutex, "operation": "LOCK_RELEASED"})
        ts += 500

    with open(out_path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
    print(f"Generated {len(events)} SQLite events at {out_path}")


def generate_memcached_trace(out_path: Path, num_events: int = 1500) -> None:
    """Simulates Memcached clean high-throughput cache operations across 64 bucket locks."""
    events = []
    pid = 9000
    threads = [9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008]
    slabs_lock = "0x7fff0000"
    lru_lock = "0x7fff0010"

    # 64 bucket locks
    bucket_locks = [f"0x7fff{1000 + (b * 16):04x}" for b in range(64)]

    ts = 1700000000000000000

    for i in range(num_events // 6):
        t = threads[i % len(threads)]
        bucket = bucket_locks[i % len(bucket_locks)]

        # Consistent hierarchy: item_lock -> slabs_lock
        events.append({"timestamp_ns": ts, "pid": pid, "tid": t, "resource": bucket, "operation": "LOCK_ACQUIRED"})
        ts += 200

        if i % 2 == 0:
            events.append({"timestamp_ns": ts, "pid": pid, "tid": t, "resource": slabs_lock, "operation": "LOCK_ACQUIRED"})
            ts += 150
            events.append({"timestamp_ns": ts, "pid": pid, "tid": t, "resource": slabs_lock, "operation": "LOCK_RELEASED"})
            ts += 150

        events.append({"timestamp_ns": ts, "pid": pid, "tid": t, "resource": bucket, "operation": "LOCK_RELEASED"})
        ts += 200

        # Background maintenance tick
        if i % 20 == 0:
            m_tid = threads[-1]
            events.append({"timestamp_ns": ts, "pid": pid, "tid": m_tid, "resource": lru_lock, "operation": "LOCK_ACQUIRED"})
            ts += 100
            events.append({"timestamp_ns": ts, "pid": pid, "tid": m_tid, "resource": slabs_lock, "operation": "LOCK_ACQUIRED"})
            ts += 100
            events.append({"timestamp_ns": ts, "pid": pid, "tid": m_tid, "resource": slabs_lock, "operation": "LOCK_RELEASED"})
            ts += 100
            events.append({"timestamp_ns": ts, "pid": pid, "tid": m_tid, "resource": lru_lock, "operation": "LOCK_RELEASED"})
            ts += 100

    with open(out_path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
    print(f"Generated {len(events)} Memcached clean events at {out_path}")


def generate_memcached_hazard_trace(out_path: Path) -> None:
    """Simulates Memcached classic slab-vs-bucket hierarchy inversion hazard."""
    events = []
    pid = 9000
    worker_tid = 9001
    crawler_tid = 9008
    bucket_lock = "0x7fff1000"
    slabs_lock = "0x7fff0000"

    ts = 1700000000000000000

    # Worker executes SET: bucket -> slab
    events.append({"timestamp_ns": ts, "pid": pid, "tid": worker_tid, "resource": bucket_lock, "operation": "LOCK_ACQUIRED"})
    ts += 1000
    events.append({"timestamp_ns": ts, "pid": pid, "tid": worker_tid, "resource": slabs_lock, "operation": "LOCK_ACQUIRED"})
    ts += 1000
    events.append({"timestamp_ns": ts, "pid": pid, "tid": worker_tid, "resource": slabs_lock, "operation": "LOCK_RELEASED"})
    ts += 1000
    events.append({"timestamp_ns": ts, "pid": pid, "tid": worker_tid, "resource": bucket_lock, "operation": "LOCK_RELEASED"})
    ts += 2000

    # Crawler executes LRU maintenance: slab -> bucket (INVERSION!)
    events.append({"timestamp_ns": ts, "pid": pid, "tid": crawler_tid, "resource": slabs_lock, "operation": "LOCK_ACQUIRED"})
    ts += 1000
    events.append({"timestamp_ns": ts, "pid": pid, "tid": crawler_tid, "resource": bucket_lock, "operation": "LOCK_ACQUIRED"})
    ts += 1000
    events.append({"timestamp_ns": ts, "pid": pid, "tid": crawler_tid, "resource": bucket_lock, "operation": "LOCK_RELEASED"})
    ts += 1000
    events.append({"timestamp_ns": ts, "pid": pid, "tid": crawler_tid, "resource": slabs_lock, "operation": "LOCK_RELEASED"})

    with open(out_path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
    print(f"Generated {len(events)} Memcached hazard events at {out_path}")


if __name__ == "__main__":
    tests_dir = _ROOT / "tests"
    generate_sqlite_trace(tests_dir / "sample_sqlite_events.json")
    generate_memcached_trace(tests_dir / "sample_memcached_events.json")
    generate_memcached_hazard_trace(tests_dir / "sample_memcached_hazard_events.json")
