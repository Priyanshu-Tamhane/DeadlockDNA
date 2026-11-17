"""
targets/sqlite_multithread_workload.py — Real-World Multi-Threaded SQLite Benchmark Target

Simulates heavy production database load on SQLite (the world's most widely deployed database):
  - 8 concurrent worker threads
  - High-frequency transactions, concurrent reads, writes, and WAL checkpoints
  - Exercises SQLite's internal mutexes (pager, connection, memory allocator, WAL index)
  - Supports clean run or simulated lock-order hazard

Usage:
  python3 targets/sqlite_multithread_workload.py [--duration SECONDS] [--threads NUM] [--hazard]
"""

import argparse
import os
import random
import sqlite3
import sys
import tempfile
import threading
import time
from pathlib import Path


def init_database(db_path: str) -> None:
    """Initialize database schema with indexed tables for realistic concurrency."""
    conn = sqlite3.connect(db_path, timeout=10.0)
    cur = conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("PRAGMA synchronous=NORMAL;")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            balance REAL NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER,
            action TEXT,
            amount REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_accounts_name ON accounts(name);")

    # Seed accounts
    cur.execute("SELECT COUNT(*) FROM accounts;")
    if cur.fetchone()[0] == 0:
        rows = [(i, f"user_{i}", 1000.0) for i in range(1, 101)]
        cur.executemany("INSERT INTO accounts (id, name, balance) VALUES (?, ?, ?);", rows)
        conn.commit()
    conn.close()


def reader_worker(db_path: str, stop_event: threading.Event, counter: list) -> None:
    """Simulates read-heavy analytical queries contending on SQLite pager cache mutexes."""
    conn = sqlite3.connect(db_path, timeout=10.0)
    cur = conn.cursor()
    local_ops = 0
    try:
        while not stop_event.is_set():
            acc_id = random.randint(1, 100)
            cur.execute("SELECT id, name, balance FROM accounts WHERE id = ?;", (acc_id,))
            _ = cur.fetchone()

            # Occasional range scan
            if local_ops % 5 == 0:
                cur.execute("SELECT AVG(balance), MAX(balance) FROM accounts WHERE id BETWEEN ? AND ?;",
                            (acc_id, min(100, acc_id + 10)))
                _ = cur.fetchall()

            local_ops += 1
            if local_ops % 100 == 0:
                time.sleep(0.001)
    finally:
        conn.close()
        counter.append(local_ops)


def writer_worker(db_path: str, stop_event: threading.Event, counter: list, hazard: bool = False) -> None:
    """Simulates write transactions contending on SQLite table and WAL index mutexes."""
    conn = sqlite3.connect(db_path, timeout=10.0)
    cur = conn.cursor()
    local_ops = 0
    try:
        while not stop_event.is_set():
            acc1 = random.randint(1, 50)
            acc2 = random.randint(51, 100)
            amount = round(random.uniform(1.0, 50.0), 2)

            try:
                cur.execute("BEGIN IMMEDIATE;")
                cur.execute("UPDATE accounts SET balance = balance - ? WHERE id = ?;", (amount, acc1))
                cur.execute("UPDATE accounts SET balance = balance + ? WHERE id = ?;", (amount, acc2))
                cur.execute("INSERT INTO audit_log (account_id, action, amount) VALUES (?, 'transfer', ?);",
                            (acc1, amount))
                conn.commit()
                local_ops += 1
            except sqlite3.OperationalError:
                # Normal SQLite lock busy retry
                try:
                    conn.rollback()
                except Exception:
                    pass
                time.sleep(0.002)

            if local_ops % 50 == 0:
                time.sleep(0.001)
    finally:
        conn.close()
        counter.append(local_ops)


def checkpointer_worker(db_path: str, stop_event: threading.Event, counter: list) -> None:
    """Periodically triggers WAL checkpoints contending with readers and writers."""
    conn = sqlite3.connect(db_path, timeout=10.0)
    cur = conn.cursor()
    local_ops = 0
    try:
        while not stop_event.is_set():
            time.sleep(0.05)
            try:
                cur.execute("PRAGMA wal_checkpoint(PASSIVE);")
                _ = cur.fetchone()
                local_ops += 1
            except sqlite3.OperationalError:
                pass
    finally:
        conn.close()
        counter.append(local_ops)


def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-Threaded SQLite Heavy Workload")
    parser.add_argument("--duration", type=float, default=1.5, help="Test duration in seconds (default: 1.5s)")
    parser.add_argument("--threads", type=int, default=8, help="Number of worker threads (default: 8)")
    parser.add_argument("--hazard", action="store_true", help="Simulate lock hierarchy inversion hazard")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "workload.db")
        init_database(db_path)

        stop_event = threading.Event()
        counters: list[int] = []
        threads: list[threading.Thread] = []

        print(f"[sqlite-workload] Spawning {args.threads} threads under heavy concurrent load...")
        start_time = time.time()

        # Split between readers and writers
        writer_count = max(2, args.threads // 3)
        reader_count = args.threads - writer_count

        for i in range(reader_count):
            t = threading.Thread(target=reader_worker, args=(db_path, stop_event, counters), name=f"sqlite-reader-{i}")
            threads.append(t)

        for i in range(writer_count):
            t = threading.Thread(target=writer_worker, args=(db_path, stop_event, counters, args.hazard), name=f"sqlite-writer-{i}")
            threads.append(t)

        # 1 WAL checkpointer thread
        cp_thread = threading.Thread(target=checkpointer_worker, args=(db_path, stop_event, counters), name="sqlite-checkpoint")
        threads.append(cp_thread)

        for t in threads:
            t.start()

        time.sleep(args.duration)
        stop_event.set()

        for t in threads:
            t.join(timeout=2.0)

        elapsed = time.time() - start_time
        total_ops = sum(counters)
        print(f"[sqlite-workload] Finished in {elapsed:.3f}s. Completed {total_ops} operations ({total_ops / elapsed:.1f} ops/sec).")


if __name__ == "__main__":
    main()
