"""
risk/risk_store.py — Persistent Lock-Order History & Edge Store (Feature D)

Persists observed lock-order edges and circular hierarchy risks into SQLite.
Enables cross-run and cross-session lock acquisition order analysis.
"""

import json
from pathlib import Path
import sqlite3
from typing import Dict, List, Optional, Tuple

from .lock_order_tracker import LockOrderEvidence, LockOrderTracker
from .risk_cycle_detector import LockOrderRisk


class RiskStore:
    """
    SQLite-backed store for historical lock-order edges and detected risk warnings.
    """

    def __init__(self, db_path: str = "logs/deadlocks.db") -> None:
        self.db_path = db_path
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        with self._conn:
            self._conn.execute("PRAGMA foreign_keys = ON;")
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS lock_order_edges (
                    src_resource TEXT NOT NULL,
                    dst_resource TEXT NOT NULL,
                    thread_id INTEGER NOT NULL,
                    pid INTEGER NOT NULL,
                    session_id TEXT NOT NULL,
                    first_seen_ns INTEGER NOT NULL,
                    last_seen_ns INTEGER NOT NULL,
                    count INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (src_resource, dst_resource, thread_id, session_id)
                );
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS lock_order_risks (
                    risk_id TEXT PRIMARY KEY,
                    pattern TEXT NOT NULL,
                    cycle_json TEXT NOT NULL,
                    threads_json TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    first_detected_ns INTEGER NOT NULL,
                    last_detected_ns INTEGER NOT NULL,
                    occurrence_count INTEGER NOT NULL DEFAULT 1
                );
            """)

    def record_edge(self, ev: LockOrderEvidence) -> None:
        """Records an observed lock-order edge into the database."""
        with self._conn:
            self._conn.execute("""
                INSERT INTO lock_order_edges (
                    src_resource, dst_resource, thread_id, pid, session_id,
                    first_seen_ns, last_seen_ns, count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(src_resource, dst_resource, thread_id, session_id) DO UPDATE SET
                    last_seen_ns = excluded.last_seen_ns,
                    count = lock_order_edges.count + excluded.count;
            """, (
                ev.src_resource, ev.dst_resource, ev.thread_id, ev.pid, ev.session_id,
                ev.first_seen_ns, ev.last_seen_ns, ev.count
            ))

    def record_risk(self, risk: LockOrderRisk) -> int:
        """
        Records a detected lock-order risk in a transaction.
        Increments occurrence count if already seen.

        Returns:
            Updated occurrence count.
        """
        cycle_json = json.dumps(risk.cycle)
        threads_json = json.dumps(risk.threads_involved)
        evidence_json = json.dumps(risk.evidence)

        with self._conn:
            self._conn.execute("""
                INSERT INTO lock_order_risks (
                    risk_id, pattern, cycle_json, threads_json, evidence_json,
                    first_detected_ns, last_detected_ns, occurrence_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(risk_id) DO UPDATE SET
                    occurrence_count = lock_order_risks.occurrence_count + 1,
                    last_detected_ns = excluded.last_detected_ns;
            """, (
                risk.risk_id, risk.pattern, cycle_json, threads_json, evidence_json,
                risk.first_observed_ns, risk.last_observed_ns
            ))

            cur = self._conn.execute(
                "SELECT occurrence_count FROM lock_order_risks WHERE risk_id = ?;",
                (risk.risk_id,)
            )
            row = cur.fetchone()
            return int(row["occurrence_count"]) if row else 1

    def get_all_risks(self) -> List[Dict]:
        """Retrieves all recorded lock-order risk records."""
        cur = self._conn.execute("""
            SELECT risk_id, pattern, cycle_json, threads_json, evidence_json,
                   first_detected_ns, last_detected_ns, occurrence_count
            FROM lock_order_risks
            ORDER BY occurrence_count DESC, last_detected_ns DESC;
        """)
        results = []
        for r in cur.fetchall():
            d = dict(r)
            d["cycle"] = json.loads(d.pop("cycle_json"))
            d["threads"] = json.loads(d.pop("threads_json"))
            d["evidence"] = json.loads(d.pop("evidence_json"))
            results.append(d)
        return results

    def load_into_tracker(self, tracker: LockOrderTracker) -> int:
        """Loads historical edges from database into a LockOrderTracker."""
        cur = self._conn.execute("""
            SELECT src_resource, dst_resource, thread_id, pid, session_id,
                   first_seen_ns, last_seen_ns, count
            FROM lock_order_edges;
        """)
        loaded = 0
        for r in cur.fetchall():
            ev = LockOrderEvidence(
                src_resource=r["src_resource"],
                dst_resource=r["dst_resource"],
                thread_id=r["thread_id"],
                pid=r["pid"],
                session_id=r["session_id"],
                first_seen_ns=r["first_seen_ns"],
                last_seen_ns=r["last_seen_ns"],
                count=r["count"],
            )
            tracker._log.add_edge(ev.src_resource, ev.dst_resource, evidence=ev)
            tracker._evidence[(ev.src_resource, ev.dst_resource)] = ev
            loaded += 1
        return loaded

    def count_edges(self) -> int:
        """Total distinct lock order edge records."""
        cur = self._conn.execute("SELECT COUNT(*) AS cnt FROM lock_order_edges;")
        row = cur.fetchone()
        return int(row["cnt"]) if row else 0

    def count_risks(self) -> int:
        """Total distinct lock order risk records."""
        cur = self._conn.execute("SELECT COUNT(*) AS cnt FROM lock_order_risks;")
        row = cur.fetchone()
        return int(row["cnt"]) if row else 0

    def close(self) -> None:
        """Closes SQLite database connection."""
        self._conn.close()

