"""
dna/store.py — SQLite Persistence & History Store (Feature B)

Stores deadlocks, canonical patterns, occurrence counts, and runtime detection records
adhering to Section 4 of the Feature Expansion Specification.
"""

import json
from pathlib import Path
import sqlite3
import sys
from typing import List, Optional, Dict, Any, Tuple


class DeadlockStore:
    """
    SQLite-backed store for deadlock fingerprints and detection history.
    """

    def __init__(self, db_path: str = "logs/deadlocks.db") -> None:
        self.db_path = db_path
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        if db_path != ":memory:" and sys.platform == "win32" and not db_path.startswith("file:"):
            p_str = Path(db_path).as_posix()
            self._conn = sqlite3.connect(f"file:{p_str}?nolock=1", uri=True, timeout=30.0, check_same_thread=False)
        else:
            self._conn = sqlite3.connect(db_path, timeout=30.0, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        with self._conn:
            self._conn.execute("PRAGMA foreign_keys = ON;")
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS fingerprints (
                    fingerprint TEXT PRIMARY KEY,
                    canonical_pattern TEXT NOT NULL,
                    first_seen_ns INTEGER NOT NULL,
                    last_seen_ns INTEGER NOT NULL,
                    occurrence_count INTEGER NOT NULL DEFAULT 1
                );
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT NOT NULL,
                    detected_at_ns INTEGER NOT NULL,
                    pid INTEGER,
                    tids_json TEXT NOT NULL,
                    resources_json TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    FOREIGN KEY (fingerprint) REFERENCES fingerprints(fingerprint)
                );
            """)

    def record(self, fingerprint: str, canonical_pattern: str, detected_at_ns: int,
               pid: Optional[int], tids: List[int], resources: List[str],
               confidence: str = "complete") -> int:
        """
        Record a deadlock detection in a single atomic transaction.

        If the fingerprint is new, creates a record with occurrence_count=1.
        If it already exists, increments occurrence_count and updates last_seen_ns.
        Appends an individual detection event to the detections table.

        Returns:
            int: The current occurrence_count for this fingerprint.
        """
        tids_json = json.dumps(tids, sort_keys=True)
        resources_json = json.dumps(resources, sort_keys=True)

        with self._conn:
            # 1. Upsert into fingerprints table
            self._conn.execute("""
                INSERT INTO fingerprints (
                    fingerprint, canonical_pattern, first_seen_ns, last_seen_ns, occurrence_count
                ) VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    occurrence_count = occurrence_count + 1,
                    last_seen_ns = excluded.last_seen_ns;
            """, (fingerprint, canonical_pattern, detected_at_ns, detected_at_ns))

            # 2. Insert into detections table
            self._conn.execute("""
                INSERT INTO detections (
                    fingerprint, detected_at_ns, pid, tids_json, resources_json, confidence
                ) VALUES (?, ?, ?, ?, ?, ?);
            """, (fingerprint, detected_at_ns, pid, tids_json, resources_json, confidence))

            # 3. Retrieve current occurrence count
            cur = self._conn.execute(
                "SELECT occurrence_count FROM fingerprints WHERE fingerprint = ?;",
                (fingerprint,)
            )
            row = cur.fetchone()
            return int(row["occurrence_count"]) if row else 1

    def get_fingerprint(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        """Retrieve fingerprint summary record."""
        cur = self._conn.execute(
            "SELECT fingerprint, canonical_pattern, first_seen_ns, last_seen_ns, occurrence_count "
            "FROM fingerprints WHERE fingerprint = ?;",
            (fingerprint,)
        )
        row = cur.fetchone()
        if not row:
            return None
        return dict(row)

    def get_detections(self, fingerprint: Optional[str] = None,
                       limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve detection records, optionally filtered by fingerprint."""
        if fingerprint:
            cur = self._conn.execute(
                "SELECT id, fingerprint, detected_at_ns, pid, tids_json, resources_json, confidence "
                "FROM detections WHERE fingerprint = ? ORDER BY id DESC LIMIT ?;",
                (fingerprint, limit)
            )
        else:
            cur = self._conn.execute(
                "SELECT id, fingerprint, detected_at_ns, pid, tids_json, resources_json, confidence "
                "FROM detections ORDER BY id DESC LIMIT ?;",
                (limit,)
            )

        results = []
        for r in cur.fetchall():
            d = dict(r)
            d["tids"] = json.loads(d.pop("tids_json"))
            d["resources"] = json.loads(d.pop("resources_json"))
            results.append(d)
        return results

    def get_all_fingerprints(self) -> List[Dict[str, Any]]:
        """Retrieve all recorded fingerprints ordered by recurrence."""
        cur = self._conn.execute(
            "SELECT fingerprint, canonical_pattern, first_seen_ns, last_seen_ns, occurrence_count "
            "FROM fingerprints ORDER BY occurrence_count DESC, last_seen_ns DESC;"
        )
        return [dict(r) for r in cur.fetchall()]

    def count_fingerprints(self) -> int:
        """Total distinct fingerprints stored."""
        cur = self._conn.execute("SELECT COUNT(*) AS cnt FROM fingerprints;")
        row = cur.fetchone()
        return int(row["cnt"]) if row else 0

    def count_detections(self) -> int:
        """Total individual detections logged."""
        cur = self._conn.execute("SELECT COUNT(*) AS cnt FROM detections;")
        row = cur.fetchone()
        return int(row["cnt"]) if row else 0

    def close(self) -> None:
        """Close SQLite database connection."""
        self._conn.close()
