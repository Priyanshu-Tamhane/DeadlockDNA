"""
tests/test_dna.py — Unit tests for Deadlock DNA Fingerprinting & History Store (Feature B)
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1]))

import pytest
from dna.canonicalizer import canonicalize, CanonicalCycle
from dna.fingerprint import compute_fingerprint, fingerprint_cycle
from dna.store import DeadlockStore


class TestCanonicalization:

    def test_two_thread_canonical_pattern(self):
        """2-thread deadlock produces standard role-based pattern."""
        cycle = ["M@5000:0x1000", "T5001", "M@5000:0x2000", "T5002", "M@5000:0x1000"]
        canon = canonicalize(cycle)
        assert canon.pattern == "THREAD_0 -> RESOURCE_0 -> THREAD_1 -> RESOURCE_1 -> THREAD_0"
        assert canon.thread_count == 2
        assert canon.resource_count == 2
        assert len(canon.nodes) == 4
        assert len(canon.edges) == 4

    def test_different_tids_produce_same_canonical_pattern(self):
        """Cycles with different TIDs, PIDs, and addresses produce identical canonical forms."""
        run1 = ["M@5000:0x1111", "T1001", "M@5000:0x2222", "T1002", "M@5000:0x1111"]
        run2 = ["M@9000:0xaaaa", "T8001", "M@9000:0xbbbb", "T8002", "M@9000:0xaaaa"]

        c1 = canonicalize(run1)
        c2 = canonicalize(run2)

        assert c1.pattern == c2.pattern
        assert c1.nodes == c2.nodes
        assert c1.edges == c2.edges
        assert c1.serialize() == c2.serialize()

    def test_different_rotations_produce_same_canonical_pattern(self):
        """Rotating starting position produces identical canonical representation."""
        rot1 = ["T1", "M2", "T2", "M1", "T1"]
        rot2 = ["T2", "M1", "T1", "M2", "T2"]
        rot3 = ["M1", "T1", "M2", "T2", "M1"]
        rot4 = ["M2", "T2", "M1", "T1", "M2"]

        c1 = canonicalize(rot1)
        c2 = canonicalize(rot2)
        c3 = canonicalize(rot3)
        c4 = canonicalize(rot4)

        assert c1.pattern == c2.pattern == c3.pattern == c4.pattern
        assert c1.serialize() == c2.serialize() == c3.serialize() == c4.serialize()

    def test_three_thread_cycle(self):
        """3-thread cycle produces distinct 3-node canonical pattern."""
        cycle = [
            "M@5000:0x1000", "T1",
            "M@5000:0x2000", "T2",
            "M@5000:0x3000", "T3",
            "M@5000:0x1000"
        ]
        canon = canonicalize(cycle)
        expected = "THREAD_0 -> RESOURCE_0 -> THREAD_1 -> RESOURCE_1 -> THREAD_2 -> RESOURCE_2 -> THREAD_0"
        assert canon.pattern == expected
        assert canon.thread_count == 3
        assert canon.resource_count == 3

    def test_different_structures_produce_different_patterns(self):
        """2-way and 3-way cycles have different patterns."""
        c2 = canonicalize(["M1", "T1", "M2", "T2", "M1"])
        c3 = canonicalize(["M1", "T1", "M2", "T2", "M3", "T3", "M1"])
        assert c2.pattern != c3.pattern

    def test_invalid_cycle_raises_value_error(self):
        """Malformed or non-alternating cycles raise ValueError."""
        with pytest.raises(ValueError, match="at least 4 nodes"):
            canonicalize(["T1", "M1"])

        with pytest.raises(ValueError, match="strictly alternate"):
            canonicalize(["T1", "T2", "M1", "M2", "T1"])

        with pytest.raises(ValueError, match="even number of nodes"):
            canonicalize(["T1", "M1", "T2", "T1"])


class TestFingerprinting:

    def test_fingerprint_sha256_format(self):
        """Fingerprint is a valid 64-character hex string."""
        cycle = ["M@5000:0x1000", "T1", "M@5000:0x2000", "T2", "M@5000:0x1000"]
        fp, canon = fingerprint_cycle(cycle)
        assert len(fp) == 64
        assert int(fp, 16) >= 0

    def test_equivalent_cycles_share_fingerprint(self):
        """Different runs of equivalent deadlocks yield exact same fingerprint."""
        run1 = ["M@100:0x1000", "T1", "M@100:0x2000", "T2", "M@100:0x1000"]
        run2 = ["M@200:0xbeef", "T9", "M@200:0xdead", "T8", "M@200:0xbeef"]

        fp1, _ = fingerprint_cycle(run1)
        fp2, _ = fingerprint_cycle(run2)

        assert fp1 == fp2

    def test_different_cycles_produce_different_fingerprints(self):
        """2-way and 3-way deadlocks produce distinct fingerprints."""
        c2 = ["M1", "T1", "M2", "T2", "M1"]
        c3 = ["M1", "T1", "M2", "T2", "M3", "T3", "M1"]

        fp2, _ = fingerprint_cycle(c2)
        fp3, _ = fingerprint_cycle(c3)

        assert fp2 != fp3


class TestDeadlockStore:

    def test_store_lifecycle_and_recurrence_counter(self):
        """Verify insert, occurrence increment, and retrieval in SQLite."""
        store = DeadlockStore(":memory:")

        cycle1 = ["M@1:0x10", "T1", "M@1:0x20", "T2", "M@1:0x10"]
        fp1, canon1 = fingerprint_cycle(cycle1)

        # 1st detection
        count1 = store.record(
            fingerprint=fp1,
            canonical_pattern=canon1.pattern,
            detected_at_ns=1_000_000,
            pid=1,
            tids=[1, 2],
            resources=["M@1:0x10", "M@1:0x20"],
            confidence="complete",
        )
        assert count1 == 1
        assert store.count_fingerprints() == 1
        assert store.count_detections() == 1

        # 2nd detection of same pattern (different runtime TIDs)
        cycle2 = ["M@2:0xaa", "T10", "M@2:0xbb", "T20", "M@2:0xaa"]
        fp2, canon2 = fingerprint_cycle(cycle2)
        assert fp1 == fp2

        count2 = store.record(
            fingerprint=fp2,
            canonical_pattern=canon2.pattern,
            detected_at_ns=2_000_000,
            pid=2,
            tids=[10, 20],
            resources=["M@2:0xaa", "M@2:0xbb"],
            confidence="complete",
        )
        assert count2 == 2
        # Still only 1 distinct fingerprint
        assert store.count_fingerprints() == 1
        assert store.count_detections() == 2

        # Verify summary row
        fp_row = store.get_fingerprint(fp1)
        assert fp_row is not None
        assert fp_row["occurrence_count"] == 2
        assert fp_row["canonical_pattern"] == canon1.pattern
        assert fp_row["first_seen_ns"] == 1_000_000
        assert fp_row["last_seen_ns"] == 2_000_000

        # Verify detection logs
        dets = store.get_detections(fp1)
        assert len(dets) == 2
        assert dets[0]["pid"] == 2
        assert dets[0]["tids"] == [10, 20]
        assert dets[1]["pid"] == 1
        assert dets[1]["tids"] == [1, 2]

        store.close()

    def test_store_multiple_fingerprints(self):
        """Storing distinct deadlock types tracks counts independently."""
        store = DeadlockStore(":memory:")

        fp2, canon2 = fingerprint_cycle(["M1", "T1", "M2", "T2", "M1"])
        fp3, canon3 = fingerprint_cycle(["M1", "T1", "M2", "T2", "M3", "T3", "M1"])

        store.record(fp2, canon2.pattern, 100, 1, [1, 2], ["M1", "M2"])
        store.record(fp2, canon2.pattern, 200, 1, [1, 2], ["M1", "M2"])
        store.record(fp3, canon3.pattern, 300, 1, [1, 2, 3], ["M1", "M2", "M3"])

        assert store.count_fingerprints() == 2
        assert store.count_detections() == 3

        all_fps = store.get_all_fingerprints()
        assert len(all_fps) == 2
        assert all_fps[0]["fingerprint"] == fp2
        assert all_fps[0]["occurrence_count"] == 2
        assert all_fps[1]["fingerprint"] == fp3
        assert all_fps[1]["occurrence_count"] == 1

        store.close()
