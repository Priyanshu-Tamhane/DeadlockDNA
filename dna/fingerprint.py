"""
dna/fingerprint.py — Deadlock DNA Fingerprinting (Feature B)

Computes deterministic SHA-256 fingerprints from canonical cycle representations
as specified in Section 4 of the Feature Expansion Specification.
"""

import hashlib
import json
from typing import List, Tuple, Union, Dict, Any

from .canonicalizer import CanonicalCycle, canonicalize


def compute_fingerprint(canonical_payload: Union[CanonicalCycle, Dict[str, Any]]) -> str:
    """
    Computes a SHA-256 fingerprint from a normalized canonical payload.

    Args:
        canonical_payload: CanonicalCycle object or dictionary representing canonical cycle.

    Returns:
        Hexadecimal SHA-256 hash string (64 characters).
    """
    if hasattr(canonical_payload, "serialize"):
        encoded = canonical_payload.serialize().encode("utf-8")
    elif isinstance(canonical_payload, dict):
        encoded = json.dumps(
            canonical_payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    else:
        raise TypeError(f"Expected CanonicalCycle or dict, got {type(canonical_payload)}")

    return hashlib.sha256(encoded).hexdigest()


def fingerprint_cycle(cycle: List[str]) -> Tuple[str, CanonicalCycle]:
    """
    Convenience helper: canonicalizes a cycle and returns its SHA-256 fingerprint.

    Args:
        cycle: List of cycle node names.

    Returns:
        Tuple of (sha256_fingerprint, canonical_cycle).
    """
    canon = canonicalize(cycle)
    fp = compute_fingerprint(canon)
    return fp, canon
