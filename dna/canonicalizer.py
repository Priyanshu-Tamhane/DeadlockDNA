"""
dna/canonicalizer.py — Deadlock DNA Canonicalization (Feature B)

Transforms runtime cycle topologies with arbitrary PIDs, TIDs, and memory addresses
into deterministic, role-based canonical representations adhering to Section 4 of
the Feature Expansion Specification.
"""

from dataclasses import dataclass, field
import json
from typing import List, Dict, Any, Tuple


@dataclass(frozen=True)
class CanonicalCycle:
    """
    Normalized, role-based representation of a deadlock cycle.
    Independent of runtime PIDs, TIDs, and virtual memory addresses.
    """
    pattern: str                            # e.g. "THREAD_0 -> RESOURCE_0 -> THREAD_1 -> RESOURCE_1 -> THREAD_0"
    nodes: Tuple[str, ...]                  # ("THREAD_0", "RESOURCE_0", "THREAD_1", "RESOURCE_1")
    edges: Tuple[Tuple[str, str, str], ...] # (("THREAD_0", "REQUEST", "RESOURCE_0"), ...)
    thread_count: int
    resource_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern": self.pattern,
            "nodes": list(self.nodes),
            "edges": [
                {"src": src, "type": edge_type, "dst": dst}
                for src, edge_type, dst in self.edges
            ],
            "thread_count": self.thread_count,
            "resource_count": self.resource_count,
        }

    def serialize(self) -> str:
        """Deterministic UTF-8 JSON serialization for hashing."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


def _best_effort_canonicalize(nodes: List[str]) -> CanonicalCycle:
    """
    Best-effort canonicalization for degenerate (non-bipartite) cycles.

    Sorts thread nodes and resource nodes independently, assigns labels in sorted
    order, and builds a CanonicalCycle. Used for partially-built RAG cycles that
    fail strict bipartite validation.
    """
    thread_nodes = sorted(n for n in nodes if n.startswith("T"))
    resource_nodes = sorted(n for n in nodes if not n.startswith("T"))

    thread_map = {t: f"THREAD_{i}" for i, t in enumerate(thread_nodes)}
    res_map = {r: f"RESOURCE_{i}" for i, r in enumerate(resource_nodes)}

    canonical_nodes = [
        thread_map[n] if n.startswith("T") else res_map[n]
        for n in nodes
    ]

    num_nodes = len(canonical_nodes)
    canonical_edges: List[Tuple[str, str, str]] = []
    for i in range(num_nodes):
        src = canonical_nodes[i]
        dst = canonical_nodes[(i + 1) % num_nodes]
        edge_type = "REQUEST" if src.startswith("THREAD") else "ALLOCATION"
        canonical_edges.append((src, edge_type, dst))

    pattern_str = " -> ".join(canonical_nodes + [canonical_nodes[0]]) if canonical_nodes else ""

    return CanonicalCycle(
        pattern=pattern_str,
        nodes=tuple(canonical_nodes),
        edges=tuple(canonical_edges),
        thread_count=len(thread_nodes),
        resource_count=len(resource_nodes),
    )


def canonicalize(cycle: List[str], best_effort: bool = False) -> CanonicalCycle:
    """
    Canonicalizes a directed cycle from the Resource Allocation Graph.

    Args:
        cycle: List of cycle node names (e.g. ['M@5000:0x1000', 'T5001', 'M@5000:0x2000', 'T5002', 'M@5000:0x1000']).
        best_effort: When True, non-bipartite or degenerate cycles that would normally raise
            ValueError are handled with a best-effort canonicalization: thread and resource nodes
            are sorted independently, labeled in sorted order, and a CanonicalCycle is returned.
            This handles degenerate cycles from partially-built RAGs.

    Returns:
        CanonicalCycle: Deterministic, normalized cycle representation.

    Raises:
        ValueError: If cycle is malformed or not a closed bipartite cycle (and best_effort=False).
    """
    if not cycle or len(cycle) < 4:
        raise ValueError(f"Cycle must have at least 4 nodes (2 threads, 2 resources), got: {cycle}")

    # Strip closing loop node if present
    nodes = cycle[:-1] if cycle[0] == cycle[-1] else list(cycle)
    num_nodes = len(nodes)

    if num_nodes % 2 != 0:
        if best_effort:
            return _best_effort_canonicalize(nodes)
        raise ValueError(f"Bipartite deadlock cycle must have an even number of nodes, got {num_nodes}: {nodes}")

    # Validate alternating bipartite structure
    for i in range(num_nodes):
        curr_is_thread = nodes[i].startswith("T")
        next_is_thread = nodes[(i + 1) % num_nodes].startswith("T")
        if curr_is_thread == next_is_thread:
            if best_effort:
                return _best_effort_canonicalize(nodes)
            raise ValueError(
                f"Cycle must strictly alternate between threads (T) and resources (M@). "
                f"Violation at index {i}: '{nodes[i]}' -> '{nodes[(i + 1) % num_nodes]}'"
            )

    thread_indices = [i for i, n in enumerate(nodes) if n.startswith("T")]
    num_threads = len(thread_indices)
    num_resources = num_nodes - num_threads

    if num_threads < 2 or num_resources < 2:
        if best_effort:
            return _best_effort_canonicalize(nodes)
        raise ValueError(f"Cycle must contain at least 2 threads and 2 resources, got: {nodes}")

    candidates: List[Tuple[str, CanonicalCycle]] = []

    # Evaluate each valid rotation starting at a THREAD
    for start_idx in thread_indices:
        rotated = nodes[start_idx:] + nodes[:start_idx]

        # Assign role-based labels in order of appearance
        thread_map: Dict[str, str] = {}
        res_map: Dict[str, str] = {}
        t_counter = 0
        r_counter = 0

        canonical_nodes: List[str] = []
        for n in rotated:
            if n.startswith("T"):
                if n not in thread_map:
                    thread_map[n] = f"THREAD_{t_counter}"
                    t_counter += 1
                canonical_nodes.append(thread_map[n])
            else:
                if n not in res_map:
                    res_map[n] = f"RESOURCE_{r_counter}"
                    r_counter += 1
                canonical_nodes.append(res_map[n])

        # Form semantic edges:
        # THREAD -> RESOURCE is REQUEST
        # RESOURCE -> THREAD is ALLOCATION
        canonical_edges: List[Tuple[str, str, str]] = []
        for i in range(num_nodes):
            src = canonical_nodes[i]
            dst = canonical_nodes[(i + 1) % num_nodes]
            if src.startswith("THREAD"):
                edge_type = "REQUEST"
            else:
                edge_type = "ALLOCATION"
            canonical_edges.append((src, edge_type, dst))

        pattern_str = " -> ".join(canonical_nodes + [canonical_nodes[0]])

        candidate = CanonicalCycle(
            pattern=pattern_str,
            nodes=tuple(canonical_nodes),
            edges=tuple(canonical_edges),
            thread_count=num_threads,
            resource_count=num_resources,
        )

        serialized = candidate.serialize()
        candidates.append((serialized, candidate))

    # Select the lexicographically smallest canonical serialization
    candidates.sort(key=lambda c: c[0])
    return candidates[0][1]
