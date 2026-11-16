"""
rag.py — Resource Allocation Graph Engine (graph/)

Maintains a live directed graph of thread-resource relationships.

Node types:
  Thread node:   "T{tid}"              e.g. T5001
  Resource node: "M@{pid}:{addr}"     e.g. M@5000:0x7ffd1234

Edge types:
  Request edge:    T → R  (thread waiting for resource)
  Allocation edge: R → T  (resource held by thread)

Deadlock ↔ cycle in this directed graph.
"""

import logging
from typing import List, Optional, Tuple

import networkx as nx

from .models import Event, Operation, thread_node, resource_node

logger = logging.getLogger(__name__)


class ResourceAllocationGraph:
    def __init__(self) -> None:
        self._g: nx.DiGraph = nx.DiGraph()
        self._holder: dict[str, str] = {}   # resource_node → thread_node
        self.last_event_ts_ns: int = 0

    # ── Public ────────────────────────────────────────────────────────────

    def process_event(self, event: Event) -> None:
        self.last_event_ts_ns = event.timestamp_ns
        t = thread_node(event.tid)
        r = resource_node(event.pid, event.resource)

        if event.operation == Operation.LOCK_REQUEST:
            self._request(t, r, owner_tid=event.owner_tid, ts_ns=event.timestamp_ns)
        elif event.operation == Operation.LOCK_ACQUIRED:
            self._acquired(t, r, ts_ns=event.timestamp_ns)
        elif event.operation == Operation.LOCK_RELEASED:
            self._released(t, r, ts_ns=event.timestamp_ns)

    def get_edges(self) -> List[Tuple[str, str]]:
        return list(self._g.edges())

    def get_graph(self) -> nx.DiGraph:
        return self._g

    def get_thread_nodes(self) -> List[str]:
        return [n for n in self._g.nodes() if n.startswith("T")]

    def get_resource_nodes(self) -> List[str]:
        return [n for n in self._g.nodes() if n.startswith("M@")]

    def is_empty(self) -> bool:
        return self._g.number_of_edges() == 0

    # ── Event handlers ────────────────────────────────────────────────────

    def _request(self, t: str, r: str, owner_tid: Optional[int] = None,
                 ts_ns: Optional[int] = None) -> None:
        """Thread T is waiting for resource R.  Add edge T → R."""
        if not self._g.has_edge(t, r):
            self._g.add_edge(t, r, kind="request", timestamp_ns=ts_ns, source="futex")
            logger.debug("RAG +request  %s → %s", t, r)

        if owner_tid is not None:
            owner_t = thread_node(owner_tid)
            if not self._holder.get(r):
                self._g.add_edge(r, owner_t, kind="allocation", inferred=True,
                                 timestamp_ns=ts_ns, source="futex_owner_word")
                self._holder[r] = owner_t
                logger.debug("RAG +alloc (inferred from futex owner) %s → %s", r, owner_t)

    def _acquired(self, t: str, r: str, ts_ns: Optional[int] = None) -> None:
        """Thread T acquired resource R.
        Remove request edge T→R (no longer waiting).
        Remove old holder's allocation edge R→old_T.
        Add allocation edge R→T.
        """
        if self._g.has_edge(t, r):
            self._g.remove_edge(t, r)
            logger.debug("RAG -request  %s → %s", t, r)

        old = self._holder.get(r)
        if old and self._g.has_edge(r, old):
            self._g.remove_edge(r, old)
            logger.debug("RAG -alloc    %s → %s (evicted)", r, old)

        self._g.add_edge(r, t, kind="allocation", inferred=False,
                         timestamp_ns=ts_ns, source="pthread_mutex_lock")
        self._holder[r] = t
        logger.debug("RAG +alloc    %s → %s", r, t)
        self._prune()

    def _released(self, t: str, r: str, ts_ns: Optional[int] = None) -> None:
        """Thread T released resource R.  Remove allocation edge R→T."""
        if self._g.has_edge(r, t):
            self._g.remove_edge(r, t)
            logger.debug("RAG -alloc    %s → %s (released)", r, t)
        if self._holder.get(r) == t:
            del self._holder[r]
        self._prune()

    def _prune(self) -> None:
        isolated = [n for n in list(self._g.nodes()) if self._g.degree(n) == 0]
        self._g.remove_nodes_from(isolated)
