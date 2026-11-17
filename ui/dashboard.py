"""
ui/dashboard.py — DeadlockDNA Real-Time Web Dashboard (ui/)

Provides a modern interactive web-based dashboard for DeadlockDNA.
Spins up a lightweight background HTTP/SSE daemon, serving an interactive
physics-based graph canvas, live event streams, DNA fingerprints, and
recovery recommendations directly in the user's browser.
"""

from collections import deque
from contextlib import contextmanager
import logging
import sys
import time
from typing import Any, Generator, List, Optional
import webbrowser

from graph.models import DeadlockResult, Event
from graph.rag import ResourceAllocationGraph
from .web_server import WebDashboardServer

logger = logging.getLogger(__name__)


class Dashboard:
    """
    Interactive Web Dashboard for DeadlockDNA.

    Usage:
        dash = Dashboard("test_2way", 5000, port=8080)
        with dash.live_context():
            for event in events:
                rag.process_event(event)
                deadlocks = detector.detect(...)
                dash.update(event, rag, deadlocks, risks)
    """

    def __init__(self, target_name: str, pid: int, port: int = 8080, open_browser: bool = True) -> None:
        self.target_name = target_name
        self.pid = pid
        self.port = port
        self.open_browser = open_browser

        self._server: Optional[WebDashboardServer] = None
        self._events: deque = deque(maxlen=20)
        self._deadlocks: List[DeadlockResult] = []
        self._risks: List[Any] = []
        self._t0 = time.time()
        self._n_events = 0
        self._deadlock_alert_shown = False

    @contextmanager
    def live_context(self) -> Generator["Dashboard", None, None]:
        """Context manager starting the web dashboard daemon."""
        self._server = WebDashboardServer(host="127.0.0.1", port=self.port)
        actual_port = self._server.start()
        self.port = actual_port
        url = f"http://127.0.0.1:{self.port}"

        print("\n" + "=" * 70, file=sys.stderr)
        print(f"  ⚡ DeadlockDNA Web UI Server Active: {url}", file=sys.stderr)
        print(f"  Target: {self.target_name} (PID: {self.pid or 'Discovering...'})", file=sys.stderr)
        print("  Real-time RAG visualization, DNA fingerprinting & diagnostics live.", file=sys.stderr)
        print("=" * 70 + "\n", file=sys.stderr)

        if self.open_browser:
            self._open_in_browser(url)

        try:
            yield self
        finally:
            if self._server:
                self._server.stop()
                self._server = None
            print("\n[deadlockdna] Web UI server stopped.", file=sys.stderr)

    def _open_in_browser(self, url: str) -> None:
        """Opens URL in the browser, with native support for WSL to host browser."""
        try:
            import platform
            import shutil
            import subprocess
            from pathlib import Path

            is_wsl = "microsoft" in platform.uname().release.lower() or Path("/proc/sys/fs/binfmt_misc/WSLInterop").exists()
            if is_wsl:
                # 1. Try wslview (standard wslu tool)
                if shutil.which("wslview"):
                    subprocess.Popen(["wslview", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return
                # 2. Try launching Windows default browser via PowerShell
                if shutil.which("powershell.exe"):
                    subprocess.Popen(
                        ["powershell.exe", "-NoProfile", "-Command", f"Start-Process '{url}'"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    return

            # Native fallback (Linux/macOS/Windows)
            webbrowser.open(url)
        except Exception as e:
            logger.debug("Automatic browser open skipped: %s", e)

    def update(
        self,
        event: Event,
        rag: ResourceAllocationGraph,
        deadlocks: Optional[List[DeadlockResult]] = None,
        risks: Optional[List[Any]] = None,
    ) -> None:
        """Pushes state updates to the web dashboard and logs to console."""
        self._n_events += 1
        uptime_sec = int(time.time() - self._t0)

        # Record recent event for UI table
        self._events.append({
            "timestamp_ns": event.timestamp_ns,
            "operation": event.operation.name,
            "tid": event.tid,
            "pid": event.pid,
            "resource": event.resource,
        })

        if deadlocks is not None:
            self._deadlocks = deadlocks
        if risks is not None:
            self._risks = risks

        # Extract RAG nodes and edges with rich source symbols (Upgrade 1)
        g = rag.get_graph()
        resolver = getattr(self, "_resolver", None)
        if not resolver:
            from diagnosis.symbol_resolver import SymbolResolver
            self._resolver = SymbolResolver(target_hint=self.target_name)
            resolver = self._resolver

        nodes = []
        for n in g.nodes():
            if n.startswith("T"):
                tid = int(n[1:]) if n[1:].isdigit() else 0
                func_name = resolver.resolve_thread_function(tid, self.pid or event.pid)
                nodes.append({
                    "id": n,
                    "label": f"T{tid} ({func_name})",
                    "kind": "thread",
                    "function": func_name,
                })
            else:
                sym = resolver.resolve_resource(n, self.pid or event.pid)
                nodes.append({
                    "id": n,
                    "label": sym.display_str,
                    "kind": "resource",
                    "symbol": sym.name,
                    "location": sym.location_str,
                })
        edges = []
        for u, v, data in g.edges(data=True):
            edges.append({
                "from": u,
                "to": v,
                "kind": data.get("kind", "allocation"),
                "inferred": data.get("inferred", False),
            })

        # Serialize deadlocks
        serialized_dls = []
        for dl in self._deadlocks:
            dl_dict = {
                "detected": dl.detected,
                "cycle": dl.cycle,
                "threads": dl.threads,
                "resources": dl.resources,
                "latency_us": dl.latency_us,
                "fingerprint": dl.fingerprint,
                "canonical_pattern": dl.canonical_pattern,
                "occurrence_count": dl.occurrence_count,
                "diagnosis": None,
                "recovery_plan": None,
            }
            if dl.diagnosis:
                if hasattr(dl.diagnosis, "to_dict"):
                    dl_dict["diagnosis"] = dl.diagnosis.to_dict()
                else:
                    dl_dict["diagnosis"] = {
                        "summary": str(dl.diagnosis),
                        "confidence": "complete",
                        "steps": [],
                    }
            if dl.recovery_plan:
                if hasattr(dl.recovery_plan, "to_dict"):
                    dl_dict["recovery_plan"] = dl.recovery_plan.to_dict()
                else:
                    dl_dict["recovery_plan"] = str(dl.recovery_plan)

            serialized_dls.append(dl_dict)

        # Serialize risks
        serialized_risks = [r.to_dict() if hasattr(r, "to_dict") else str(r) for r in self._risks]

        # Dispatch snapshot to Web UI
        snapshot = {
            "status": "DEADLOCK DETECTED" if self._deadlocks else "MONITORING",
            "target_name": self.target_name,
            "pid": self.pid or event.pid,
            "nodes": nodes,
            "edges": edges,
            "deadlocks": serialized_dls,
            "risks": serialized_risks,
            "recent_events": list(self._events),
            "total_events": self._n_events,
            "uptime_sec": uptime_sec,
            "last_updated": time.time(),
        }

        if self._server:
            self._server.state_store.update(snapshot)

        # Compact console progress output
        op_name = event.operation.name
        n_threads = len([n for n in nodes if n["id"].startswith("T")])
        n_mutexes = len([n for n in nodes if n["id"].startswith("M@")])

        if self._deadlocks and not self._deadlock_alert_shown:
            self._deadlock_alert_shown = True
            dl = self._deadlocks[0]
            cycle_str = " ➔ ".join(dl.cycle)
            print(f"\n[deadlockdna] 🚨 DEADLOCK DETECTED! Cycle: {cycle_str}", file=sys.stderr)
            if dl.fingerprint:
                print(f"[deadlockdna]    DNA Fingerprint: {dl.fingerprint} (seen {dl.occurrence_count}x)", file=sys.stderr)
            if dl.diagnosis:
                print(f"[deadlockdna]    Diagnosis: {dl.diagnosis.summary}", file=sys.stderr)
            print(f"[deadlockdna]    Interactive view at: http://127.0.0.1:{self.port}\n", file=sys.stderr)
        elif not self._deadlocks and self._deadlock_alert_shown:
            self._deadlock_alert_shown = False
            print("\n[deadlockdna] ✅ Deadlock cycle resolved.\n", file=sys.stderr)
        else:
            sys.stderr.write(
                f"\r[deadlockdna] Event #{self._n_events:<4} | {op_name:<13} T{event.tid} ➔ {event.resource} "
                f"| RAG: {n_threads} threads, {n_mutexes} locks | http://127.0.0.1:{self.port}"
            )
            sys.stderr.flush()
