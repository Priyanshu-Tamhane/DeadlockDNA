"""
dashboard.py — DeadlockDNA Terminal Dashboard (ui/)

Rich-based live terminal dashboard.

Updated from pipeline via dashboard.update(event, rag, deadlocks).
The detection pipeline drives the dashboard — not the reverse.
"""

import time
from collections import deque
from datetime import datetime
from typing import List, Optional

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from graph.models import DeadlockResult
from graph.rag import ResourceAllocationGraph

_MAX_EVENTS = 5

_OP_STYLE = {
    "LOCK_REQUEST":  "bold red",
    "LOCK_ACQUIRED": "bold green",
    "LOCK_RELEASED": "dim green",
}


class Dashboard:
    """
    Terminal dashboard for DeadlockDNA.

    Usage:
        dash = Dashboard("test_2way", 5000)
        with dash.live_context():
            for event in events:
                rag.process_event(event)
                deadlocks = detector.detect(...)
                dash.update(event, rag, deadlocks)
    """

    def __init__(self, target_name: str, pid: int) -> None:
        self.target_name = target_name
        self.pid = pid
        self._console = Console()
        self._live: Optional[Live] = None
        self._events: deque = deque(maxlen=_MAX_EVENTS)
        self._deadlocks: List[DeadlockResult] = []
        self._t0 = time.time()
        self._n_events = 0

    def live_context(self) -> Live:
        self._live = Live(self._render(), console=self._console,
                          refresh_per_second=4, screen=False)
        return self._live

    def update(self, event, rag: ResourceAllocationGraph,
               deadlocks: List[DeadlockResult]) -> None:
        self._events.append(event)
        self._n_events += 1
        if deadlocks:
            self._deadlocks = deadlocks
        elif not deadlocks and self._deadlocks:
            self._deadlocks = []          # cycle resolved
        if self._live:
            self._live.update(self._render(rag))

    def print_final_summary(self, rag: ResourceAllocationGraph) -> None:
        self._console.print(self._render(rag))

    # ── Rendering ─────────────────────────────────────────────────────────

    def _render(self, rag: Optional[ResourceAllocationGraph] = None) -> Panel:
        parts: list = [
            self._info_panel(),
            self._events_panel(),
        ]
        parts.append(self._rag_panel(rag))
        parts.append(self._status_panel())

        return Panel(
            Group(*parts),
            title="[bold cyan]⬡  D E A D L O C K D N A[/bold cyan]",
            subtitle=f"[dim]uptime {self._uptime()}  |  events {self._n_events}[/dim]",
            border_style="cyan",
            padding=(0, 1),
        )

    def _info_panel(self) -> Panel:
        g = Table.grid(padding=(0, 2))
        g.add_column(style="dim"); g.add_column(style="bold white")
        g.add_row("Target :", self.target_name)
        g.add_row("PID    :", str(self.pid) if self.pid else "—")
        return Panel(g, title="[blue]Target[/blue]", border_style="blue",
                     padding=(0, 1))

    def _events_panel(self) -> Panel:
        t = Table(box=box.SIMPLE, show_header=True,
                  header_style="bold magenta", padding=(0, 1))
        t.add_column("TIME",      style="dim",    width=14)
        t.add_column("TID",       style="cyan",   width=9)
        t.add_column("RESOURCE",  style="yellow", width=26)
        t.add_column("OPERATION",                 width=17)

        for ev in self._events:
            ts  = datetime.fromtimestamp(ev.timestamp_ns / 1e9).strftime("%H:%M:%S.%f")[:12]
            op  = ev.operation.name
            t.add_row(ts, str(ev.tid), ev.resource,
                      Text(op, style=_OP_STYLE.get(op, "white")))

        return Panel(t, title="[magenta]Live Events[/magenta]",
                     border_style="magenta", padding=(0, 0))

    def _rag_panel(self, rag: Optional[ResourceAllocationGraph]) -> Panel:
        edges = rag.get_edges() if rag is not None else []
        if not edges:
            body = Text("  (no edges — graph is empty)", style="dim")
        else:
            lines = []
            for src, dst in edges:
                line = Text()
                if src.startswith("M@"):           # allocation: R → T
                    line.append(src, "yellow"); line.append(" → ", "dim")
                    line.append(dst, "cyan")
                else:                              # request: T → R
                    line.append(src, "cyan");   line.append(" → ", "dim")
                    line.append(dst, "yellow")
                lines.append(line)
            body = Group(*lines)

        return Panel(body, title="[yellow]Resource Allocation Graph[/yellow]",
                     border_style="yellow", padding=(0, 1))

    def _status_panel(self) -> Panel:
        if not self._deadlocks:
            return Panel(
                Text("✅  No deadlock detected", style="bold green"),
                title="[green]Status[/green]",
                border_style="green",
                padding=(0, 1),
            )

        parts = [Text("⚠  DEADLOCK DETECTED", style="bold red on dark_red")]
        for dl in self._deadlocks:
            parts.append(Text("Cycle:", style="bold yellow"))
            cyc = Text()
            for i, node in enumerate(dl.cycle):
                cyc.append(node, "bold cyan" if node.startswith("T") else "bold yellow")
                if i < len(dl.cycle) - 1:
                    cyc.append(" → ", "dim")
            parts.append(cyc)

            if dl.fingerprint:
                parts.append(Text(
                    f"\nDNA Fingerprint : {dl.fingerprint[:16]}... (recurrence: {dl.occurrence_count}x)",
                    style="bold magenta"
                ))
                if dl.canonical_pattern:
                    parts.append(Text(f"Canonical Pattern: {dl.canonical_pattern}", style="dim magenta"))

            if dl.diagnosis:
                diag = dl.diagnosis
                conf_style = "bold green" if diag.confidence == "complete" else "bold yellow" if diag.confidence == "partial" else "bold red"
                parts.append(Text(f"\nDiagnosis: {diag.summary}", style="bold white"))
                parts.append(Text(f"Confidence: {diag.confidence.upper()}", style=conf_style))
                parts.append(Text("Explanation:", style="bold yellow"))
                for s in diag.steps:
                    parts.append(Text(f"  • {s.description}", style="white"))
                if diag.limitations:
                    parts.append(Text("Limitations:", style="dim yellow"))
                    for lim in diag.limitations:
                        parts.append(Text(f"  - {lim}", style="dim"))
            else:
                parts.append(Text(
                    f"Threads  : {', '.join(f'T{t}' for t in dl.threads)}", style="cyan"))
                parts.append(Text(
                    f"Resources: {', '.join(dl.resources)}", style="yellow"))

            parts.append(Text(
                f"\nDetection latency: {dl.latency_us:.1f} µs", style="bold white"))

        return Panel(Group(*parts), title="[red]Status[/red]",
                     border_style="red", padding=(0, 1))

    def _uptime(self) -> str:
        s = int(time.time() - self._t0)
        return f"{s // 60:02d}:{s % 60:02d}"
