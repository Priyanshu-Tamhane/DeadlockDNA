"""
tests/test_ui.py — Unit Tests for Web Dashboard (ui/)
"""

import json
import urllib.request
import time
import pytest

from graph.models import Event, Operation, DeadlockResult
from graph.rag import ResourceAllocationGraph
from ui.dashboard import Dashboard
from ui.web_server import WebDashboardState, WebDashboardServer


def test_web_dashboard_state_broadcast():
    store = WebDashboardState(max_history=10)
    sub = store.subscribe()

    snapshot = {"status": "MONITORING", "total_events": 5}
    store.update(snapshot)

    assert len(sub) == 1
    received = json.loads(sub.popleft())
    assert received["status"] == "MONITORING"
    assert received["total_events"] == 5

    history = store.get_history()
    assert len(history) == 1
    assert history[0]["total_events"] == 5

    store.unsubscribe(sub)
    assert sub not in store.subscribers


def test_web_server_initialization_and_static_files():
    server = WebDashboardServer(host="127.0.0.1", port=8990)
    assert server.host == "127.0.0.1"
    assert server.port == 8990
    assert server.state_store is not None

    # Verify static SPA index.html exists and contains core assets
    from ui.web_server import STATIC_DIR
    index_file = STATIC_DIR / "index.html"
    assert index_file.exists()
    content = index_file.read_text(encoding="utf-8")
    assert "DeadlockDNA" in content
    assert "rag-canvas" in content


def test_dashboard_update_and_serialization():
    rag = ResourceAllocationGraph()
    ev1 = Event(timestamp_ns=1000, pid=5000, tid=5001, resource="0x1000", operation=Operation.LOCK_ACQUIRED)
    rag.process_event(ev1)

    dash = Dashboard(target_name="test_target", pid=5000, port=8995, open_browser=False)
    with dash.live_context():
        dash.update(ev1, rag)
        state = dash._server.state_store.get_current()

        assert state["target_name"] == "test_target"
        assert state["pid"] == 5000
        assert len(state["nodes"]) == 2
        assert len(state["edges"]) == 1
        assert state["edges"][0]["from"] == "M@5000:0x1000"
        assert state["edges"][0]["to"] == "T5001"
