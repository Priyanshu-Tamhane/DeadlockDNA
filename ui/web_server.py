"""
ui/web_server.py — High-Performance Real-Time Web Server for DeadlockDNA

Provides a zero-external-dependency HTTP and Server-Sent Events (SSE) server
that streams live RAG graphs, cycle detections, DNA fingerprints, and recovery
plans directly to the browser frontend.
"""

from collections import deque
import json
import logging
from pathlib import Path
import threading
import time
from typing import Any, Dict, List, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handles each incoming HTTP request in a separate thread."""
    daemon_threads = True
    allow_reuse_address = True


class WebDashboardState:
    """Thread-safe state store for DeadlockDNA web clients."""

    def __init__(self, max_history: int = 500) -> None:
        self._lock = threading.Lock()
        self.target_name: str = "DeadlockDNA Target"
        self.pid: int = 0
        self.uptime_sec: int = 0
        self.total_events: int = 0
        self.current_state: Dict[str, Any] = {
            "status": "MONITORING",
            "target_name": self.target_name,
            "pid": self.pid,
            "nodes": [],
            "edges": [],
            "deadlocks": [],
            "risks": [],
            "recent_events": [],
            "total_events": 0,
            "uptime_sec": 0,
            "last_updated": time.time(),
        }
        self.history: deque = deque(maxlen=max_history)
        self.subscribers: List[deque] = []

    def update(self, snapshot: Dict[str, Any]) -> None:
        with self._lock:
            self.current_state = snapshot
            self.history.append(snapshot)
            # Push to all active SSE subscribers
            payload = json.dumps(snapshot)
            dead_subs = []
            for q in self.subscribers:
                try:
                    q.append(payload)
                except Exception:
                    dead_subs.append(q)
            for d in dead_subs:
                if d in self.subscribers:
                    self.subscribers.remove(d)

    def get_current(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self.current_state)

    def get_history(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.history)

    def subscribe(self) -> deque:
        with self._lock:
            q: deque = deque(maxlen=50)
            self.subscribers.append(q)
            return q

    def unsubscribe(self, q: deque) -> None:
        with self._lock:
            if q in self.subscribers:
                self.subscribers.remove(q)


class WebDashboardRequestHandler(BaseHTTPRequestHandler):
    """Serves the DeadlockDNA interactive SPA and live SSE streams."""

    state_store: Optional[WebDashboardState] = None

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress routine HTTP 200 access logs from polluting terminal
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("%s - " + format, self.address_string(), *args)

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            self._serve_index()
        elif self.path == "/api/state":
            self._serve_json(self.state_store.get_current() if self.state_store else {})
        elif self.path == "/api/history":
            self._serve_json(self.state_store.get_history() if self.state_store else [])
        elif self.path == "/api/stream":
            self._serve_sse()
        else:
            self.send_error(404, "Not Found")

    def _serve_index(self) -> None:
        index_file = STATIC_DIR / "index.html"
        if not index_file.exists():
            self.send_error(500, "Dashboard index.html not found.")
            return

        content = index_file.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(content)

    def _serve_json(self, data: Any) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _serve_sse(self) -> None:
        if not self.state_store:
            self.send_error(503, "State store unavailable")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        sub_queue = self.state_store.subscribe()

        # Send initial snapshot immediately upon connect
        try:
            initial = json.dumps(self.state_store.get_current())
            self.wfile.write(f"data: {initial}\n\n".encode("utf-8"))
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            self.state_store.unsubscribe(sub_queue)
            return

        try:
            while True:
                if sub_queue:
                    payload = sub_queue.popleft()
                    msg = f"data: {payload}\n\n".encode("utf-8")
                    self.wfile.write(msg)
                    self.wfile.flush()
                else:
                    # Keep-alive heartbeat every 2 seconds
                    time.sleep(0.05)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            self.state_store.unsubscribe(sub_queue)


class WebDashboardServer:
    """Manages the background HTTP/SSE daemon."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080) -> None:
        self.host = host
        self.port = port
        self.state_store = WebDashboardState()
        self._server: Optional[ThreadedHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> int:
        """Starts the web server in a background thread. Finds next free port if occupied."""
        for p in range(self.port, self.port + 20):
            try:
                WebDashboardRequestHandler.state_store = self.state_store
                self._server = ThreadedHTTPServer((self.host, p), WebDashboardRequestHandler)
                self.port = p
                break
            except OSError:
                continue

        if not self._server:
            raise RuntimeError(f"Could not bind Web Dashboard server to {self.host}:{self.port}")

        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True, name="DeadlockDNA-WebServer")
        self._thread.start()
        logger.info("Web dashboard server listening at http://%s:%d", self.host, self.port)
        return self.port

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
