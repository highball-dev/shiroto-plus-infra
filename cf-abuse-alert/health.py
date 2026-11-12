from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from state import FAILURE_ALERT_AFTER

logger = logging.getLogger("health")


def _iso(t: float | None) -> str | None:
    if t is None:
        return None
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Health:
    """Liveness/readiness of the loop. Holds no IPs, tokens or config."""

    def __init__(self, stale_after_seconds: float, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self.stale_after = stale_after_seconds
        self.started = clock()
        self.last_beat = self.started
        self.last_tick: float | None = None
        self.last_success: float | None = None
        self.consecutive_failures = 0
        self.last_error = ""

    def beat(self) -> None:
        with self._lock:
            self.last_beat = self._clock()

    def record(self, ok: bool, error: str = "") -> None:
        with self._lock:
            now = self._clock()
            self.last_beat = now
            self.last_tick = now
            if ok:
                self.last_success = now
                self.consecutive_failures = 0
                self.last_error = ""
            else:
                self.consecutive_failures += 1
                self.last_error = error

    def live(self) -> bool:
        with self._lock:
            return self._clock() - self.last_beat <= self.stale_after

    def ready(self) -> bool:
        with self._lock:
            fresh = self._clock() - self.last_beat <= self.stale_after
            return fresh and self.consecutive_failures < FAILURE_ALERT_AFTER

    def snapshot(self) -> dict:
        with self._lock:
            now = self._clock()
            return {
                "uptime_seconds": round(now - self.started),
                "seconds_since_beat": round(now - self.last_beat),
                "stale_after_seconds": round(self.stale_after),
                "last_tick": _iso(self.last_tick),
                "last_success": _iso(self.last_success),
                "consecutive_failures": self.consecutive_failures,
                "last_error": self.last_error[:200],
            }


def _handler(health: Health):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path == "/healthz":
                ok = health.live()
            elif path == "/readyz":
                ok = health.ready()
            else:
                self._send(404, {"status": "not found"})
                return
            body = {"status": "ok" if ok else "unhealthy", **health.snapshot()}
            self._send(200 if ok else 503, body)

        def _send(self, status: int, body: dict) -> None:
            data = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args) -> None:
            return

    return Handler


def serve(health: Health, port: int, host: str = "0.0.0.0") -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), _handler(health))
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name="health", daemon=True).start()
    logger.info("health endpoint on :%d (/healthz, /readyz)", server.server_address[1])
    return server
