from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .core import EventStore, SimulatedShell, create_stix_bundle


WEB_ROOT = Path(__file__).with_name("web")
MAX_REQUEST_BYTES = 8192


def create_handler(store: EventStore, shell: SimulatedShell) -> type[BaseHTTPRequestHandler]:
    class DemoHandler(BaseHTTPRequestHandler):
        server_version = "ADN-Demo"

        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            if path == "/":
                self._send_file("index.html", "text/html; charset=utf-8")
            elif path == "/app.js":
                self._send_file("app.js", "text/javascript; charset=utf-8")
            elif path == "/style.css":
                self._send_file("style.css", "text/css; charset=utf-8")
            elif path == "/api/events":
                self._send_json({"events": store.recent_events()})
            elif path == "/api/stix":
                self._send_json(create_stix_bundle(store), filename="adn-threat-feed.json")
            else:
                self.send_error(404)

        def do_POST(self) -> None:
            if urlsplit(self.path).path != "/api/command":
                self.send_error(404)
                return
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send_json({"error": "Invalid Content-Length."}, status=400)
                return
            if content_length <= 0 or content_length > MAX_REQUEST_BYTES:
                self._send_json({"error": "Request body must be between 1 and 8192 bytes."}, status=413)
                return
            try:
                body = json.loads(self.rfile.read(content_length))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send_json({"error": "Request body must be valid JSON."}, status=400)
                return
            if not isinstance(body, dict) or not isinstance(body.get("command"), str):
                self._send_json({"error": "JSON body must contain a string 'command'."}, status=400)
                return

            command = body["command"]
            if not command.strip():
                self._send_json({"error": "Command cannot be empty."}, status=400)
                return
            if len(command) > 4096:
                self._send_json({"error": "Command exceeds the 4096-character limit."}, status=413)
                return
            response = shell.respond(command)
            store.record(command, None, response.techniques, response.indicators)
            self._send_json(
                {
                    "response": response.text,
                    "cwd": shell.cwd,
                    "techniques": response.techniques,
                    "indicators": [indicator.__dict__ for indicator in response.indicators],
                }
            )

        def _send_file(self, filename: str, content_type: str) -> None:
            content = (WEB_ROOT / filename).read_bytes()
            self._send_bytes(content, content_type)

        def _send_json(self, payload: dict[str, Any], status: int = 200, filename: str | None = None) -> None:
            headers = {}
            if filename:
                headers["Content-Disposition"] = f'attachment; filename="{filename}"'
            self._send_bytes(json.dumps(payload).encode("utf-8"), "application/json; charset=utf-8", status, headers)

        def _send_bytes(
            self,
            content: bytes,
            content_type: str,
            status: int = 200,
            extra_headers: dict[str, str] | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'")
            for name, value in (extra_headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(content)

        def log_message(self, format: str, *args: Any) -> None:
            print(f"[web] {self.address_string()} - {format % args}")

    return DemoHandler


def serve_demo(store: EventStore, host: str = "127.0.0.1", port: int = 8765) -> None:
    if host != "127.0.0.1":
        raise ValueError("The demo server must bind to 127.0.0.1.")
    with HTTPServer((host, port), create_handler(store, SimulatedShell())) as server:
        print(f"Demo dashboard running at http://{host}:{server.server_port}")
        print("Local-only demo: interactions are simulated; no submitted commands are executed.")
        print("Press Ctrl+C to stop.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nStopping demo server.")
