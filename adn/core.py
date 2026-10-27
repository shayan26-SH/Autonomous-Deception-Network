from __future__ import annotations

import ipaddress
import json
import re
import shlex
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MAX_COMMAND_LENGTH = 4096

SYNTHETIC_FILES: dict[str, str] = {
    "/etc/hostname": "decoy-node-01\n",
    "/etc/os-release": 'NAME="Ubuntu"\nVERSION="22.04 LTS (Jammy Jellyfish)"\n',
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "analyst:x:1000:1000:Local User:/home/analyst:/bin/bash\n"
    ),
    "/var/log/auth.log": "Decoy authentication log. No real host data is present.\n",
    "/home/analyst/README.txt": "Synthetic decoy filesystem. No real files are present.\n",
}

DIRECTORIES = {
    "/",
    "/etc",
    "/var",
    "/var/log",
    "/home",
    "/home/analyst",
    "/tmp",
}

ATTACK_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(?:whoami|id)\b", re.I), "T1033"),
    (re.compile(r"\buname\b", re.I), "T1082"),
    (re.compile(r"\b(?:cat|less|more)\s+/etc/passwd\b", re.I), "T1087.001"),
    (re.compile(r"\b(?:curl|wget)\b", re.I), "T1105"),
)

IP_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
SHA256_PATTERN = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")


@dataclass(frozen=True)
class Indicator:
    kind: str
    value: str


@dataclass(frozen=True)
class SimulatedResponse:
    text: str
    techniques: tuple[str, ...]
    indicators: tuple[Indicator, ...]


def extract_indicators(text: str) -> tuple[Indicator, ...]:
    found: set[Indicator] = set()
    for candidate in IP_PATTERN.findall(text):
        try:
            normalized = str(ipaddress.IPv4Address(candidate))
        except ipaddress.AddressValueError:
            continue
        found.add(Indicator("ipv4-addr", normalized))
    for candidate in SHA256_PATTERN.findall(text):
        found.add(Indicator("sha256", candidate.lower()))
    return tuple(sorted(found, key=lambda item: (item.kind, item.value)))


def map_techniques(command: str) -> tuple[str, ...]:
    return tuple(sorted({technique for pattern, technique in ATTACK_RULES if pattern.search(command)}))


class SimulatedShell:
    """A tiny synthetic shell. It never invokes a real command or opens a socket."""

    def __init__(self) -> None:
        self.cwd = "/home/analyst"

    def respond(self, command: str) -> SimulatedResponse:
        if len(command) > MAX_COMMAND_LENGTH:
            return SimulatedResponse(
                f"Input too long (maximum {MAX_COMMAND_LENGTH} characters).",
                (),
                (),
            )
        techniques = map_techniques(command)
        indicators = extract_indicators(command)
        try:
            args = shlex.split(command)
        except ValueError:
            return SimulatedResponse("sh: syntax error: malformed quoting", techniques, indicators)
        if not args:
            return SimulatedResponse("", techniques, indicators)

        executable, *params = args
        handlers = {
            "help": self._help,
            "pwd": self._pwd,
            "whoami": self._whoami,
            "id": self._id,
            "uname": self._uname,
            "hostname": self._hostname,
            "ls": self._ls,
            "cat": self._cat,
            "cd": self._cd,
            "ps": self._ps,
            "ip": self._ip,
            "ifconfig": self._ifconfig,
            "python": self._python,
            "curl": self._transfer,
            "wget": self._transfer,
        }
        handler = handlers.get(executable)
        if handler is None:
            result = f"{executable}: command not found"
        else:
            result = handler(params)
        return SimulatedResponse(result, techniques, indicators)

    @staticmethod
    def _help(_: list[str]) -> str:
        return "Available simulated commands: cat, cd, curl, help, hostname, id, ifconfig, ip, ls, ps, pwd, python, uname, wget, whoami"

    @staticmethod
    def _python(params: list[str]) -> str:
        if params in (["--version"], ["-V"]):
            return "Python 3.11.9 (simulated)"
        if params == ["-m", "unittest", "discover", "-v"]:
            return (
                "python: simulated unittest response\n"
                "SIMULATION ONLY: no Python code or tests were executed. "
                "This decoy has no project test files."
            )
        return (
            "python: simulated interpreter; this decoy does not execute Python code. "
            "Supported examples: python --version, python -m unittest discover -v"
        )

    @staticmethod
    def _transfer(params: list[str]) -> str:
        target = next((param for param in params if param.startswith(("http://", "https://"))), None)
        if target is None:
            return "Usage: curl <URL> (simulated; outbound network access is disabled)"
        return (
            f"curl: simulated request to {target}\n"
            "Connection timed out. No network request was made."
        )

    def _pwd(self, _: list[str]) -> str:
        return self.cwd

    @staticmethod
    def _whoami(_: list[str]) -> str:
        return "analyst"

    @staticmethod
    def _id(_: list[str]) -> str:
        return "uid=1000(analyst) gid=1000(analyst) groups=1000(analyst)"

    @staticmethod
    def _uname(_: list[str]) -> str:
        return "Linux decoy-node-01 5.15.0-generic #1 SMP x86_64 GNU/Linux"

    @staticmethod
    def _hostname(_: list[str]) -> str:
        return "decoy-node-01"

    def _ls(self, params: list[str]) -> str:
        target = self._resolve(params[-1] if params else self.cwd)
        if target not in DIRECTORIES:
            return f"ls: cannot access '{target}': No such file or directory"
        entries = {
            directory.rsplit("/", 1)[-1]
            for directory in DIRECTORIES
            if directory != target and directory.rsplit("/", 1)[0] == target.rstrip("/")
        }
        for filename in SYNTHETIC_FILES:
            if filename.rsplit("/", 1)[0] == target.rstrip("/"):
                entries.add(filename.rsplit("/", 1)[-1])
        return "  ".join(sorted(entries)) if entries else ""

    def _cat(self, params: list[str]) -> str:
        if not params:
            return "cat: missing file operand"
        path = self._resolve(params[-1])
        return SYNTHETIC_FILES.get(path, f"cat: {params[-1]}: No such file or directory").rstrip("\n")

    def _cd(self, params: list[str]) -> str:
        target = self._resolve(params[0] if params else "/home/analyst")
        if target not in DIRECTORIES:
            return f"bash: cd: {target}: No such file or directory"
        self.cwd = target
        return ""

    @staticmethod
    def _ps(_: list[str]) -> str:
        return "  PID TTY          TIME CMD\n    1 ?        00:00:01 init\n  412 pts/0    00:00:00 bash"

    @staticmethod
    def _ip(params: list[str]) -> str:
        if params[:1] == ["addr"]:
            return "1: lo: <LOOPBACK,UP> mtu 65536\n    inet 127.0.0.1/8\n2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n    inet 192.0.2.10/24"
        return "Usage: ip addr"

    @staticmethod
    def _ifconfig(_: list[str]) -> str:
        return "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500\n    inet 192.0.2.10  netmask 255.255.255.0"

    def _resolve(self, path: str) -> str:
        if not path.startswith("/"):
            path = f"{self.cwd}/{path}"
        parts: list[str] = []
        for part in path.split("/"):
            if part in {"", "."}:
                continue
            if part == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(part)
        return "/" + "/".join(parts)


class EventStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = threading.RLock()
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                created_at TEXT NOT NULL,
                source_ip TEXT,
                command TEXT NOT NULL,
                techniques_json TEXT NOT NULL,
                indicators_json TEXT NOT NULL
            )"""
        )
        self.connection.commit()

    def record(
        self,
        command: str,
        source_ip: str | None,
        techniques: tuple[str, ...],
        indicators: tuple[Indicator, ...],
    ) -> None:
        if source_ip is not None:
            source_ip = str(ipaddress.ip_address(source_ip))
            indicators = tuple(set(indicators) | {Indicator("ipv4-addr", source_ip)})
        with self._lock:
            self.connection.execute(
                "INSERT INTO events (created_at, source_ip, command, techniques_json, indicators_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    datetime.now(timezone.utc).isoformat(),
                    source_ip,
                    command,
                    json.dumps(techniques),
                    json.dumps([indicator.__dict__ for indicator in indicators]),
                ),
            )
            self.connection.commit()

    def indicators(self) -> tuple[Indicator, ...]:
        with self._lock:
            rows = self.connection.execute("SELECT indicators_json FROM events").fetchall()
        unique = {
            Indicator(item["kind"], item["value"])
            for (raw,) in rows
            for item in json.loads(raw)
        }
        return tuple(sorted(unique, key=lambda item: (item.kind, item.value)))

    def recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.connection.execute(
                "SELECT id, created_at, source_ip, command, techniques_json, indicators_json "
                "FROM events ORDER BY id DESC LIMIT ?",
                (max(1, min(limit, 200)),),
            ).fetchall()
        return [
            {
                "id": event_id,
                "created_at": created_at,
                "source_ip": source_ip,
                "command": command,
                "techniques": json.loads(techniques_json),
                "indicators": json.loads(indicators_json),
            }
            for event_id, created_at, source_ip, command, techniques_json, indicators_json in rows
        ]

    def close(self) -> None:
        with self._lock:
            self.connection.close()


def _stix_indicator(indicator: Indicator, timestamp: str) -> dict[str, Any]:
    object_id = str(uuid.uuid4())
    if indicator.kind == "ipv4-addr":
        pattern = f"[ipv4-addr:value = '{indicator.value}']"
        name = f"IPv4 address {indicator.value}"
    else:
        pattern = f"[file:hashes.'SHA-256' = '{indicator.value}']"
        name = f"SHA-256 {indicator.value}"
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{object_id}",
        "created": timestamp,
        "modified": timestamp,
        "name": name,
        "pattern": pattern,
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": timestamp,
        "labels": ["malicious-activity"],
    }


def create_stix_bundle(store: EventStore) -> dict[str, Any]:
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [_stix_indicator(indicator, timestamp) for indicator in store.indicators()],
    }


def export_stix(store: EventStore, path: str | Path) -> None:
    bundle = create_stix_bundle(store)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
