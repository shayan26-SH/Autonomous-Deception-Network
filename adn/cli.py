import argparse
import ipaddress
import sys
from pathlib import Path

from .core import EventStore, SimulatedShell, export_stix


def _source_ip(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid IP address: {value}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="adn",
        description="Run the local, non-networked deception simulator.",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path("adn-events.sqlite3"),
        help="SQLite event database (default: ./adn-events.sqlite3)",
    )
    parser.add_argument(
        "--source-ip",
        type=_source_ip,
        help="Optional IP label to associate with this simulated session",
    )
    parser.add_argument(
        "--export-stix",
        type=Path,
        metavar="FILE",
        help="Export collected IP/hash indicators as a STIX 2.1 bundle and exit",
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Run the local browser demo at http://127.0.0.1:8765",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Local demo port (default: 8765; only used with --web)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = EventStore(args.db)
    if args.export_stix:
        export_stix(store, args.export_stix)
        print(f"STIX bundle written to {args.export_stix}")
        store.close()
        return 0
    if args.web:
        if not 0 <= args.port <= 65535:
            parser.error("--port must be between 0 and 65535")
        from .web import serve_demo

        try:
            serve_demo(store, port=args.port)
        finally:
            store.close()
        return 0

    shell = SimulatedShell()
    print("Autonomous Deception Network - local simulator")
    print("No network listener is started; commands are simulated, never executed.")
    print("Type 'help' for simulated commands or 'exit' to quit.")
    try:
        while True:
            try:
                command = input(f"analyst@decoy:{shell.cwd}$ ")
            except EOFError:
                print()
                break
            if command.strip().lower() in {"exit", "quit"}:
                break
            if not command.strip():
                continue
            response = shell.respond(command)
            store.record(command, args.source_ip, response.techniques, response.indicators)
            print(response.text)
    except KeyboardInterrupt:
        print("\nSession ended.")
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
