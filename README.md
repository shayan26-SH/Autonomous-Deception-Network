# Autonomous Deception Network

An adaptive honeypot and threat-intelligence platform designed to attract, observe, and safely analyze unauthorized interactions with decoy services.

> **Project status:** Safe local prototype. This implementation is a command simulator and event/indicator exporter. It is not a network honeypot and is not production-ready.

## Overview

Autonomous Deception Network creates realistic but isolated network decoys—such as SSH, HTTP, and FTP services—and observes how visitors interact with them. Configurable response engines can use deterministic state machines or an LLM-backed simulator to return context-aware responses without exposing real systems or data.

Collected activity can be normalized into security events, enriched with indicators of compromise (IOCs), mapped to the MITRE ATT&CK framework, and exported in formats suitable for threat-intelligence and SIEM workflows.

## Goals

- Make decoy interactions convincing enough to collect useful behavioral signals.
- Contain every decoy and its generated content within a controlled environment.
- Turn observed activity into explainable, reviewable threat intelligence.
- Support integration with existing security monitoring and analysis tools.

## Implemented prototype

### Local command simulator

- Provides a small synthetic Linux-like command set, including `python --version`, a simulated response to `python -m unittest discover -v`, and simulated `curl`/`wget` responses.
- Does not execute Python code or run tests in the decoy. Run the actual project tests from your system terminal using `python -m unittest discover -v`.
- Uses a fixed synthetic filesystem and deterministic responses.
- Never invokes a host command, starts a network listener, or executes submitted input.
- Logs each non-empty interaction to a local SQLite database.

### Event enrichment and threat feed

- Applies a small, transparent set of command-pattern mappings to MITRE ATT&CK technique IDs.
- Extracts valid IPv4 addresses and SHA-256-shaped strings from interaction text.
- Accepts an optional source IP label for a simulated session.
- Exports deduplicated indicators as a STIX 2.1 bundle. This prototype does not publish to TAXII or connect to a SIEM.

## Run locally

Requires Python 3.10 or newer. The project uses only the Python standard library.

### Browser demo

Start the local dashboard from a terminal in the project directory:

```powershell
python -m adn --web
```

Open `http://127.0.0.1:8765` in your browser. The demo has a simulated shell, activity dashboard, ATT&CK tags, and a STIX feed download. The server binds only to localhost and uses the selected local SQLite database. Use `Ctrl+C` in the terminal to stop it. To select a different database or port:

```powershell
python -m adn --web --db .\data\events.sqlite3 --port 8765
```

This dashboard has no external font or CDN dependencies and does not expose a remotely accessible honeypot.

### Terminal simulator

```powershell
python -m adn
```

By default, events are stored in `adn-events.sqlite3` in the current directory. To attach a source IP label to a simulated session:

```powershell
python -m adn --db .\data\events.sqlite3 --source-ip 198.51.100.10
```

Enter simulated commands at the prompt; use `help` to see the supported command list and `exit` to stop. Export indicators collected in the selected database:

```powershell
python -m adn --db .\data\events.sqlite3 --export-stix .\data\feed.json
```

The IP ranges in examples and synthetic responses are reserved for documentation. Treat captured interaction data as untrusted and sensitive; set appropriate file permissions and retention policies for the database and exported feeds.

## Run tests

```powershell
python -m unittest discover -v
```

## High-level architecture

```text
External traffic
      |
      v
Decoy services (SSH / HTTP / FTP)
      |
      +--> Interaction simulator (state machine or optional LLM)
      |
      v
Event collection and normalization
      |
      +--> MITRE ATT&CK enrichment
      +--> IOC extraction and validation
      |
      v
Storage, analyst review, and STIX/TAXII or SIEM export
```

The architecture below describes a possible future direction, not implemented services. This prototype uses Python and SQLite only; it does not include SSH, HTTP, or FTP listeners, an LLM, Docker/Kubernetes manifests, a MITRE API client, TAXII, or SIEM integration.

## Technology direction

| Area | Candidate technologies |
|---|---|
| Decoy deployment | Docker, Kubernetes |
| Orchestration and analysis | Python |
| Network services | Go |
| Adaptive responses | Deterministic state machines; optional Llama/Mistral-based model or LangChain integration |
| Threat mapping | MITRE ATT&CK data/API |
| Threat-intelligence exchange | STIX and TAXII |

Specific versions, providers, and integrations remain to be selected.

## Security and responsible operation

Honeypots are intentionally exposed services and must be treated as high-risk infrastructure.

- Run decoys in isolated, least-privilege containers or networks; do not connect them to production systems.
- Do not place real credentials, customer data, or sensitive files in synthetic environments.
- Restrict outbound traffic and administrative access; monitor the decoys and their hosts.
- Ensure an attacker cannot use a decoy as a pivot, relay, or launch point for activity against third parties.
- Treat collected payloads and indicators as untrusted data. Do not execute submitted files or commands on analyst systems.
- Apply access controls, retention limits, and privacy review to collected network and interaction data.
- Deploy only on infrastructure you own or are explicitly authorized to operate, and comply with applicable laws and organizational policies.
- If an LLM is used, constrain its tools and network access. It should generate decoy responses only, not execute commands or control infrastructure.

## Possible next steps

1. Define an isolated deployment and data-retention model before introducing any network-facing decoys.
2. Expand event evidence and analyst review for technique mappings.
3. Add validation against a STIX 2.1 schema and document export limitations.
4. Evaluate any future network service or model integration only within an explicitly isolated, authorized environment.

## Repository status

The local simulator, SQLite event store, basic ATT&CK pattern mapping, IOC extraction, and STIX JSON export are implemented. Network services and deployment automation remain out of scope.

## License

No license has been specified yet. Until one is added, all rights remain with the copyright holder; do not assume the project may be redistributed or reused.
