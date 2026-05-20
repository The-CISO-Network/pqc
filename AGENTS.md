# AGENTS.md — PQ

This file is a machine-readable project guide for AI coding agents. It describes the actual state of the codebase, build system, conventions, and known issues. All information below is derived from the files in this repository.

---

## Project Overview

**PQ** is a Post-Quantum Cryptography (PQC) readiness scanner and connection monitor. It probes TLS, SSH, and IKEv2/VPN endpoints to detect whether they advertise post-quantum cryptographic algorithms (ML-KEM / Kyber, ML-DSA / Dilithium, FALCON, SPHINCS+, etc.) and classifies the result with a binary verdict:

- 🔴 **NO PQC** — No post-quantum algorithms detected.
- 🟢 **PQC OK** — At least one post-quantum algorithm was detected.

The project provides:
1. A **scanner** (`scan` command) for one-off endpoint probes.
2. A **monitoring agent** (`agent` command) that polls the host's active TCP connection table and proactively scans observed endpoints.
3. A **Python API** (`pqc.scanner.scan`, `pqc.agent.Agent`).

---

## Technology Stack

- **Language**: Python
- **Minimum Python version**: 3.8 (declared in `pyproject.toml`)
- **Build backend**: `setuptools` (configured in `pyproject.toml`)
- **Package name**: `pqc` (distribution), `pqc` (import)
- **CLI entry points**: `pqc` (alias to `pqc.cli:main`)

### Core dependencies
The project has **zero mandatory runtime dependencies**. It works using only the Python standard library.

### Optional extras
| Extra | Package | Purpose |
|-------|---------|---------|
| `sslyze` | `sslyze>=6.0` | Deep TLS enumeration (all cipher suites, all KEX groups) |
| `agent` | `psutil>=5.9` | Reliable cross-platform connection table for the monitoring agent |
| `asyncssh` | `asyncssh>=2.14` | Richer SSH probing with negotiation details |
| `all` | All of the above | Convenience meta-extra |
| `dev` | `pytest>=8`, `pytest-asyncio`, `pytest-cov`, `ruff`, `mypy` | Development tooling |

---

## Project Structure

```
├── src/
│   └── pqc/              # Package source
│       ├── __init__.py
│       ├── __main__.py
│       ├── algorithms.py          # PQC taxonomy: PQCStatus, classify(), is_pqc(), TRAFFIC_LIGHT
│       ├── scanner.py             # Core scanner: scan(), Protocol, ScanResult, auto-detection
│       ├── cli.py                 # argparse CLI: scan + agent subcommands, pretty-printing, JSON output
│       ├── agent.py               # Monitoring daemon: Agent, AgentConfig, connection polling, logging
│       └── protocols/             # Protocol-specific probers (sub-package)
│           ├── __init__.py        # Empty
│           ├── tls.py             # TLS prober: stdlib ssl fallback, sslyze deep probe
│           ├── ssh.py             # SSH prober: raw KEXINIT parser (default), asyncssh fallback
│           └── ike.py             # IKEv2 prober: raw UDP SA_INIT request/response parser
├── tests/
│   └── test_pq.py     # Test suite
├── pyproject.toml               # Build & tool configuration
└── README.md                    # Human-facing documentation
```

### Module responsibilities

- **`algorithms.py`** — The source of truth for known PQC algorithm names. Contains frozen sets of PQC KEX and auth algorithms, a `classify()` function that returns `PQCStatus.NO_PQC / PQC_AVAILABLE`, and `TRAFFIC_LIGHT` mapping for display.
- **`scanner.py`** — Orchestrates probing. Auto-detects protocol by port hint (22→SSH, 443→TLS, 500/4500→IKE) or by banner/TLS handshake. Delegates to the appropriate protocol prober, deduplicates results, and builds a `ScanResult`.
- **`cli.py`** — Argument parsing and output formatting. `scan` exits with codes: `0` for PQC_AVAILABLE, `1` for NO_PQC, `2` for unknown errors.
- **`agent.py`** — Polls active connections via `psutil` (preferred), `ss`, or `netstat` fallback. Spawns a background thread per target to run `scan()`. Supports logging to NDJSON (`.json`), CSV (`.csv`), or stdout. Implements a rescan cooldown to avoid thrashing.
- **`protocols/tls.py`** — Two probe strategies: `_probe_stdlib` (negotiated cipher + TLS version) and `_probe_sslyze` (full cipher suite + elliptic curve enumeration).
- **`protocols/ssh.py`** — Two probe strategies: `_probe_raw` (reads SSH banner, parses SSH_MSG_KEXINIT packet type 20 without authenticating) and `_probe_asyncssh` (uses asyncssh library for richer negotiation info).
- **`protocols/ike.py`** — No third-party dependencies. Builds a minimal IKEv2 IKE_SA_INIT UDP packet, sends it, and parses the SA payload to extract DH groups, encryption, integrity, and PRF transforms. Maps IANA DH group IDs to human-readable names (including PQC groups like kyber768, mlkem768, x25519_mlkem768).

---

## Build, Install, and Run Commands

### Install from source (editable)
```bash
pip install -e ".[all]"        # With all optional extras
pip install -e ".[dev]"        # With development dependencies
```

### Run the CLI
```bash
# Scan a single endpoint
pqc scan example.com 443
pqc scan github.com 22
pqc scan vpn.example.com 500

# Force protocol, JSON output, verbose
pqc scan example.com 8443 --protocol tls --json -v

# Run agent
pqc agent example.com:443 github.com:22
pqc agent --scan-all --poll-interval 10 --cooldown 60 --log-file results.json
```

### Run tests
```bash
pytest tests/ -v
```

> **Note**: Tests live in `tests/test_pqc.py`. `pyproject.toml` sets `testpaths = ["tests"]`, so bare `pytest` discovers them automatically once the package is installed in editable mode.

### Lint and type-check
```bash
ruff check .
mypy src/pqc/
```

---

## Code Style and Conventions

- **Line length**: 100 characters (ruff config).
- **Target Python version**: 3.11 (ruff and mypy config).
- **Lint rules enabled**: `E`, `F`, `I`, `UP` (ruff).
- **Type checking**: mypy with `strict = false` and `ignore_missing_imports = true`.
- **String literals**: Double quotes are used consistently in docstrings and most string literals.
- **Annotations**: `from __future__ import annotations` is present in every module. Type hints use modern syntax (e.g., `list[str]`, `tuple[str, int]`, `Optional[str]`).
- **Logging**: Each module creates a module-level logger via `logging.getLogger(__name__)`.
- **Dataclasses**: Heavily used for result objects (`ScanResult`, `TLSResult`, `SSHResult`, `IKEResult`, `AgentConfig`, `ScanEvent`).
- **Enums**: `Protocol` and `PQCStatus` are `Enum` subclasses.
- **Docstrings**: All modules and public functions have descriptive docstrings.

---

## Testing Strategy

- **Framework**: pytest.
- **Async support**: `pytest-asyncio` is installed; `asyncio_mode = auto` is configured in `pyproject.toml`.
- **Coverage**: `pytest-cov` is available but not pre-configured with a target threshold.
- **Test file**: `tests/test_pqc.py` (single file under `tests/`).
- **Test categories**:
  - Algorithm classification logic (`TestPQCClassification`, `TestIsPQC`, `TestTrafficLight`)
  - Scanner dataclass behavior (`TestScanner`)
  - TLS prober dataclass fields (`TestTLSProber`)
  - SSH raw packet parsing (`TestSSHRawParser`)
  - Agent target matching and cooldown logic (`TestAgent`)
  - IKE packet construction sanity checks (`TestIKEPacket`)
- **Network policy**: Tests are strictly offline — no real network connections are made. All protocol tests exercise dataclass construction, parsing helpers, or logic branches only.

---

## Known Issues and Structural Notes

### 1. Python version gap
`pyproject.toml` declares `requires-python = ">=3.8"`. While the code is written for Python 3.11+ syntax (e.g. `list[str]` instead of `typing.List[str]`), the `from __future__ import annotations` import defers evaluation and keeps the code compatible with 3.8+ at runtime. However, some stdlib features used in development tooling may assume a newer interpreter.

---

## Security Considerations

- **No credentials required**: All protocol probes are unauthenticated. The SSH prober reads the server's KEXINIT banner and disconnects. The TLS prober performs a handshake without sending client certificates. The IKEv2 prober sends a SA_INIT request only.
- **TLS certificate validation is disabled** during probes (`ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE`). This is intentional — the goal is algorithm enumeration, not trust verification.
- **Agent runs probes in daemon threads**: Each observed connection spawns a new `threading.Thread(daemon=True)` to run `scan()`. Exceptions inside threads are logged but do not crash the agent.
- **Logging**: The agent can write scan results to disk in NDJSON or CSV format. Log files are opened in append mode (`"a"`). Ensure the log directory has appropriate permissions.
- **UDP socket usage**: The IKEv2 prober uses raw UDP sockets. It does not require elevated privileges for standard ports (500/4500) unless a local firewall policy blocks outbound UDP.

---

## Quick Reference for Agents

| Task | Command |
|------|---------|
| Install dev deps | `pip install -e ".[dev]"` |
| Run tests | `pytest tests/ -v` |
| Lint | `ruff check .` |
| Type check | `mypy src/pqc/` |
| Scan endpoint | `python -m pqc.cli scan HOST PORT` |
| Run agent | `python -m pqc.cli agent --scan-all` |

---

*Last updated: 2026-05-20*
