"""
PQ Agent.

Monitors the host's active TCP/UDP connections using psutil (or ss/netstat
as a fallback). When a connection to a monitored or any external host:port is
observed, the agent proactively connects to that endpoint separately and runs
a PQC scan, logging the result.

Usage
-----
    from pqc.agent import Agent, AgentConfig
    cfg = AgentConfig(targets=[("example.com", 443)])
    agent = Agent(cfg)
    agent.run()         # blocking
    # or
    await agent.run_async()
"""

from __future__ import annotations

import asyncio
import csv
import ipaddress
import json
import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Callable

from .scanner import scan, ScanResult

log = logging.getLogger(__name__)


def _is_local_address(host: str) -> bool:
    """Return True if *host* is a loopback, link-local, or RFC 1918 private address."""
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_loopback or addr.is_link_local or addr.is_private
    except ValueError:
        return False


@dataclass
class AgentConfig:
    # List of (host, port) to watch for connections to. Empty = watch ALL.
    targets: list[tuple[str, int]] = field(default_factory=list)

    # Seconds between connection-table polls
    poll_interval: float = 5.0

    # Seconds to wait before re-scanning the same endpoint (avoid thrash)
    rescan_cooldown: float = 300.0

    # Timeout for each probe
    probe_timeout: float = 10.0

    # Where to write logs. Supports .json, .csv, or .log (plaintext).
    log_file: Optional[Path] = None

    # Also log to stdout
    log_stdout: bool = True

    # Force a specific protocol ("tls"/"ssh"/"ike") or None for auto-detect
    protocol_hint: Optional[str] = None

    # Whether to scan ALL observed connections, not just target list
    scan_all: bool = False

    # Only scan local/private addresses (loopback, link-local, RFC 1918)
    scan_local: bool = False


@dataclass
class ScanEvent:
    timestamp: str
    host: str
    port: int
    protocol: str
    status: str
    label: str
    pqc_algorithms: list[str]
    classical_algorithms: list[str]
    error: Optional[str]
    resolved_ip: Optional[str] = None
    hostname: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_scan_result(cls, result: ScanResult) -> "ScanEvent":
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            host=result.host,
            port=result.port,
            protocol=result.protocol.value,
            status=result.status.value,
            label=result.label,
            pqc_algorithms=result.pqc_algorithms,
            classical_algorithms=result.classical_algorithms,
            error=result.error,
            resolved_ip=result.resolved_ip,
            hostname=result.hostname,
        )


# ---------------------------------------------------------------------------
# Connection enumeration
# ---------------------------------------------------------------------------

# TCP connection states worth tracking (catches short-lived and in-progress connections)
_TRACKED_STATES = frozenset({"ESTABLISHED", "SYN_SENT", "SYN_RECV", "SYN-SENT", "SYN-RECV", "ESTAB"})


def _connections_psutil() -> set[tuple[str, int]]:
    """Return set of (remote_host, remote_port) for active/in-progress connections."""
    import psutil
    _psutil_tracked = frozenset({
        psutil.CONN_ESTABLISHED,
        psutil.CONN_SYN_SENT,
        psutil.CONN_SYN_RECV,
    })
    endpoints: set[tuple[str, int]] = set()
    for conn in psutil.net_connections(kind="inet"):
        if conn.status in _psutil_tracked and conn.raddr:
            endpoints.add((conn.raddr.ip, conn.raddr.port))
    return endpoints


def _connections_ss() -> set[tuple[str, int]]:
    """Fallback: parse `ss -tnp` output."""
    endpoints: set[tuple[str, int]] = set()
    try:
        out = subprocess.check_output(["ss", "-tnp"], text=True, timeout=5)
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5 and parts[0] in _TRACKED_STATES:
                peer = parts[4]
                if ":" in peer:
                    host, _, port = peer.rpartition(":")
                    try:
                        endpoints.add((host.strip("[]"), int(port)))
                    except ValueError:
                        pass
    except Exception as exc:
        log.debug("ss failed: %s", exc)
    return endpoints


def _connections_netstat() -> set[tuple[str, int]]:
    """Fallback: parse `netstat -tn` (Linux and macOS/BSD formats)."""
    endpoints: set[tuple[str, int]] = set()
    try:
        out = subprocess.check_output(["netstat", "-tn"], text=True, timeout=5)
        for line in out.splitlines():
            if any(state in line for state in _TRACKED_STATES):
                parts = line.split()
                if len(parts) >= 5:
                    peer = parts[4]
                    host = port_str = None
                    # Linux:  192.168.1.1:443
                    # macOS:  192.168.1.1.443
                    if ":" in peer:
                        host, _, port_str = peer.rpartition(":")
                    elif "." in peer:
                        host, _, port_str = peer.rpartition(".")
                    if host and port_str:
                        try:
                            endpoints.add((host.strip("[]"), int(port_str)))
                        except ValueError:
                            pass
    except Exception as exc:
        log.debug("netstat failed: %s", exc)
    return endpoints


def get_active_connections() -> set[tuple[str, int]]:
    """Return active outbound/established TCP connections as (host, port) pairs.

    Merges results from all available sources (psutil, ss, netstat) because
    individual tools can have incomplete visibility on some platforms
    (e.g. macOS psutil may miss connections without root privileges).
    """
    endpoints: set[tuple[str, int]] = set()

    try:
        endpoints.update(_connections_psutil())
    except Exception as exc:
        log.debug("psutil connection enumeration failed: %s", exc)

    try:
        endpoints.update(_connections_ss())
    except Exception as exc:
        log.debug("ss connection enumeration failed: %s", exc)

    try:
        endpoints.update(_connections_netstat())
    except Exception as exc:
        log.debug("netstat connection enumeration failed: %s", exc)

    return endpoints


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

class EventLogger:
    def __init__(self, log_file: Optional[Path], log_stdout: bool):
        self._file = log_file
        self._stdout = log_stdout
        self._csv_writer = None
        self._fh = None
        self._lock = threading.Lock()

        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            if log_file.suffix == ".csv":
                self._fh = open(log_file, "a", newline="")
                self._csv_writer = csv.DictWriter(
                    self._fh,
                    fieldnames=["timestamp", "host", "port", "protocol", "status",
                                "label", "pqc_algorithms", "classical_algorithms", "error",
                                "resolved_ip", "hostname"],
                )
                if log_file.stat().st_size == 0:
                    self._csv_writer.writeheader()
            else:
                self._fh = open(log_file, "a")

    def log(self, event: ScanEvent) -> None:
        with self._lock:
            d = event.to_dict()

            if self._stdout:
                emoji = {"no_pqc": "🔴", "pqc_available": "🟢"}.get(event.status, "⚪")
                display_host = event.host
                if event.hostname and event.hostname != event.host:
                    display_host = f"{event.hostname} ({event.host})"
                elif event.resolved_ip and event.resolved_ip != event.host:
                    display_host = f"{event.host} ({event.resolved_ip})"
                pqc_part = f"  PQC={event.pqc_algorithms}" if event.pqc_algorithms else ""
                proto_display = "---" if event.protocol.upper() == "UNKNOWN" else event.protocol.upper()
                print(
                    f"[{event.timestamp}] {emoji} {proto_display:5s}  {event.label:8s}  "
                    f"{display_host}:{event.port}{pqc_part}",
                    flush=True,
                )

            if self._fh:
                if self._csv_writer:
                    row = {**d}
                    row["pqc_algorithms"] = ",".join(event.pqc_algorithms)
                    row["classical_algorithms"] = ",".join(event.classical_algorithms)
                    self._csv_writer.writerow(row)
                else:
                    self._fh.write(json.dumps(d) + "\n")
                self._fh.flush()

    def close(self):
        if self._fh:
            self._fh.close()


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class Agent:
    """
    Proactive PQC monitoring agent.

    Polls the system's active connection table. When a connection to a
    watched endpoint appears, it independently connects to that endpoint and
    runs a PQC scan, logging the result.
    """

    def __init__(
        self,
        config: AgentConfig,
        on_result: Optional[Callable[[ScanEvent], None]] = None,
    ):
        self.config = config
        self._on_result = on_result
        self._logger = EventLogger(config.log_file, config.log_stdout)
        # (host, port) → last scan timestamp
        self._last_scanned: dict[tuple[str, int], float] = {}
        # (host, port) currently being probed (prevents stampede on slow endpoints)
        self._in_flight: set[tuple[str, int]] = set()
        self._stop_event = threading.Event()

    # -- Target matching -------------------------------------------------------

    def _is_watched(self, host: str, port: int) -> bool:
        if self.config.scan_local and not _is_local_address(host):
            return False
        if self.config.scan_all:
            return True
        if not self.config.targets:
            return False
        for t_host, t_port in self.config.targets:
            if t_port == port and (t_host in ("*", host) or host == t_host):
                return True
        return False

    def _in_cooldown(self, host: str, port: int) -> bool:
        last = self._last_scanned.get((host, port))
        if last is None:
            return False
        return (time.monotonic() - last) < self.config.rescan_cooldown

    def _in_flight_check(self, host: str, port: int) -> bool:
        return (host, port) in self._in_flight

    # -- Scanning --------------------------------------------------------------

    def _probe(self, host: str, port: int) -> None:
        key = (host, port)
        if key in self._in_flight:
            return
        self._in_flight.add(key)
        try:
            log.info("Probing %s:%d", host, port)
            try:
                result = scan(
                    host,
                    port,
                    protocol=self.config.protocol_hint,
                    timeout=self.config.probe_timeout,
                )
            except Exception as exc:
                log.error("Scan error for %s:%d — %s", host, port, exc)
                return

            self._last_scanned[key] = time.monotonic()
            event = ScanEvent.from_scan_result(result)
            self._logger.log(event)

            if self._on_result:
                try:
                    self._on_result(event)
                except Exception as exc:
                    log.warning("on_result callback raised: %s", exc)
        finally:
            self._in_flight.discard(key)

    # -- Main loop -------------------------------------------------------------

    def run(self) -> None:
        """Blocking main loop. Call stop() from another thread to exit."""
        log.info(
            "PQ Agent started. Poll interval=%.1fs  Cooldown=%.0fs",
            self.config.poll_interval,
            self.config.rescan_cooldown,
        )
        if self.config.targets:
            log.info("Watching targets: %s", self.config.targets)
        elif self.config.scan_all:
            log.info("scan_all=True — watching ALL observed connections")
        else:
            log.warning("No targets configured and scan_all=False — agent is a no-op")

        try:
            while not self._stop_event.is_set():
                self._tick()
                self._stop_event.wait(self.config.poll_interval)
        finally:
            self._logger.close()
            log.info("Agent stopped.")

    def _tick(self) -> None:
        connections = get_active_connections()
        for host, port in connections:
            if (
                self._is_watched(host, port)
                and not self._in_cooldown(host, port)
                and not self._in_flight_check(host, port)
            ):
                t = threading.Thread(target=self._probe, args=(host, port), daemon=True)
                t.start()

    def stop(self) -> None:
        self._stop_event.set()

    # -- Async wrapper ---------------------------------------------------------

    async def run_async(self) -> None:
        """Async version: runs the blocking loop in an executor."""
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self.run)


# ---------------------------------------------------------------------------
# Allow `python -m pqc.agent ...` to work as a convenience alias
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    # If no recognised subcommand is present, default to "agent"
    if len(sys.argv) < 2 or sys.argv[1] not in ("scan", "agent", "-h", "--help"):
        sys.argv.insert(1, "agent")

    from pqc.cli import main

    sys.exit(main())
