"""
pqc CLI

Commands:
  scan    — probe a single host:port
  agent   — run the monitoring daemon
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        format="%(levelname)s %(name)s: %(message)s",
        level=level,
    )


# ---------------------------------------------------------------------------
# Pretty-print scan result
# ---------------------------------------------------------------------------

def _print_result(result, json_out: bool, verbose: bool) -> None:
    from pqc.algorithms import TRAFFIC_LIGHT, PQCStatus

    if json_out:
        print(json.dumps(result.to_dict(), indent=2))
        return

    emoji, label, description = TRAFFIC_LIGHT[result.status]
    width = 60

    print()
    print("─" * width)
    print(f"  {emoji}  {label}")
    print(f"  {description}")
    print("─" * width)
    print(f"  Host:     {result.host}:{result.port}")
    print(f"  Protocol: {result.protocol.value.upper()}")

    if result.error:
        print(f"  Error:    {result.error}")

    if result.pqc_algorithms:
        print(f"\n  PQC algorithms detected ({len(result.pqc_algorithms)}):")
        for a in result.pqc_algorithms:
            print(f"    ✓ {a}")

    if verbose and result.classical_algorithms:
        print(f"\n  Classical algorithms ({len(result.classical_algorithms)}):")
        for a in result.classical_algorithms:
            print(f"    · {a}")

    if result.ssh and verbose:
        print(f"\n  SSH banner: {result.ssh.banner}")

    if result.tls and verbose:
        print(f"\n  TLS version: {result.tls.tls_version}")
        if result.tls.certificate_sig_alg:
            print(f"  Cert sig alg: {result.tls.certificate_sig_alg}")

    print()


# ---------------------------------------------------------------------------
# scan sub-command
# ---------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    from pqc.scanner import scan

    result = scan(
        host=args.host,
        port=args.port,
        protocol=args.protocol,
        timeout=args.timeout,
        prefer_sslyze=not args.no_sslyze,
        prefer_asyncssh=args.asyncssh,
    )

    _print_result(result, args.json, args.verbose)

    # Exit code reflects status
    return {
        "no_pqc": 1,
        "pqc_available": 0,
    }.get(result.status.value, 2)


# ---------------------------------------------------------------------------
# agent sub-command
# ---------------------------------------------------------------------------

def cmd_agent(args: argparse.Namespace) -> int:
    from pqc.agent import Agent, AgentConfig

    targets: list[tuple[str, int]] = []
    for t in (args.targets or []):
        try:
            host, port = t.rsplit(":", 1)
            targets.append((host, int(port)))
        except ValueError:
            print(f"Invalid target '{t}' — expected host:port", file=sys.stderr)
            return 1

    log_file = Path(args.log_file) if args.log_file else None

    # agent defaults to scan-all when no explicit targets are given
    scan_all = args.scan_all or (not targets and not args.no_scan_all)

    config = AgentConfig(
        targets=targets,
        poll_interval=args.poll_interval,
        rescan_cooldown=args.cooldown,
        probe_timeout=args.timeout,
        log_file=log_file,
        log_stdout=True,
        protocol_hint=args.protocol,
        scan_all=scan_all,
        scan_local=args.scan_local,
    )

    agent = Agent(config)
    try:
        agent.run()
    except KeyboardInterrupt:
        agent.stop()

    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pqc",
        description="Post-Quantum Cryptography readiness scanner & monitor",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    sub = parser.add_subparsers(dest="command", required=True)

    # -- scan -----------------------------------------------------------------
    p_scan = sub.add_parser("scan", help="Probe a single host:port")
    p_scan.add_argument("host", help="Target hostname or IP")
    p_scan.add_argument("port", type=int, help="Target port")
    p_scan.add_argument(
        "-p", "--protocol",
        choices=["tls", "ssh", "ike"],
        default=None,
        help="Force protocol (default: auto-detect)",
    )
    p_scan.add_argument("--timeout", type=float, default=10.0, help="Socket timeout (s)")
    p_scan.add_argument("--no-sslyze", action="store_true", help="Skip sslyze, use stdlib ssl")
    p_scan.add_argument("--asyncssh", action="store_true", help="Use asyncssh for SSH probing")
    p_scan.add_argument("--json", action="store_true", help="Output JSON")

    # -- agent ----------------------------------------------------------------
    p_agent = sub.add_parser("agent", help="Run the connection monitoring daemon")
    p_agent.add_argument(
        "targets",
        nargs="*",
        metavar="HOST:PORT",
        help="Endpoints to watch (e.g. example.com:443). "
             "If omitted, the agent scans ALL observed connections by default.",
    )
    p_agent.add_argument(
        "--scan-all",
        action="store_true",
        help="Scan ALL observed connections (default: true when no targets are given)",
    )
    p_agent.add_argument(
        "--no-scan-all",
        action="store_true",
        help="Only scan explicitly listed targets, not all observed connections",
    )
    p_agent.add_argument(
        "--scan-local",
        action="store_true",
        help="Only scan connections to local/private IP ranges (RFC 1918, loopback). "
             "Use with --scan-all or --targets",
    )
    p_agent.add_argument(
        "--poll-interval",
        type=float,
        default=5.0,
        help="Seconds between connection-table polls (default: 5)",
    )
    p_agent.add_argument(
        "--cooldown",
        type=float,
        default=300.0,
        help="Seconds before re-scanning the same endpoint (default: 300)",
    )
    p_agent.add_argument("--timeout", type=float, default=10.0, help="Probe socket timeout (s)")
    p_agent.add_argument("-p", "--protocol", choices=["tls", "ssh", "ike"], default=None)
    p_agent.add_argument(
        "--log-file",
        metavar="PATH",
        help="Log file path (.json appends NDJSON, .csv appends CSV rows, other = plaintext)",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    _setup_logging(args.verbose)

    dispatch = {"scan": cmd_scan, "agent": cmd_agent}
    fn = dispatch.get(args.command)
    if fn is None:
        parser.print_help()
        sys.exit(1)

    sys.exit(fn(args))


if __name__ == "__main__":
    main()
