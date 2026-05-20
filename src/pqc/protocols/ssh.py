"""
SSH protocol prober.

Connects to an SSH server and reads the server's algorithm advertisement
from the SSH_MSG_KEXINIT packet without completing authentication.
Uses asyncssh when available; falls back to a raw banner + kexinit parser.
"""

from __future__ import annotations

import socket
import struct
import logging
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class SSHResult:
    host: str
    port: int
    success: bool
    banner: Optional[str] = None
    kex_algorithms: list[str] = field(default_factory=list)
    host_key_algorithms: list[str] = field(default_factory=list)
    encryption_algorithms_client: list[str] = field(default_factory=list)
    encryption_algorithms_server: list[str] = field(default_factory=list)
    mac_algorithms: list[str] = field(default_factory=list)
    compression_algorithms: list[str] = field(default_factory=list)
    error: Optional[str] = None
    probe_method: str = "raw"


def _read_name_list(data: bytes, offset: int) -> tuple[list[str], int]:
    """Parse an SSH name-list (uint32 length + comma-separated string)."""
    if offset + 4 > len(data):
        return [], offset
    length = struct.unpack_from(">I", data, offset)[0]
    offset += 4
    if offset + length > len(data):
        return [], offset
    names = data[offset: offset + length].decode("ascii", errors="replace")
    offset += length
    return [n.strip() for n in names.split(",") if n.strip()], offset


def _probe_raw(host: str, port: int, timeout: float) -> SSHResult:
    """
    Raw TCP probe: grab SSH banner + parse SSH_MSG_KEXINIT (packet type 20).
    No authentication performed.
    """
    result = SSHResult(host=host, port=port, success=False)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            # Read banner
            banner_bytes = b""
            while b"\n" not in banner_bytes and len(banner_bytes) < 512:
                chunk = sock.recv(1)
                if not chunk:
                    break
                banner_bytes += chunk
            result.banner = banner_bytes.decode("utf-8", errors="replace").strip()

            # Send our client banner
            sock.sendall(b"SSH-2.0-pqc_0.1\r\n")

            # Read SSH binary packets until we get KEXINIT (msg type 20)
            for _ in range(8):  # tolerate up to 8 packets before giving up
                # Packet: uint32 packet_length, byte padding_length, payload
                header = b""
                while len(header) < 4:
                    chunk = sock.recv(4 - len(header))
                    if not chunk:
                        break
                    header += chunk
                if len(header) < 4:
                    break

                pkt_len = struct.unpack(">I", header)[0]
                if pkt_len > 65536:
                    result.error = f"Unexpectedly large packet: {pkt_len}"
                    return result

                pkt_data = b""
                while len(pkt_data) < pkt_len:
                    chunk = sock.recv(pkt_len - len(pkt_data))
                    if not chunk:
                        break
                    pkt_data += chunk

                if len(pkt_data) < 2:
                    continue

                padding_len = pkt_data[0]
                msg_type = pkt_data[1]
                payload = pkt_data[2: pkt_len - padding_len]

                if msg_type != 20:  # SSH_MSG_KEXINIT
                    continue

                # Parse KEXINIT payload
                # 16-byte cookie, then 10 name-lists, then 1-byte follows + reserved uint32
                offset = 16  # skip cookie
                result.kex_algorithms, offset = _read_name_list(payload, offset)
                result.host_key_algorithms, offset = _read_name_list(payload, offset)
                result.encryption_algorithms_client, offset = _read_name_list(payload, offset)
                result.encryption_algorithms_server, offset = _read_name_list(payload, offset)
                result.mac_algorithms, offset = _read_name_list(payload, offset)
                result.mac_algorithms, offset = _read_name_list(payload, offset)  # mac c->s
                result.compression_algorithms, offset = _read_name_list(payload, offset)
                result.success = True
                break

    except Exception as exc:
        result.error = str(exc)

    return result


def _probe_asyncssh(host: str, port: int, timeout: float) -> SSHResult:
    """Probe using asyncssh for richer detail."""
    import asyncio

    try:
        import asyncssh
    except ImportError:
        raise ImportError("asyncssh not installed")

    result = SSHResult(host=host, port=port, success=False, probe_method="asyncssh")

    async def _inner():
        try:
            # Connect but don't authenticate — just get the algorithm negotiation
            conn, _ = await asyncio.wait_for(
                asyncssh.create_connection(
                    None,
                    host=host,
                    port=port,
                    known_hosts=None,
                    username="pqc-probe",
                ),
                timeout=timeout,
            )
            result.banner = conn.get_extra_info("server_version")
            # asyncssh exposes the negotiated algorithm set
            result.kex_algorithms = [conn.get_extra_info("kex_alg", "")]
            result.host_key_algorithms = [conn.get_extra_info("server_host_key_alg", "")]
            encryption = conn.get_extra_info("encryption_alg", "")
            result.encryption_algorithms_client = [encryption]
            result.success = True
            conn.close()
        except asyncssh.DisconnectError:
            # Expected — we don't supply valid credentials
            result.success = True
        except Exception as exc:
            result.error = str(exc)

    try:
        asyncio.run(_inner())
    except RuntimeError:
        loop = asyncio.new_event_loop()
        loop.run_until_complete(_inner())
        loop.close()

    return result


def probe_ssh(host: str, port: int, timeout: float = 10.0, prefer_asyncssh: bool = False) -> SSHResult:
    """
    Probe an SSH endpoint and enumerate its advertised algorithms.

    The raw prober is default because it requires no third-party library and
    captures the full server KEXINIT advertisement (not just what was negotiated).
    """
    if prefer_asyncssh:
        try:
            return _probe_asyncssh(host, port, timeout)
        except ImportError:
            log.debug("asyncssh not available, using raw prober")

    return _probe_raw(host, port, timeout)
