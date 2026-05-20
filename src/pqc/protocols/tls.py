"""
TLS protocol prober.

Uses sslyze when available for deep enumeration; falls back to the stdlib
ssl module for basic supported-cipher detection, augmented with a raw
TLS 1.3 ClientHello probe to detect post-quantum key-exchange groups
even when sslyze is not installed.
"""

from __future__ import annotations

import logging
import random
import socket
import ssl
import struct
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..algorithms import is_pqc

log = logging.getLogger(__name__)


@dataclass
class TLSResult:
    host: str
    port: int
    success: bool
    tls_version: Optional[str] = None
    kex_algorithms: list[str] = field(default_factory=list)
    cipher_suites: list[str] = field(default_factory=list)
    certificate_sig_alg: Optional[str] = None
    error: Optional[str] = None
    probe_method: str = "stdlib"


# ---------------------------------------------------------------------------
# Raw TLS hello probe helpers
# ---------------------------------------------------------------------------

# HelloRetryRequest fixed random value (RFC 8446 §4.1.3)
_HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
)

# IANA TLS Supported Groups registry (relevant entries)
_TLS_GROUP_NAMES: dict[int, str] = {
    # Classical
    0x001D: "X25519",
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    # Pure ML-KEM
    0x0200: "MLKEM512",
    0x0201: "MLKEM768",
    0x0202: "MLKEM1024",
    # Hybrid ECDHE-MLKEM (final)
    0x11EC: "X25519MLKEM768",
    0x11EB: "SecP256r1MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
    # Hybrid ECDHE-Kyber (draft / obsolete)
    0x6399: "X25519Kyber768Draft00",
    0x639A: "SecP256r1Kyber768Draft00",
}

# PQC group IDs we probe for
_PQC_GROUP_IDS = [
    0x11EC,
    0x6399,
    0x11EB,
    0x11ED,
    0x0200,
    0x0201,
    0x0202,
]


def _build_client_hello(
    host: str,
    random_bytes: bytes,
    supported_group_ids: list[int],
    key_share_entries: list[tuple[int, bytes]],
) -> bytes:
    """Build a minimal TLS 1.3 ClientHello record."""
    extensions = b""

    # server_name (SNI)
    sni_hostname = host.encode("ascii")
    sni_entry = b"\x00" + struct.pack("!H", len(sni_hostname)) + sni_hostname
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    extensions += struct.pack("!HH", 0, len(sni_list)) + sni_list

    # supported_versions (TLS 1.3)
    supp_versions = b"\x02\x03\x04"
    extensions += struct.pack("!HH", 43, len(supp_versions)) + supp_versions

    # supported_groups
    groups = b"".join(struct.pack("!H", g) for g in supported_group_ids)
    groups_ext = struct.pack("!H", len(groups)) + groups
    extensions += struct.pack("!HH", 10, len(groups_ext)) + groups_ext

    # key_share
    entries = b"".join(
        struct.pack("!H", gid) + struct.pack("!H", len(data)) + data
        for gid, data in key_share_entries
    )
    key_share_data = struct.pack("!H", len(entries)) + entries
    extensions += struct.pack("!HH", 51, len(key_share_data)) + key_share_data

    # signature_algorithms
    sigs = struct.pack(
        "!HHHHHHHH",
        0x0403,  # ecdsa_secp256r1_sha256
        0x0804,  # rsa_pss_rsae_sha256
        0x0401,  # rsa_pkcs1_sha256
        0x0503,  # ecdsa_secp384r1_sha384
        0x0603,  # ecdsa_secp521r1_sha512
        0x0201,  # rsa_pkcs1_sha1
        0x0203,  # ecdsa_sha1
        0x0807,  # ed25519
    )
    sigs_ext = struct.pack("!H", len(sigs)) + sigs
    extensions += struct.pack("!HH", 13, len(sigs_ext)) + sigs_ext

    # Cipher suites (TLS 1.3 only)
    cipher_suites = struct.pack("!HHH", 0x1301, 0x1302, 0x1303)
    ciphers = struct.pack("!H", len(cipher_suites)) + cipher_suites

    client_hello = (
        b"\x03\x03"  # legacy_version = TLS 1.2
        + random_bytes
        + b"\x00"  # session_id length
        + ciphers
        + b"\x01\x00"  # compression methods
        + struct.pack("!H", len(extensions))
        + extensions
    )

    handshake = b"\x01" + struct.pack("!I", len(client_hello))[1:] + client_hello
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record


def _read_tls_record(sock: socket.socket) -> tuple[int, int, bytes] | None:
    """Read a single TLS record from *sock*."""
    header = sock.recv(5)
    if len(header) < 5:
        return None
    typ, ver, length = struct.unpack("!BHH", header)
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return typ, ver, data


def _parse_server_hello(data: bytes) -> tuple[bool, int | None]:
    """Parse a ServerHello/HRR.  Returns (is_hrr, key_share_group_id)."""
    if len(data) < 4:
        return False, None
    ht = data[0]
    hl = struct.unpack("!I", b"\x00" + data[1:4])[0]
    if ht != 0x02 or len(data) < 4 + hl:
        return False, None

    ptr = 4
    # legacy_version
    ptr += 2
    # random
    sh_random = data[ptr : ptr + 32]
    ptr += 32
    is_hrr = sh_random == _HRR_RANDOM

    # session_id
    sid_len = data[ptr]
    ptr += 1 + sid_len

    # cipher_suite
    ptr += 2

    # legacy_compression_method
    ptr += 1

    # extensions
    if len(data) < ptr + 2:
        return is_hrr, None
    exts_len = struct.unpack("!H", data[ptr : ptr + 2])[0]
    ptr += 2
    end = ptr + exts_len

    key_share_group: int | None = None
    while ptr < end:
        if len(data) < ptr + 4:
            break
        etype, elen = struct.unpack("!HH", data[ptr : ptr + 4])
        ptr += 4
        if len(data) < ptr + elen:
            break
        edata = data[ptr : ptr + elen]
        ptr += elen
        if etype == 51 and len(edata) >= 2:  # key_share
            key_share_group = struct.unpack("!H", edata[:2])[0]

    return is_hrr, key_share_group


def _probe_tls_hello(host: str, port: int, timeout: float) -> list[str]:
    """
    Detect PQC key-exchange groups via raw TLS 1.3 ClientHello probes.

    Strategy:
      1. Offer PQC + X25519 in supported_groups with an X25519 key_share.
         If the server replies with an HRR for a PQC group, or selects a
         PQC group directly, we know PQC is supported.
      2. Otherwise, offer *only* PQC groups with an empty key_share.
         A TLS 1.3 server that supports any of them MUST reply with an
         HRR naming the preferred group.  An alert means no support.
    """
    x25519_base = bytes.fromhex(
        "0900000000000000000000000000000000000000000000000000000000000000"
    )
    random_bytes = bytes(random.getrandbits(8) for _ in range(32))

    # --- Probe 1: PQC + classical supported_groups, X25519 key_share ---
    probe1_groups = _PQC_GROUP_IDS + [0x001D]
    record1 = _build_client_hello(
        host, random_bytes, probe1_groups, [(0x001D, x25519_base)]
    )

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(record1)
            resp = _read_tls_record(sock)
            while resp and resp[0] == 0x14:  # skip ChangeCipherSpec
                resp = _read_tls_record(sock)

            if resp and resp[0] == 0x16:
                is_hrr, group_id = _parse_server_hello(resp[2])
                name = _TLS_GROUP_NAMES.get(group_id) if group_id is not None else None
                if name and is_pqc(name):
                    return [name]
                # If classical group was selected, fall through to Probe 2.
    except Exception as exc:
        log.debug("TLS raw probe 1 failed for %s:%d: %s", host, port, exc)

    # --- Probe 2: PQC-only supported_groups, empty key_share ---
    record2 = _build_client_hello(host, random_bytes, _PQC_GROUP_IDS, [])

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(record2)
            resp = _read_tls_record(sock)
            while resp and resp[0] == 0x14:
                resp = _read_tls_record(sock)

            if resp and resp[0] == 0x16:
                is_hrr, group_id = _parse_server_hello(resp[2])
                name = _TLS_GROUP_NAMES.get(group_id) if group_id is not None else None
                if name and is_hrr and is_pqc(name):
                    return [name]
            # Any alert or regular ServerHello here means no PQC from our set.
    except Exception as exc:
        log.debug("TLS raw probe 2 failed for %s:%d: %s", host, port, exc)

    return []


# ---------------------------------------------------------------------------
# STARTTLS negotiation helpers
# ---------------------------------------------------------------------------


def _read_smtp_lines(sock: socket.socket) -> list[bytes]:
    """Read a complete SMTP multi-line response."""
    lines: list[bytes] = []
    while True:
        line = b""
        while not line.endswith(b"\r\n"):
            chunk = sock.recv(1)
            if not chunk:
                break
            line += chunk
        if not line:
            break
        lines.append(line)
        # Final line has a space in the 4th position; continuation lines have '-'.
        if len(line) >= 4 and line[3:4] == b" ":
            break
    return lines


def _starttls_smtp(sock: socket.socket, _host: str) -> bool:
    """Negotiate STARTTLS on an SMTP connection (ports 25/587)."""
    lines = _read_smtp_lines(sock)
    if not lines or not lines[0].startswith(b"220"):
        return False
    sock.sendall(b"EHLO pqc\r\n")
    lines = _read_smtp_lines(sock)
    if not any(line.startswith(b"250") for line in lines):
        return False
    if not any(b"STARTTLS" in line for line in lines):
        return False
    sock.sendall(b"STARTTLS\r\n")
    lines = _read_smtp_lines(sock)
    return any(line.startswith(b"220") for line in lines)


def _starttls_ftp(sock: socket.socket, _host: str) -> bool:
    """Negotiate AUTH TLS on an FTP control connection (port 21)."""
    banner = sock.recv(1024)
    if not banner.startswith(b"220"):
        return False
    sock.sendall(b"AUTH TLS\r\n")
    resp = sock.recv(1024)
    return resp.startswith(b"234")


def _starttls_xmpp(sock: socket.socket, host: str) -> bool:
    """Negotiate STARTTLS on an XMPP client connection (port 5222)."""
    sock.sendall(
        b'<?xml version="1.0"?>'
        b'<stream:stream to="' + host.encode() + b'" '
        b'xmlns="jabber:client" '
        b'xmlns:stream="http://etherx.jabber.org/streams" '
        b'version="1.0">'
    )
    resp = b""
    while b"</stream:features>" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk
    # Accept both single and double quotes in XML attributes
    if b"urn:ietf:params:xml:ns:xmpp-tls" not in resp or b"<starttls" not in resp:
        return False
    sock.sendall(b'<starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>')
    resp = sock.recv(1024)
    return b"<proceed" in resp and b"urn:ietf:params:xml:ns:xmpp-tls" in resp


def _starttls_ldap(sock: socket.socket, _host: str) -> bool:
    """Negotiate StartTLS on an LDAP connection (port 389)."""
    # BER-encoded ExtendedRequest for OID 1.3.6.1.4.1.1466.20037
    req = bytes.fromhex(
        "301f020101771a8018"
        "312e332e362e312e342e312e313436362e3230303337"
    )
    sock.sendall(req)
    resp = sock.recv(4096)
    if len(resp) < 10 or resp[0] != 0x30:
        return False
    idx = resp.find(b"\x78")
    if idx == -1:
        return False
    # Look for success ENUMERATED (0x0a 0x01 0x00) inside the ExtendedResponse.
    return b"\x0a\x01\x00" in resp[idx : idx + 20]


# Port -> STARTTLS negotiator mapping
_STARTTLS_NEGOTIATORS: dict[int, Callable[[socket.socket, str], bool]] = {
    25: _starttls_smtp,
    587: _starttls_smtp,
    21: _starttls_ftp,
    5222: _starttls_xmpp,
    389: _starttls_ldap,
}


# ---------------------------------------------------------------------------
# Public probe functions
# ---------------------------------------------------------------------------


def _probe_stdlib(
    host: str,
    port: int,
    timeout: float,
    starttls_fn: Callable[[socket.socket, str], bool] | None = None,
) -> TLSResult:
    """Basic probe using stdlib ssl — captures negotiated cipher + TLS version."""
    result = TLSResult(host=host, port=port, success=False, probe_method="stdlib")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            if starttls_fn is not None:
                try:
                    ok = starttls_fn(raw, host)
                except Exception as exc:
                    result.error = f"STARTTLS negotiation failed: {exc}"
                    return result
                if not ok:
                    result.error = "STARTTLS not supported or rejected by server"
                    return result
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cipher = tls.cipher()
                result.tls_version = tls.version()
                if cipher:
                    result.cipher_suites = [cipher[0]]
                # Try to get the server cert sig alg
                cert = tls.getpeercert(binary_form=False)
                if cert:
                    sig = cert.get("signatureAlgorithm") or cert.get("signature_algorithm")
                    if sig:
                        result.certificate_sig_alg = str(sig)
                result.success = True
    except Exception as exc:
        result.error = str(exc)

    # Raw hello probe to discover PQC KEX groups that stdlib ssl cannot expose.
    try:
        raw_kex = _probe_tls_hello(host, port, timeout)
        result.kex_algorithms.extend(raw_kex)
    except Exception as exc:
        log.debug("Raw TLS hello probe failed for %s:%d: %s", host, port, exc)

    return result


def _probe_sslyze(host: str, port: int, timeout: float) -> TLSResult:
    """Deep probe using sslyze — enumerates all supported cipher suites and KEX groups."""
    try:
        from sslyze import (
            Scanner,
            ServerNetworkLocation,
            ServerScanRequest,
        )
        from sslyze.plugins.scan_commands import ScanCommand
    except ImportError:
        raise ImportError("sslyze not installed")

    result = TLSResult(host=host, port=port, success=False, probe_method="sslyze")

    try:
        location = ServerNetworkLocation(hostname=host, port=port)
        request = ServerScanRequest(
            server_location=location,
            scan_commands={
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.ELLIPTIC_CURVES,
                ScanCommand.CERTIFICATE_INFO,
            },
        )
        scanner = Scanner()
        scanner.queue_scans([request])

        for scan_result in scanner.get_results():
            if scan_result.scan_result is None:
                result.error = str(scan_result.connectivity_error)
                return result

            # Cipher suites
            for cmd in [ScanCommand.TLS_1_3_CIPHER_SUITES, ScanCommand.TLS_1_2_CIPHER_SUITES]:
                cmd_result = getattr(scan_result.scan_result, cmd.value, None)
                if cmd_result and hasattr(cmd_result, "accepted_cipher_suites"):
                    for cs in cmd_result.accepted_cipher_suites:
                        result.cipher_suites.append(cs.cipher_suite.name)

            # Elliptic curves / KEX groups (includes PQC hybrids when server supports them)
            ec_result = scan_result.scan_result.elliptic_curves
            if ec_result and hasattr(ec_result, "supported_curves") and ec_result.supported_curves:
                for curve in ec_result.supported_curves:
                    result.kex_algorithms.append(curve.name)

            # Certificate sig alg
            cert_result = scan_result.scan_result.certificate_info
            if cert_result and cert_result.certificate_deployments:
                dep = cert_result.certificate_deployments[0]
                leaf = dep.received_certificate_chain[0]
                result.certificate_sig_alg = leaf.signature_hash_algorithm.name if leaf.signature_hash_algorithm else None

            result.success = True

    except Exception as exc:
        result.error = str(exc)

    return result


def probe_tls(host: str, port: int, timeout: float = 10.0, prefer_sslyze: bool = True) -> TLSResult:
    """
    Probe a TLS endpoint.

    Tries sslyze first (if installed and prefer_sslyze=True) for comprehensive
    results; falls back to stdlib ssl.  For STARTTLS ports (SMTP, XMPP, LDAP,
    FTP) the stdlib path is always used because sslyze does not expose a
    simple STARTTLS API.
    """
    starttls_fn = _STARTTLS_NEGOTIATORS.get(port)
    if starttls_fn is not None:
        return _probe_stdlib(host, port, timeout, starttls_fn)

    if prefer_sslyze:
        try:
            return _probe_sslyze(host, port, timeout)
        except ImportError:
            log.debug("sslyze not available, falling back to stdlib ssl")

    return _probe_stdlib(host, port, timeout)
