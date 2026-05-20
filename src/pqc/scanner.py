"""
Core scanner.

Auto-detects or accepts a protocol hint, probes the target, collects all
advertised algorithms, and returns a unified ScanResult with PQC classification.
"""

from __future__ import annotations

import socket
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .algorithms import classify, is_pqc, PQCStatus, TRAFFIC_LIGHT
from .protocols.tls import probe_tls, TLSResult
from .protocols.ssh import probe_ssh, SSHResult
from .protocols.ike import probe_ike, IKEResult

log = logging.getLogger(__name__)


class Protocol(str, Enum):
    TLS = "tls"
    SSH = "ssh"
    IKE = "ike"
    OPENVPN = "openvpn"
    WIREGUARD = "wireguard"
    UNKNOWN = "unknown"


# Port → protocol hints
PORT_HINTS: dict[int, Protocol] = {
    22: Protocol.SSH,
    443: Protocol.TLS,
    465: Protocol.TLS,
    636: Protocol.TLS,
    993: Protocol.TLS,
    995: Protocol.TLS,
    8443: Protocol.TLS,
    500: Protocol.IKE,
    4500: Protocol.IKE,
    1194: Protocol.OPENVPN,
    51820: Protocol.WIREGUARD,
    # Plain-TLS protocols
    853: Protocol.TLS,    # DNS over TLS (DoT)
    8883: Protocol.TLS,   # MQTT over TLS
    6443: Protocol.TLS,   # Kubernetes API (HTTPS)
    5061: Protocol.TLS,   # SIP/TLS
    990: Protocol.TLS,    # FTPS (implicit TLS)
    # StartTLS protocols (scanner probes TLS after upgrading the plaintext connection)
    25: Protocol.TLS,     # SMTP STARTTLS
    587: Protocol.TLS,    # SMTP submission STARTTLS
    5222: Protocol.TLS,   # XMPP client STARTTLS
    389: Protocol.TLS,    # LDAP STARTTLS
    21: Protocol.TLS,     # FTP STARTTLS
}


def _looks_like_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        pass
    return False


def _resolve_host_info(host: str) -> tuple[Optional[str], Optional[str]]:
    """Return (resolved_ip, hostname) for *host*.

    *resolved_ip* is the IPv4/IPv6 address we would connect to.
    *hostname* is a human-readable name (reverse-DNS when *host* is an IP,
    otherwise the original *host* value).
    """
    resolved_ip: Optional[str] = None
    hostname: Optional[str] = None

    if _looks_like_ip(host):
        resolved_ip = host
        try:
            hostname = socket.gethostbyaddr(host)[0]
        except Exception:
            pass
    else:
        hostname = host
        try:
            resolved_ip = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
        except Exception:
            pass

    return resolved_ip, hostname


@dataclass
class ScanResult:
    host: str
    port: int
    protocol: Protocol
    status: PQCStatus
    pqc_algorithms: list[str] = field(default_factory=list)
    classical_algorithms: list[str] = field(default_factory=list)
    all_algorithms: list[str] = field(default_factory=list)
    tls: Optional[TLSResult] = None
    ssh: Optional[SSHResult] = None
    ike: Optional[IKEResult] = None
    error: Optional[str] = None
    resolved_ip: Optional[str] = None
    hostname: Optional[str] = None

    @property
    def emoji(self) -> str:
        return TRAFFIC_LIGHT[self.status][0]

    @property
    def label(self) -> str:
        return TRAFFIC_LIGHT[self.status][1]

    @property
    def description(self) -> str:
        return TRAFFIC_LIGHT[self.status][2]

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol.value,
            "status": self.status.value,
            "label": self.label,
            "pqc_algorithms": self.pqc_algorithms,
            "classical_algorithms": self.classical_algorithms,
            "all_algorithms": self.all_algorithms,
            "error": self.error,
            "resolved_ip": self.resolved_ip,
            "hostname": self.hostname,
        }


def _detect_protocol(host: str, port: int, timeout: float) -> Protocol:
    """Attempt to detect protocol by port hint and banner grab."""
    hint = PORT_HINTS.get(port)
    if hint:
        return hint

    # Try TLS handshake
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return Protocol.TLS
    except ssl.SSLError:
        return Protocol.TLS  # TLS port but cert issue — still TLS
    except Exception:
        pass

    # Try SSH banner
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            banner = s.recv(32).decode("ascii", errors="ignore")
            if banner.startswith("SSH-"):
                return Protocol.SSH
    except Exception:
        pass

    return Protocol.UNKNOWN


def _collect_ssh_algorithms(r: SSHResult) -> list[str]:
    algs: list[str] = []
    algs.extend(r.kex_algorithms)
    algs.extend(r.host_key_algorithms)
    algs.extend(r.encryption_algorithms_client)
    algs.extend(r.encryption_algorithms_server)
    algs.extend(r.mac_algorithms)
    return algs


def scan(
    host: str,
    port: int,
    protocol: Optional[str] = None,
    timeout: float = 10.0,
    prefer_sslyze: bool = True,
    prefer_asyncssh: bool = False,
) -> ScanResult:
    """
    Scan a host:port and return a PQC-classified ScanResult.

    Parameters
    ----------
    host:            Target hostname or IP address.
    port:            Target port number.
    protocol:        Force protocol ("tls", "ssh", "ike"). Auto-detected if None.
    timeout:         Socket timeout in seconds.
    prefer_sslyze:   Use sslyze for TLS probing when available.
    prefer_asyncssh: Use asyncssh for SSH probing when available.
    """
    if protocol:
        detected = Protocol(protocol.lower())
    else:
        detected = _detect_protocol(host, port, timeout)

    all_algorithms: list[str] = []
    tls_result: Optional[TLSResult] = None
    ssh_result: Optional[SSHResult] = None
    ike_result: Optional[IKEResult] = None
    error: Optional[str] = None

    if detected == Protocol.TLS:
        tls_result = probe_tls(host, port, timeout, prefer_sslyze)
        if tls_result.success:
            algs = tls_result.kex_algorithms + tls_result.cipher_suites
            if tls_result.certificate_sig_alg:
                algs.append(tls_result.certificate_sig_alg)
            all_algorithms = algs
        else:
            error = tls_result.error

    elif detected == Protocol.SSH:
        ssh_result = probe_ssh(host, port, timeout, prefer_asyncssh)
        if ssh_result.success:
            all_algorithms = _collect_ssh_algorithms(ssh_result)
        else:
            error = ssh_result.error

    elif detected == Protocol.IKE:
        ike_result = probe_ike(host, port, timeout)
        if ike_result.success:
            all_algorithms = ike_result.dh_groups + ike_result.encr_transforms
        else:
            error = ike_result.error

    elif detected == Protocol.OPENVPN:
        error = f"OpenVPN ({host}:{port}) cannot be probed for PQC (tls-crypt prevents inspection)"
    elif detected == Protocol.WIREGUARD:
        error = f"WireGuard ({host}:{port}) cannot be probed for PQC (Noise protocol handshake is opaque)"
    else:
        error = f"Could not detect protocol on {host}:{port}"

    # Deduplicate
    seen: set[str] = set()
    unique_algs: list[str] = []
    for a in all_algorithms:
        if a and a not in seen:
            seen.add(a)
            unique_algs.append(a)

    pqc_algs = [a for a in unique_algs if is_pqc(a)]
    classical_algs = [a for a in unique_algs if not is_pqc(a)]
    status = classify(unique_algs)

    resolved_ip, hostname = _resolve_host_info(host)

    return ScanResult(
        host=host,
        port=port,
        protocol=detected,
        status=status,
        pqc_algorithms=pqc_algs,
        classical_algorithms=classical_algs,
        all_algorithms=unique_algs,
        tls=tls_result,
        ssh=ssh_result,
        ike=ike_result,
        error=error,
        resolved_ip=resolved_ip,
        hostname=hostname,
    )
