"""
VPN / IKEv2 protocol prober.

Sends an IKEv2 SA_INIT request and parses the SA payload to extract
supported transforms (encryption, PRF, integrity, DH groups).

No third-party dependency required — uses raw UDP sockets.

IKEv2 reference: RFC 7296
"""

from __future__ import annotations

import os
import socket
import struct
import logging
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# IKEv2 constants
# ---------------------------------------------------------------------------
IKE_VERSION = 0x20  # IKEv2
EXCHANGE_TYPE_SA_INIT = 34
FLAG_INITIATOR = 0x08

# Transform types
TRANSFORM_TYPE_ENCR = 1   # Encryption
TRANSFORM_TYPE_PRF = 2    # Pseudorandom function
TRANSFORM_TYPE_INTEG = 3  # Integrity
TRANSFORM_TYPE_DH = 4     # Diffie-Hellman group
TRANSFORM_TYPE_ESN = 5    # Extended sequence numbers

# Selected PQC-related DH groups (IANA assignments / drafts)
PQC_DH_GROUPS: dict[int, str] = {
    # NIST PQC hybrids (draft-ietf-ipsecme-ikev2-mlkem)
    35: "kyber512",
    36: "kyber768",
    37: "kyber1024",
    38: "x25519kyber768",
    39: "x25519kyber1024",
    43: "mlkem512",
    44: "mlkem768",
    45: "mlkem1024",
    46: "x25519_mlkem768",
    47: "secp256r1_mlkem768",
    48: "secp384r1_mlkem1024",
}

KNOWN_DH_GROUPS: dict[int, str] = {
    1: "modp768",
    2: "modp1024",
    5: "modp1536",
    14: "modp2048",
    15: "modp3072",
    16: "modp4096",
    19: "ecp256",
    20: "ecp384",
    21: "ecp521",
    25: "ecp192",
    26: "ecp224",
    27: "brainpoolP224r1",
    28: "brainpoolP256r1",
    29: "brainpoolP384r1",
    30: "brainpoolP512r1",
    31: "curve25519",
    32: "curve448",
    33: "gost3410_2012_256",
    34: "gost3410_2012_512",
    **PQC_DH_GROUPS,
}


@dataclass
class IKEResult:
    host: str
    port: int
    success: bool
    dh_groups: list[str] = field(default_factory=list)
    encr_transforms: list[str] = field(default_factory=list)
    integ_transforms: list[str] = field(default_factory=list)
    prf_transforms: list[str] = field(default_factory=list)
    raw_dh_ids: list[int] = field(default_factory=list)
    error: Optional[str] = None


def _build_sa_init() -> bytes:
    """Build a minimal IKEv2 IKE_SA_INIT request with a broad SA proposal."""

    initiator_spi = os.urandom(8)
    responder_spi = b"\x00" * 8
    msg_id = 0

    # Build transforms for one proposal
    def transform(t_type: int, t_id: int, attrs: bytes = b"") -> bytes:
        # Last transform in group has 0 for more, others have 3
        payload = struct.pack(">BBH", t_type, 0, t_id) + attrs
        length = 4 + len(payload)
        return struct.pack(">BBH", 3, 0, length) + payload  # more=3 (not last)

    def last_transform(t_type: int, t_id: int, attrs: bytes = b"") -> bytes:
        payload = struct.pack(">BBH", t_type, 0, t_id) + attrs
        length = 4 + len(payload)
        return struct.pack(">BBH", 0, 0, length) + payload  # more=0 (last)

    # Key length attribute for AES: type=14, value=256
    aes_keylen_attr = struct.pack(">HH", 0x800E, 256)

    transforms = (
        transform(TRANSFORM_TYPE_ENCR, 12, aes_keylen_attr)  # AES-CBC-256
        + transform(TRANSFORM_TYPE_PRF, 2)                   # PRF-HMAC-SHA1
        + transform(TRANSFORM_TYPE_INTEG, 2)                 # AUTH-HMAC-SHA1-96
        + last_transform(TRANSFORM_TYPE_DH, 14)              # MODP-2048
    )

    # Proposal substructure
    proposal_num = 1
    proposal_id = 1  # IKE
    spi_size = 0
    num_transforms = 4
    proposal_body = struct.pack(">BBBBBB", proposal_num, proposal_id, spi_size, num_transforms, 0, 0) + transforms
    prop_len = 4 + len(proposal_body)
    proposal = struct.pack(">BBH", 0, 0, prop_len) + proposal_body  # last proposal

    # SA payload (type 33)
    sa_body = proposal
    sa_len = 4 + len(sa_body)
    sa_payload_next = 40  # KE payload follows (simplified: we'll omit for detection)
    sa_payload = struct.pack(">BBH", 0, 0, sa_len) + sa_body  # next=0 (last), critical=0

    # Minimal Nonce payload (type 40)
    nonce = os.urandom(32)
    nonce_len = 4 + len(nonce)
    nonce_payload = struct.pack(">BBH", 0, 0, nonce_len) + nonce

    # Compose payloads — SA (33) -> Nonce (40)
    # Re-build with correct next-payload chaining
    nonce_payload_final = struct.pack(">BBH", 0, 0, nonce_len) + nonce
    sa_payload_final = struct.pack(">BBH", 40, 0, sa_len) + sa_body  # next=40 (Nonce)

    payloads = sa_payload_final + nonce_payload_final
    total_length = 28 + len(payloads)

    header = (
        initiator_spi
        + responder_spi
        + struct.pack(">B", 33)   # next payload: SA
        + struct.pack(">B", IKE_VERSION)
        + struct.pack(">B", EXCHANGE_TYPE_SA_INIT)
        + struct.pack(">B", FLAG_INITIATOR)
        + struct.pack(">I", msg_id)
        + struct.pack(">I", total_length)
    )
    return header + payloads


def _parse_sa_response(data: bytes) -> tuple[list[int], list[str], list[str], list[str]]:
    """Parse IKEv2 response and extract DH groups and other transforms."""
    dh_ids: list[int] = []
    encr: list[str] = []
    integ: list[str] = []
    prf: list[str] = []

    if len(data) < 28:
        return dh_ids, encr, integ, prf

    # Walk payloads starting at byte 28
    next_payload = data[16]
    offset = 28

    while offset < len(data) and next_payload != 0:
        if offset + 4 > len(data):
            break
        next_payload = data[offset]
        critical = data[offset + 1]
        payload_len = struct.unpack_from(">H", data, offset + 2)[0]
        payload_data = data[offset + 4: offset + payload_len]
        payload_type = next_payload  # will be overwritten next iteration

        if next_payload == 33:  # SA payload
            # Parse proposals and transforms
            prop_offset = 0
            while prop_offset < len(payload_data):
                if prop_offset + 4 > len(payload_data):
                    break
                more_props = payload_data[prop_offset]
                prop_len = struct.unpack_from(">H", payload_data, prop_offset + 2)[0]
                prop_body = payload_data[prop_offset + 4: prop_offset + prop_len]

                if len(prop_body) >= 6:
                    num_transforms = prop_body[3]
                    t_offset = 6 + prop_body[2]  # skip SPI

                    for _ in range(num_transforms):
                        if t_offset + 8 > len(prop_body):
                            break
                        t_more = prop_body[t_offset]
                        t_len = struct.unpack_from(">H", prop_body, t_offset + 2)[0]
                        t_type = prop_body[t_offset + 4]
                        t_id = struct.unpack_from(">H", prop_body, t_offset + 6)[0]

                        if t_type == TRANSFORM_TYPE_DH:
                            dh_ids.append(t_id)
                        elif t_type == TRANSFORM_TYPE_ENCR:
                            encr.append(f"ENCR_{t_id}")
                        elif t_type == TRANSFORM_TYPE_INTEG:
                            integ.append(f"INTEG_{t_id}")
                        elif t_type == TRANSFORM_TYPE_PRF:
                            prf.append(f"PRF_{t_id}")

                        t_offset += t_len if t_len >= 8 else 8
                        if t_more == 0:
                            break

                if more_props == 0:
                    break
                prop_offset += prop_len

        next_payload = data[offset]
        offset += payload_len

    return dh_ids, encr, integ, prf


def probe_ike(host: str, port: int = 500, timeout: float = 5.0) -> IKEResult:
    """
    Send an IKEv2 IKE_SA_INIT and parse the SA response.

    Works on UDP port 500 (IKEv2) or 4500 (NAT-T).
    """
    result = IKEResult(host=host, port=port, success=False)

    try:
        packet = _build_sa_init()

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (host, port))
            response, _ = sock.recvfrom(65535)

        if len(response) < 28:
            result.error = "Response too short to be IKEv2"
            return result

        dh_ids, encr, integ, prf = _parse_sa_response(response)
        result.raw_dh_ids = dh_ids
        result.dh_groups = [KNOWN_DH_GROUPS.get(gid, f"group{gid}") for gid in dh_ids]
        result.encr_transforms = encr
        result.integ_transforms = integ
        result.prf_transforms = prf
        result.success = True

    except socket.timeout:
        result.error = "Timeout — no IKEv2 response (port closed or filtered)"
    except Exception as exc:
        result.error = str(exc)

    return result
