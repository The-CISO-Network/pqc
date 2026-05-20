"""
PQC algorithm taxonomy and classification logic.

Sources:
  - NIST PQC standards (FIPS 203/204/205)
  - IETF drafts for hybrid TLS/SSH key exchange
  - OpenSSH PQC KEX names
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet, List


class PQCStatus(Enum):
    """Binary classification for PQC readiness."""
    NO_PQC = "no_pqc"           # 🔴 No post-quantum algorithms detected
    PQC_AVAILABLE = "pqc_available"  # 🟢 At least one PQC algorithm detected


@dataclass(frozen=True)
class Algorithm:
    name: str
    is_pqc: bool
    category: str  # "kex", "auth", "cipher", "mac"
    description: str


# ---------------------------------------------------------------------------
# Known PQC key-exchange algorithms
# ---------------------------------------------------------------------------
PQC_KEX_ALGORITHMS: FrozenSet[str] = frozenset({
    # NIST ML-KEM (CRYSTALS-Kyber) hybrids — TLS 1.3
    "x25519kyber768draft00",
    "x25519_kyber768",
    "secp256r1_kyber768",
    "x25519kyber512draft00",
    "X25519Kyber768Draft00",
    "x25519Kyber768",
    "SecP256r1Kyber768",
    # IANA-assigned (final ML-KEM hybrids and pure ML-KEM)
    "mlkem512",
    "mlkem768",
    "mlkem1024",
    "x25519mlkem768",
    "secp256r1mlkem768",
    "secp384r1mlkem1024",
    "x25519_mlkem768",
    "secp256r1_mlkem768",
    "secp384r1_mlkem1024",
    # OpenSSH PQC KEX
    "mlkem768x25519-sha256",
    "sntrup761x25519-sha512@openssh.com",
    "sntrup4591761x25519-sha512@tinyssh.org",
    # IKEv2 / VPN
    "kyber512",
    "kyber768",
    "kyber1024",
    "bike1",
    "bike2",
    "hqc128",
    "hqc192",
    "hqc256",
    "frodokem640",
    "frodokem976",
    "frodokem1344",
    # NTRU
    "ntruhps2048509",
    "ntruhps2048677",
    "ntruhrss701",
})

# PQC signature/auth algorithms
PQC_AUTH_ALGORITHMS: FrozenSet[str] = frozenset({
    # ML-DSA (CRYSTALS-Dilithium)
    "mldsa44",
    "mldsa65",
    "mldsa87",
    "dilithium2",
    "dilithium3",
    "dilithium5",
    # SLH-DSA (SPHINCS+)
    "slhdsa_sha2_128s",
    "slhdsa_sha2_128f",
    "slhdsa_sha2_192s",
    "slhdsa_sha2_256s",
    "sphincssha256128fsimple",
    "sphincssha256128ssimple",
    # FN-DSA (FALCON)
    "fndsa512",
    "fndsa1024",
    "falcon512",
    "falcon1024",
    # SSH certificate types
    "ssh-mldsa65",
    "ssh-falcon512",
})

ALL_PQC_ALGORITHMS: FrozenSet[str] = PQC_KEX_ALGORITHMS | PQC_AUTH_ALGORITHMS

# Classical algorithms (well-known, non-exhaustive — used for sanity checks)
CLASSICAL_KEX: FrozenSet[str] = frozenset({
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group-exchange-sha256",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "x25519",
    "P-256",
    "P-384",
    "P-521",
    "X25519",
    "secp256r1",
    "secp384r1",
    "secp521r1",
})


def normalise(name: str) -> str:
    """Lowercase and strip whitespace for consistent matching."""
    return name.strip().lower()


# Normalised set for O(1) exact matching
ALL_PQC_ALGORITHMS_NORMALISED: FrozenSet[str] = frozenset(
    normalise(a) for a in ALL_PQC_ALGORITHMS
)


def is_pqc(algorithm_name: str) -> bool:
    return normalise(algorithm_name) in ALL_PQC_ALGORITHMS_NORMALISED


def classify(algorithms: List[str]) -> PQCStatus:
    """
    Given a list of algorithm names, return the PQC status.

    🔴 NO_PQC        — none of the algorithms are PQC
    🟢 PQC_AVAILABLE — at least one PQC algorithm was detected
    """
    if not algorithms:
        return PQCStatus.NO_PQC

    if any(is_pqc(a) for a in algorithms):
        return PQCStatus.PQC_AVAILABLE

    return PQCStatus.NO_PQC


TRAFFIC_LIGHT = {
    PQCStatus.NO_PQC:        ("🔴", "NO PQC",        "No post-quantum algorithms detected. Vulnerable to harvest-now-decrypt-later attacks."),
    PQCStatus.PQC_AVAILABLE: ("🟢", "PQC OK", "Post-quantum algorithms detected."),
}
