"""Test suite for pqc."""

import pytest
from unittest.mock import patch, MagicMock

from pqc.algorithms import classify, is_pqc, PQCStatus, TRAFFIC_LIGHT
from pqc.scanner import Protocol, _detect_protocol


# ---------------------------------------------------------------------------
# Algorithm classification
# ---------------------------------------------------------------------------

class TestPQCClassification:
    def test_no_pqc_classical_only(self):
        algs = ["curve25519-sha256", "ecdh-sha2-nistp256", "aes128-ctr"]
        assert classify(algs) == PQCStatus.NO_PQC

    def test_pqc_available_mix(self):
        algs = ["curve25519-sha256", "mlkem768x25519-sha256", "aes256-ctr"]
        assert classify(algs) == PQCStatus.PQC_AVAILABLE

    def test_pqc_available_pure(self):
        algs = ["mlkem768x25519-sha256", "sntrup761x25519-sha512@openssh.com"]
        assert classify(algs) == PQCStatus.PQC_AVAILABLE

    def test_empty_list(self):
        assert classify([]) == PQCStatus.NO_PQC

    def test_unknown_algorithms_treated_as_classical(self):
        algs = ["some-unknown-cipher", "another-unknown-kex"]
        assert classify(algs) == PQCStatus.NO_PQC


class TestIsPQC:
    @pytest.mark.parametrize("alg", [
        "mlkem768x25519-sha256",
        "sntrup761x25519-sha512@openssh.com",
        "x25519kyber768draft00",
        "kyber768",
        "mldsa65",
        "falcon512",
    ])
    def test_known_pqc(self, alg):
        assert is_pqc(alg), f"{alg} should be PQC"

    @pytest.mark.parametrize("alg", [
        "curve25519-sha256",
        "ecdh-sha2-nistp256",
        "aes256-ctr",
        "rsa-sha2-256",
        "diffie-hellman-group14-sha256",
    ])
    def test_known_classical(self, alg):
        assert not is_pqc(alg), f"{alg} should NOT be PQC"


class TestTrafficLight:
    def test_all_statuses_have_entries(self):
        for status in PQCStatus:
            assert status in TRAFFIC_LIGHT
            emoji, label, desc = TRAFFIC_LIGHT[status]
            assert emoji
            assert label
            assert desc


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class TestScanner:
    def test_scan_result_to_dict(self):
        from pqc.scanner import ScanResult, Protocol
        result = ScanResult(
            host="example.com",
            port=443,
            protocol=Protocol.TLS,
            status=PQCStatus.NO_PQC,
        )
        d = result.to_dict()
        assert d["host"] == "example.com"
        assert d["port"] == 443
        assert d["status"] == "no_pqc"

    def test_scan_result_properties(self):
        from pqc.scanner import ScanResult, Protocol
        result = ScanResult(
            host="example.com",
            port=443,
            protocol=Protocol.TLS,
            status=PQCStatus.PQC_AVAILABLE,
        )
        assert result.emoji == "🟢"
        assert result.label == "PQC OK"


# ---------------------------------------------------------------------------
# TLS prober (stdlib path — no real network)
# ---------------------------------------------------------------------------

class TestTLSProber:
    def test_tls_result_fields(self):
        from pqc.protocols.tls import TLSResult
        r = TLSResult(host="example.com", port=443, success=False, error="timeout")
        assert r.host == "example.com"
        assert not r.success
        assert r.error == "timeout"


# ---------------------------------------------------------------------------
# SSH prober — raw parsing
# ---------------------------------------------------------------------------

class TestSSHRawParser:
    def test_name_list_parsing(self):
        from pqc.protocols.ssh import _read_name_list
        import struct
        names = b"curve25519-sha256,ecdh-sha2-nistp256"
        data = struct.pack(">I", len(names)) + names
        result, offset = _read_name_list(data, 0)
        assert "curve25519-sha256" in result
        assert "ecdh-sha2-nistp256" in result
        assert offset == 4 + len(names)

    def test_empty_name_list(self):
        from pqc.protocols.ssh import _read_name_list
        import struct
        data = struct.pack(">I", 0)
        result, _ = _read_name_list(data, 0)
        assert result == []


# ---------------------------------------------------------------------------
# Agent — unit tests (no real connections)
# ---------------------------------------------------------------------------

class TestAgent:
    def _make_agent(self, targets=None, scan_all=False, scan_local=False):
        from pqc.agent import Agent, AgentConfig
        cfg = AgentConfig(
            targets=targets or [],
            scan_all=scan_all,
            scan_local=scan_local,
            log_stdout=False,
        )
        return Agent(cfg)

    def test_is_watched_specific_target(self):
        agent = self._make_agent(targets=[("example.com", 443)])
        assert agent._is_watched("example.com", 443)
        assert not agent._is_watched("other.com", 443)
        assert not agent._is_watched("example.com", 22)

    def test_is_watched_scan_all(self):
        agent = self._make_agent(scan_all=True)
        assert agent._is_watched("anything.com", 9999)

    def test_cooldown(self):
        import time
        agent = self._make_agent(targets=[("example.com", 443)])
        agent.config.rescan_cooldown = 60.0
        assert not agent._in_cooldown("example.com", 443)
        agent._last_scanned[("example.com", 443)] = time.monotonic()
        assert agent._in_cooldown("example.com", 443)

    def test_no_targets_no_scan_all_is_noop(self):
        agent = self._make_agent()
        assert not agent._is_watched("example.com", 443)

    def test_scan_local_filters_non_local(self):
        agent = self._make_agent(scan_all=True, scan_local=True)
        assert agent._is_watched("192.168.1.1", 443)
        assert agent._is_watched("10.0.0.1", 80)
        assert agent._is_watched("127.0.0.1", 443)
        assert not agent._is_watched("8.8.8.8", 443)
        assert not agent._is_watched("1.1.1.1", 53)

    def test_scan_local_with_targets(self):
        agent = self._make_agent(targets=[("192.168.1.1", 443)], scan_local=True)
        assert agent._is_watched("192.168.1.1", 443)
        assert not agent._is_watched("8.8.8.8", 443)

    def test_scan_local_with_local_targets(self):
        agent = self._make_agent(targets=[("8.8.8.8", 443)], scan_local=True)
        assert not agent._is_watched("8.8.8.8", 443)

    def test_in_flight_prevents_duplicate_probes(self):
        agent = self._make_agent(scan_all=True)
        assert not agent._in_flight_check("1.2.3.4", 80)
        agent._in_flight.add(("1.2.3.4", 80))
        assert agent._in_flight_check("1.2.3.4", 80)
        assert not agent._in_flight_check("1.2.3.4", 443)

    def test_in_flight_cleared_after_probe(self):
        import threading
        from pqc.scanner import ScanResult, Protocol
        from pqc.algorithms import PQCStatus
        agent = self._make_agent(scan_all=True)
        probed = threading.Event()

        def mock_scan(*args, **kwargs):
            probed.set()
            return ScanResult(
                host="1.2.3.4",
                port=80,
                protocol=Protocol.UNKNOWN,
                status=PQCStatus.NO_PQC,
            )

        # Temporarily replace scan on the agent module path
        import pqc.agent as agent_mod
        orig_scan = agent_mod.scan
        agent_mod.scan = mock_scan
        try:
            t = threading.Thread(target=agent._probe, args=("1.2.3.4", 80))
            t.start()
            t.join(timeout=1)
            assert probed.is_set()
            assert ("1.2.3.4", 80) not in agent._in_flight
        finally:
            agent_mod.scan = orig_scan


class TestIsLocalAddress:
    def test_loopback_ipv4(self):
        from pqc.agent import _is_local_address
        assert _is_local_address("127.0.0.1")
        assert _is_local_address("127.0.0.53")

    def test_loopback_ipv6(self):
        from pqc.agent import _is_local_address
        assert _is_local_address("::1")

    def test_rfc1918_private(self):
        from pqc.agent import _is_local_address
        assert _is_local_address("10.0.0.1")
        assert _is_local_address("172.16.0.1")
        assert _is_local_address("172.31.255.255")
        assert _is_local_address("192.168.0.1")
        assert _is_local_address("192.168.255.255")

    def test_public_ips_are_not_local(self):
        from pqc.agent import _is_local_address
        assert not _is_local_address("8.8.8.8")
        assert not _is_local_address("1.1.1.1")
        assert not _is_local_address("104.16.133.229")

    def test_hostname_returns_false(self):
        from pqc.agent import _is_local_address
        assert not _is_local_address("example.com")
        assert not _is_local_address("localhost")


# ---------------------------------------------------------------------------
# IKE prober — packet construction sanity check
# ---------------------------------------------------------------------------

class TestIKEPacket:
    def test_build_sa_init_length(self):
        from pqc.protocols.ike import _build_sa_init
        pkt = _build_sa_init()
        assert len(pkt) >= 28, "IKEv2 packet must be at least 28 bytes (header)"

    def test_spi_is_random(self):
        from pqc.protocols.ike import _build_sa_init
        p1 = _build_sa_init()[:8]
        p2 = _build_sa_init()[:8]
        assert p1 != p2, "Initiator SPI should be random"

    def test_dh_group_names(self):
        from pqc.protocols.ike import KNOWN_DH_GROUPS, PQC_DH_GROUPS
        for gid in PQC_DH_GROUPS:
            assert gid in KNOWN_DH_GROUPS
