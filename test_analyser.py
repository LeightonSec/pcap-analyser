"""
PCAP Analyser — Detection Test Suite

Generates test PCAP files via generate_test_pcaps.py, then runs analyse_pcap()
against each and verifies the expected threat type appears in results.

Both generation and parsing use scapy (analyser.py reads PCAPs with
scapy's PcapReader), so the only requirement is:
  - scapy must be installed (pip install scapy)
No external tshark/wireshark install is needed to run these tests.
"""

from analyser import analyse_pcap
from generate_test_pcaps import (
    XSS_DNS_PAYLOAD,
    generate_arp_spoof,
    generate_c2_beacon,
    generate_dns_tunnel,
    generate_dos,
    generate_icmp_flood,
    generate_port_scan,
    generate_syn_flood,
)

TEST_PCAPS = {
    "syn_flood":  "test_syn_flood.pcap",
    "port_scan":  "test_port_scan.pcap",
    "arp_spoof":  "test_arp_spoof.pcap",
    "dos":        "test_dos.pcap",
    "icmp_flood": "test_icmp_flood.pcap",
    "dns_tunnel": "test_dns_tunnel.pcap",
    "c2_beacon":  "test_c2_beacon.pcap",
}


def setup_module(module):
    generate_syn_flood(TEST_PCAPS["syn_flood"])
    generate_port_scan(TEST_PCAPS["port_scan"])
    generate_arp_spoof(TEST_PCAPS["arp_spoof"])
    generate_dos(TEST_PCAPS["dos"])
    generate_icmp_flood(TEST_PCAPS["icmp_flood"])
    generate_dns_tunnel(TEST_PCAPS["dns_tunnel"])
    generate_c2_beacon(TEST_PCAPS["c2_beacon"])


def _has_threat(result, threat_type):
    return any(t["type"] == threat_type for t in result.get("threats", []))

def _threat_types(result):
    return [t["type"] for t in result.get("threats", [])]

def _threat_of_type(result, threat_type):
    return next((t for t in result.get("threats", []) if t["type"] == threat_type), None)


def test_syn_flood():
    result = analyse_pcap(TEST_PCAPS["syn_flood"])
    assert _has_threat(result, "SYN Flood"), \
        f"Expected SYN Flood — threats found: {_threat_types(result)}"

def test_port_scan():
    result = analyse_pcap(TEST_PCAPS["port_scan"])
    assert _has_threat(result, "Port Scan"), \
        f"Expected Port Scan — threats found: {_threat_types(result)}"

def test_arp_spoof():
    result = analyse_pcap(TEST_PCAPS["arp_spoof"])
    assert _has_threat(result, "ARP Spoofing"), \
        f"Expected ARP Spoofing — threats found: {_threat_types(result)}"

def test_dos():
    result = analyse_pcap(TEST_PCAPS["dos"])
    assert _has_threat(result, "DoS/DDoS"), \
        f"Expected DoS/DDoS — threats found: {_threat_types(result)}"

def test_icmp_flood():
    result = analyse_pcap(TEST_PCAPS["icmp_flood"])
    assert _has_threat(result, "ICMP Flood"), \
        f"Expected ICMP Flood — threats found: {_threat_types(result)}"
    # Isolated fixture (150 ICMP packets) stays below the DoS threshold (1000).
    assert not _has_threat(result, "DoS/DDoS"), \
        "ICMP flood fixture should not also trip the DoS detector"

def test_dns_tunnel():
    result = analyse_pcap(TEST_PCAPS["dns_tunnel"])
    assert _has_threat(result, "DNS Tunnelling"), \
        f"Expected DNS Tunnelling — threats found: {_threat_types(result)}"

def test_dns_tunnel_preserves_raw_query_in_detail():
    """Stored/DOM XSS regression anchor.

    Proves an attacker-controlled DNS query name reaches threat["detail"]
    unmodified — the field interpolated into the dashboard's innerHTML. The
    sanitisation is client-side (templates/index.html escapeHtml); this test
    pins the source end of the source -> sink path so the threat surface is
    documented and the fixture stays meaningful.
    """
    result = analyse_pcap(TEST_PCAPS["dns_tunnel"])
    threat = _threat_of_type(result, "DNS Tunnelling")
    assert threat is not None, \
        f"Expected DNS Tunnelling — threats found: {_threat_types(result)}"
    assert XSS_DNS_PAYLOAD in threat["detail"], \
        f"Raw query name should reach detail intact; got: {threat['detail']!r}"

def test_c2_beacon():
    result = analyse_pcap(TEST_PCAPS["c2_beacon"])
    assert _has_threat(result, "C2 Beaconing"), \
        f"Expected C2 Beaconing — threats found: {_threat_types(result)}"
