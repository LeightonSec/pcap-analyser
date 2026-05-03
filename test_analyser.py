"""
PCAP Analyser — Detection Test Suite

Generates test PCAP files via generate_test_pcaps.py, then runs analyse_pcap()
against each and verifies the expected threat type appears in results.

Requirements:
  - scapy must be installed to generate test PCAPs (pip install scapy)
  - tshark must be installed for pyshark to parse them (brew install wireshark)
"""

from analyser import analyse_pcap
from generate_test_pcaps import (
    generate_syn_flood,
    generate_port_scan,
    generate_arp_spoof,
    generate_dos,
    generate_c2_beacon,
)

TEST_PCAPS = {
    "syn_flood": "test_syn_flood.pcap",
    "port_scan": "test_port_scan.pcap",
    "arp_spoof": "test_arp_spoof.pcap",
    "dos":       "test_dos.pcap",
    "c2_beacon": "test_c2_beacon.pcap",
}


def setup_module(module):
    generate_syn_flood(TEST_PCAPS["syn_flood"])
    generate_port_scan(TEST_PCAPS["port_scan"])
    generate_arp_spoof(TEST_PCAPS["arp_spoof"])
    generate_dos(TEST_PCAPS["dos"])
    generate_c2_beacon(TEST_PCAPS["c2_beacon"])


def _has_threat(result, threat_type):
    return any(t["type"] == threat_type for t in result.get("threats", []))

def _threat_types(result):
    return [t["type"] for t in result.get("threats", [])]


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

def test_c2_beacon():
    result = analyse_pcap(TEST_PCAPS["c2_beacon"])
    assert _has_threat(result, "C2 Beaconing"), \
        f"Expected C2 Beaconing — threats found: {_threat_types(result)}"
