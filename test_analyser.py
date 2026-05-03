"""
PCAP Analyser — Detection Test Suite

Generates test PCAP files via generate_test_pcaps.py, then runs analyse_pcap()
against each and verifies the expected threat type appears in results.

Requirements:
  - scapy must be installed to generate test PCAPs (pip install scapy)
  - tshark must be installed for pyshark to parse them (brew install wireshark)
  - Run this file directly — it generates PCAPs then immediately tests them

Tests check that the expected threat TYPE is present in results, not exact counts.
Detection counts vary by capture content; type presence is the meaningful signal.
"""

import os
from analyser import analyse_pcap
from generate_test_pcaps import (
    generate_syn_flood,
    generate_port_scan,
    generate_arp_spoof,
    generate_dos,
    generate_c2_beacon,
)

TEST_PCAPS = {
    "syn_flood":   "test_syn_flood.pcap",
    "port_scan":   "test_port_scan.pcap",
    "arp_spoof":   "test_arp_spoof.pcap",
    "dos":         "test_dos.pcap",
    "c2_beacon":   "test_c2_beacon.pcap",
}


def setup_test_pcaps():
    print("Generating test PCAP files...\n")
    generate_syn_flood(TEST_PCAPS["syn_flood"])
    generate_port_scan(TEST_PCAPS["port_scan"])
    generate_arp_spoof(TEST_PCAPS["arp_spoof"])
    generate_dos(TEST_PCAPS["dos"])
    generate_c2_beacon(TEST_PCAPS["c2_beacon"])
    print()


def _has_threat(result, threat_type):
    return any(t["type"] == threat_type for t in result.get("threats", []))

def _threat_detail(result, threat_type):
    for t in result.get("threats", []):
        if t["type"] == threat_type:
            return t.get("detail", "")
    return ""


def test_syn_flood():
    result = analyse_pcap(TEST_PCAPS["syn_flood"])
    passed = _has_threat(result, "SYN Flood")
    return passed, result, "SYN Flood"

def test_port_scan():
    result = analyse_pcap(TEST_PCAPS["port_scan"])
    passed = _has_threat(result, "Port Scan")
    return passed, result, "Port Scan"

def test_arp_spoof():
    result = analyse_pcap(TEST_PCAPS["arp_spoof"])
    passed = _has_threat(result, "ARP Spoofing")
    return passed, result, "ARP Spoofing"

def test_dos():
    result = analyse_pcap(TEST_PCAPS["dos"])
    passed = _has_threat(result, "DoS/DDoS")
    return passed, result, "DoS/DDoS"

def test_c2_beacon():
    result = analyse_pcap(TEST_PCAPS["c2_beacon"])
    passed = _has_threat(result, "C2 Beaconing")
    return passed, result, "C2 Beaconing"


TESTS = [
    ("SYN Flood",    test_syn_flood),
    ("Port Scan",    test_port_scan),
    ("ARP Spoofing", test_arp_spoof),
    ("DoS/DDoS",     test_dos),
    ("C2 Beaconing", test_c2_beacon),
]


def run_tests():
    setup_test_pcaps()

    passed_count = 0
    failed_count = 0
    failures = []

    print("=== PCAP Analyser Test Suite ===\n")

    for description, test_fn in TESTS:
        passed, result, threat_type = test_fn()

        status = "✅ PASS" if passed else "❌ FAIL"
        if passed:
            passed_count += 1
        else:
            failed_count += 1
            failures.append(description)

        detail = _threat_detail(result, threat_type)
        all_types = [t["type"] for t in result.get("threats", [])]

        print(f"{status} | {description}")
        print(f"       Packets analysed: {result.get('packet_count', 0)}")
        print(f"       Threats found: {all_types if all_types else 'None'}")
        if passed and detail:
            print(f"       Detail: {detail}")
        print()

    print(f"--- Results: {passed_count}/{len(TESTS)} passed ---")

    if failures:
        print("\nFailures:")
        for desc in failures:
            print(f"  • {desc}")

    print()
    return passed_count, failed_count


if __name__ == "__main__":
    run_tests()
