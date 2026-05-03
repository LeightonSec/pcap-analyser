import logging
from collections import defaultdict
from datetime import datetime, timezone
from scapy.all import PcapReader, IP, TCP, ICMP, ARP, DNS

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Detection thresholds
THRESHOLDS = {
    "dos_packet_count": 1000,      # packets from single IP within dos_window_seconds
    # 10s chosen because legitimate bursts (video, large transfers) rarely sustain
    # 1000 pps for a full 10 seconds — that duration is the meaningful signal
    "dos_window_seconds": 10,
    "syn_flood_count": 100,         # SYN packets without ACK
    "icmp_flood_count": 100,        # ICMP packets from single IP
    "port_scan_count": 20,          # unique ports hit by single IP
    "beacon_interval_tolerance": 5, # seconds variance for beaconing
    # 20 packets required before beaconing is flagged — keep-alives, NTP, and streaming
    # all produce regular intervals at low packet counts; volume reduces false positive rate
    "beacon_min_packets": 20,
    "dns_query_length": 50,         # suspicious long DNS query
}

def analyse_pcap(filepath: str) -> dict:
    """Main analysis function — runs all detectors on a PCAP file"""
    logger.info(f"Starting analysis: {filepath}")

    # Packet counters and trackers
    ip_packet_count = defaultdict(list)
    syn_count = defaultdict(int)
    icmp_count = defaultdict(int)
    ip_ports = defaultdict(set)
    arp_ip_to_macs = defaultdict(set)
    connection_times = defaultdict(list)
    dns_queries = []

    threats = []
    packet_count = 0

    try:
        with PcapReader(filepath) as packets:
            for packet in packets:
                packet_count += 1

                try:
                    # Track IP traffic volume
                    if packet.haslayer(IP):
                        src = packet[IP].src
                        dst = packet[IP].dst
                        ip_packet_count[src].append(float(packet.time))

                        # TCP analysis
                        if packet.haslayer(TCP):
                            ip_ports[src].add(packet[TCP].dport)

                            # SYN flood detection — scapy flags are pre-parsed, no hex conversion needed
                            if packet[TCP].flags.S and not packet[TCP].flags.A:
                                syn_count[src] += 1

                            # Beaconing detection
                            connection_times[f"{src}-{dst}"].append(float(packet.time))

                        # ICMP flood detection
                        if packet.haslayer(ICMP):
                            icmp_count[src] += 1

                        # DNS tunnelling detection
                        if packet.haslayer(DNS) and packet[DNS].qd:
                            query = packet[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                            if len(query) > THRESHOLDS["dns_query_length"]:
                                dns_queries.append({"src": src, "query": query})

                    # ARP spoofing detection
                    if packet.haslayer(ARP):
                        arp_ip_to_macs[packet[ARP].psrc].add(packet[ARP].hwsrc)

                except Exception as e:
                    logger.debug(f'Error parsing packet {packet_count}: {e}')
                    continue

    except Exception as e:
        logger.error(f"Error reading PCAP: {e}")
        return {"error": str(e), "threats": [], "packet_count": 0}

    # ── Run detectors ──────────────────────────────────────────────────

    # DoS detection — sliding window
    dos_threshold = THRESHOLDS["dos_packet_count"]
    dos_window = THRESHOLDS["dos_window_seconds"]
    for ip, timestamps in ip_packet_count.items():
        if len(timestamps) < dos_threshold:
            continue
        timestamps.sort()
        max_in_window = 0
        left = 0
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > dos_window:
                left += 1
            max_in_window = max(max_in_window, right - left + 1)
        if max_in_window >= dos_threshold:
            threats.append({
                "type": "DoS/DDoS",
                "severity": "HIGH",
                "src_ip": ip,
                "detail": f"{max_in_window} packets in {dos_window}s window from single source",
                "recommendation": "Block IP, investigate traffic source"
            })

    # SYN flood detection
    for ip, count in syn_count.items():
        if count >= THRESHOLDS["syn_flood_count"]:
            threats.append({
                "type": "SYN Flood",
                "severity": "HIGH",
                "src_ip": ip,
                "detail": f"{count} SYN packets without ACK",
                "recommendation": "Enable SYN cookies, block IP"
            })

    # ICMP flood detection
    for ip, count in icmp_count.items():
        if count >= THRESHOLDS["icmp_flood_count"]:
            threats.append({
                "type": "ICMP Flood",
                "severity": "MEDIUM",
                "src_ip": ip,
                "detail": f"{count} ICMP packets from single source",
                "recommendation": "Rate limit ICMP traffic"
            })

    # Port scan detection
    for ip, ports in ip_ports.items():
        if len(ports) >= THRESHOLDS["port_scan_count"]:
            threats.append({
                "type": "Port Scan",
                "severity": "MEDIUM",
                "src_ip": ip,
                "detail": f"Scanned {len(ports)} unique ports",
                "recommendation": "Block IP, review firewall rules"
            })

    # ARP spoofing detection
    for ip, macs in arp_ip_to_macs.items():
        if len(macs) > 1:
            threats.append({
                "type": "ARP Spoofing",
                "severity": "HIGH",
                "src_ip": ip,
                "detail": f"IP {ip} claimed by {len(macs)} different MACs: {', '.join(macs)}",
                "recommendation": "Investigate MitM attack, enable dynamic ARP inspection"
            })

    # DNS tunnelling detection
    for entry in dns_queries:
        threats.append({
            "type": "DNS Tunnelling",
            "severity": "MEDIUM",
            "src_ip": entry["src"],
            "detail": f"Suspicious DNS query length: {entry['query'][:80]}",
            "recommendation": "Inspect DNS traffic, check for data exfiltration"
        })

    # Beaconing detection
    # NOTE: elevated false positive risk on busy captures — keep-alives, NTP, video streaming,
    # and background OS traffic all exhibit regular intervals. Treat matches as indicators
    # requiring analyst review, not confirmed threats.
    for connection, times in connection_times.items():
        if len(times) < THRESHOLDS["beacon_min_packets"]:
            continue
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        if len(intervals) < 10:
            continue
        avg_interval = sum(intervals) / len(intervals)
        variance = sum(abs(i - avg_interval) for i in intervals) / len(intervals)
        if avg_interval > 1.0 and variance < THRESHOLDS["beacon_interval_tolerance"] and avg_interval < 60:
            src, dst = connection.split("-", 1)
            threats.append({
                "type": "C2 Beaconing",
                "severity": "HIGH",
                "src_ip": src,
                "detail": f"Regular connections to {dst} every ~{avg_interval:.1f}s",
                "recommendation": "Isolate host, investigate C2 communication"
            })

    logger.info(f"Analysis complete — {packet_count} packets, {len(threats)} threats found")

    return {
        "packet_count": packet_count,
        "threats": threats,
        "threat_count": len(threats),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "filepath": filepath
    }