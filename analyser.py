import pyshark
import logging
from collections import defaultdict
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Detection thresholds
THRESHOLDS = {
    "dos_packet_count": 1000,      # packets from single IP
    "syn_flood_count": 100,         # SYN packets without ACK
    "icmp_flood_count": 100,        # ICMP packets from single IP
    "port_scan_count": 20,          # unique ports hit by single IP
    "beacon_interval_tolerance": 5, # seconds variance for beaconing
    "dns_query_length": 50,         # suspicious long DNS query
}

def analyse_pcap(filepath: str) -> dict:
    """Main analysis function — runs all detectors on a PCAP file"""
    logger.info(f"Starting analysis: {filepath}")

    # Packet counters and trackers
    ip_packet_count = defaultdict(int)
    syn_count = defaultdict(int)
    icmp_count = defaultdict(int)
    ip_ports = defaultdict(set)
    arp_ip_to_macs = defaultdict(set)
    connection_times = defaultdict(list)
    dns_queries = []

    threats = []
    packet_count = 0

    try:
        cap = pyshark.FileCapture(filepath, keep_packets=False)

        for packet in cap:
            packet_count += 1

            try:
                # Track IP traffic volume
                if hasattr(packet, 'ip'):
                    src = packet.ip.src
                    dst = packet.ip.dst
                    ip_packet_count[src] += 1

                    # TCP analysis
                    if hasattr(packet, 'tcp'):
                        dst_port = int(packet.tcp.dstport)
                        ip_ports[src].add(dst_port)

                        # SYN flood detection
                        try:
                            flags = int(packet.tcp.flags, 16)
                            syn = bool(flags & 0x02)
                            ack = bool(flags & 0x10)
                            if syn and not ack:
                                syn_count[src] += 1
                        except:
                            pass

                        # Beaconing detection
                        connection_times[f"{src}-{dst}"].append(float(packet.sniff_timestamp))

                    # ICMP flood detection
                    if hasattr(packet, 'icmp'):
                        icmp_count[src] += 1

                    # DNS tunnelling detection
                    if hasattr(packet, 'dns'):
                        if hasattr(packet.dns, 'qry_name'):
                            query = packet.dns.qry_name
                            if len(query) > THRESHOLDS["dns_query_length"]:
                                dns_queries.append({"src": src, "query": query})

                # ARP spoofing detection
                if hasattr(packet, 'arp'):
                    if hasattr(packet.arp, 'src_proto_ipv4'):
                        arp_ip = packet.arp.src_proto_ipv4
                        arp_mac = packet.arp.src_hw_mac
                        arp_ip_to_macs[arp_ip].add(arp_mac)

            except Exception:
                continue

        cap.close()

    except Exception as e:
        logger.error(f"Error reading PCAP: {e}")
        return {"error": str(e), "threats": [], "packet_count": 0}

    # ── Run detectors ──────────────────────────────────────────────────

    # DoS detection
    for ip, count in ip_packet_count.items():
        if count >= THRESHOLDS["dos_packet_count"]:
            threats.append({
                "type": "DoS/DDoS",
                "severity": "HIGH",
                "src_ip": ip,
                "detail": f"{count} packets from single source",
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
    for connection, times in connection_times.items():
        if len(times) >= 5:
            intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
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
        "timestamp": datetime.utcnow().isoformat(),
        "filepath": filepath
    }