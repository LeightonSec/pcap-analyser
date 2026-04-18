from scapy.all import wrpcap, IP, TCP, ICMP, ARP, Ether
import random

def generate_syn_flood(filename="test_syn_flood.pcap", count=200):
    """Simulate SYN flood attack"""
    packets = []
    attacker_ip = "192.168.1.100"
    victim_ip = "10.0.0.1"

    for i in range(count):
        pkt = IP(src=attacker_ip, dst=victim_ip) / \
              TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
        packets.append(pkt)

    wrpcap(filename, packets)
    print(f"Generated {filename} — {count} SYN packets")

def generate_port_scan(filename="test_port_scan.pcap", ports=100):
    """Simulate port scan"""
    packets = []
    attacker_ip = "192.168.1.200"
    victim_ip = "10.0.0.2"

    for port in range(1, ports + 1):
        pkt = IP(src=attacker_ip, dst=victim_ip) / \
              TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
        packets.append(pkt)

    wrpcap(filename, packets)
    print(f"Generated {filename} — {ports} ports scanned")

def generate_arp_spoof(filename="test_arp_spoof.pcap"):
    """Simulate ARP spoofing — multiple MACs claiming same IP"""
    packets = []
    victim_ip = "192.168.1.1"

    macs = ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"]

    for mac in macs:
        for _ in range(10):
            pkt = Ether(src=mac) / \
                  ARP(op=2, psrc=victim_ip, hwsrc=mac,
                      pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff")
            packets.append(pkt)

    wrpcap(filename, packets)
    print(f"Generated {filename} — ARP spoofing with {len(macs)} MACs")

def generate_dos(filename="test_dos.pcap", count=1500):
    """Simulate DoS — high volume from single IP"""
    packets = []
    attacker_ip = "10.10.10.10"
    victim_ip = "10.0.0.3"

    for i in range(count):
        pkt = IP(src=attacker_ip, dst=victim_ip) / \
              ICMP()
        packets.append(pkt)

    wrpcap(filename, packets)
    print(f"Generated {filename} — {count} ICMP packets")

def generate_c2_beacon(filename="test_c2_beacon.pcap", count=20):
    """Simulate C2 beaconing — regular timed connections to same external IP"""
    packets = []
    infected_host = "192.168.1.50"
    c2_server = "185.220.101.1"
    
    base_time = 1000.0
    
    for i in range(count):
        timestamp = base_time + (i * 30) + random.uniform(-1, 1)
        pkt = IP(src=infected_host, dst=c2_server) / \
              TCP(sport=random.randint(1024, 65535), dport=443, flags="S")
        pkt.time = timestamp
        packets.append(pkt)
    
    wrpcap(filename, packets)
    print(f"Generated {filename} — {count} beacon packets every ~30s")

if __name__ == "__main__":
    print("Generating test PCAP files...")
    generate_syn_flood()
    generate_port_scan()
    generate_arp_spoof()
    generate_dos()
    generate_c2_beacon()
    print("Done — 5 test files generated")