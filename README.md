# ⚡ PCAP Analyser — Network Threat Detection System

A network packet capture analysis tool that inspects PCAP files for malicious traffic patterns and alerts analysts to potential threats. Built as part of the LeightonSec SOC Toolkit.

---

## What It Does

Security analysts capture network traffic using tools like Wireshark or tcpdump. This tool takes those capture files and automatically analyses them for known attack patterns — flagging threats, scoring severity, and enriching findings with real-time threat intelligence.

Every uploaded PCAP is run through five detection engines and cross-referenced against AbuseIPDB's threat database before delivering a structured report.

---

## Detection Capabilities

| Threat Type | Severity | Detection Method |
|-------------|----------|-----------------|
| DoS/DDoS | HIGH | High packet volume from single source |
| SYN Flood | HIGH | SYN packets without ACK response |
| Port Scan | MEDIUM | Single IP targeting many ports rapidly |
| ARP Spoofing | HIGH | Multiple MACs claiming same IP |
| C2 Beaconing | HIGH | Regular timed connections to external IP |
| ICMP Flood | MEDIUM | High volume ICMP from single source |
| DNS Tunnelling | MEDIUM | Abnormally long DNS queries |

---

## Threat Intelligence

Every suspicious IP is checked against **AbuseIPDB** in real time:
- Known malicious IPs are flagged with confidence score
- Country and ISP information surfaced
- MEDIUM severity automatically escalated to HIGH for known malicious IPs
- Private IP ranges skipped to preserve API quota

---

## Web Interface

- Upload PCAP files directly through the browser
- Live results dashboard with packet count and severity breakdown
- Detailed threat cards with source IP, detail and recommended action
- Known malicious IP badge for AbuseIPDB confirmed threats

---

## Security Design

- File type whitelist — only `.pcap`, `.pcapng`, `.cap` accepted
- `secure_filename()` — prevents path traversal attacks
- 50MB upload limit — prevents denial of service via large files
- Uploaded files deleted after analysis — PCAP files contain sensitive data
- AbuseIPDB key stored in `.env` — never committed
- Server bound to `127.0.0.1` — not exposed to external networks
- Private IPs excluded from threat intel checks

---

## Setup

**Requirements:** Python 3.x, Wireshark/tshark installed, AbuseIPDB API key

```bash
# Install tshark (required by PyShark)
brew install wireshark

# Clone the repo
git clone git@github.com:LeightonSec/pcap-analyser.git
cd pcap-analyser

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Add your API keys
echo "ABUSEIPDB_API_KEY=your-key-here" > .env

# Run the server
python3 app.py
```

Then open `http://127.0.0.1:5001` in your browser.

---

## Generating Test PCAP Files

```bash
pip install scapy
python3 generate_test_pcaps.py
```

Generates 5 test files covering all detection categories:
- `test_syn_flood.pcap`
- `test_port_scan.pcap`
- `test_arp_spoof.pcap`
- `test_dos.pcap`
- `test_c2_beacon.pcap`

---

## Project Structure

pcap-analyser/
├── app.py                  # Flask server, file upload, API routes
├── analyser.py             # Core detection engine (5 detectors)
├── threat_intel.py         # AbuseIPDB integration and IP enrichment
├── generate_test_pcaps.py  # Test PCAP generator
├── templates/
│   └── index.html          # Web interface and results dashboard
├── requirements.txt
└── .env                    # API keys (never committed)

---

## SOC Toolkit Position

This tool sits in the **Detection layer** of the LeightonSec SOC Toolkit:

Ingestion    → Intel Pipeline
Detection    → Log Analyser + PCAP Analyser ← you are here
Analysis     → AI Firewall
Response     → Incident Tracker (planned)
Visibility   → Unified Dashboard (planned)

---

## Roadmap

- [ ] Live packet capture mode
- [ ] Integration with AI Firewall for ML-based classification
- [ ] Automatic alert to Incident Tracker on HIGH severity findings
- [ ] PCAP report export as PDF
- [ ] Docker containerisation
- [ ] Unified Dashboard integration

---

## Author

**Leighton Wilson** — SOC Analyst | LeightonSec
[LeightonSec GitHub](https://github.com/LeightonSec)

---

*Built as part of a hands-on cybersecurity portfolio. Part of the LeightonSec SOC Toolkit.*