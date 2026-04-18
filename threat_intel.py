import os
import requests
import logging
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Cache checked IPs to avoid hitting API limits
_ip_cache = {}

def check_ip_reputation(ip: str) -> dict:
    """Check an IP against AbuseIPDB threat intelligence"""

    # Skip private/reserved IPs
    if _is_private_ip(ip):
        return {"ip": ip, "is_malicious": False, "confidence": 0, "skip": True}

    # Return cached result if available
    if ip in _ip_cache:
        return _ip_cache[ip]

    if not API_KEY:
        logger.warning("No AbuseIPDB API key found")
        return {"ip": ip, "is_malicious": False, "confidence": 0, "error": "No API key"}

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers={
                "Key": API_KEY,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 30,
                "verbose": False
            },
            timeout=5
        )

        if response.status_code == 200:
            data = response.json().get("data", {})
            result = {
                "ip": ip,
                "is_malicious": data.get("abuseConfidenceScore", 0) >= 50,
                "confidence": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "total_reports": data.get("totalReports", 0)
            }
            _ip_cache[ip] = result
            return result

    except Exception as e:
        logger.error(f"AbuseIPDB check failed for {ip}: {e}")

    return {"ip": ip, "is_malicious": False, "confidence": 0, "error": "API call failed"}


def enrich_threats_with_intel(threats: list) -> list:
    """Add threat intel to detected threats"""
    enriched = []
    checked_ips = set()

    for threat in threats:
        src_ip = threat.get("src_ip", "")
        intel = {}

        if src_ip and src_ip not in checked_ips:
            intel = check_ip_reputation(src_ip)
            checked_ips.add(src_ip)

            if intel.get("is_malicious"):
                threat["threat_intel"] = {
                    "known_malicious": True,
                    "confidence": intel.get("confidence"),
                    "country": intel.get("country"),
                    "isp": intel.get("isp"),
                    "total_reports": intel.get("total_reports")
                }
                # Escalate severity if IP is known malicious
                if threat["severity"] == "MEDIUM":
                    threat["severity"] = "HIGH"
                    threat["detail"] += " — IP flagged as malicious by AbuseIPDB"
            else:
                threat["threat_intel"] = {"known_malicious": False}

        enriched.append(threat)

    return enriched


def _is_private_ip(ip: str) -> bool:
    """Check if IP is private/reserved — skip AbuseIPDB for these"""
    private_ranges = [
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
        "172.30.", "172.31.", "192.168.", "127.", "0.0.0.0"
    ]
    return any(ip.startswith(r) for r in private_ranges)