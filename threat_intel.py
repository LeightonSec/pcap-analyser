import os
import ipaddress
import requests
import logging
from dotenv import load_dotenv
from pydantic import BaseModel, ValidationError

load_dotenv()

logger = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


class _AbuseIPDBData(BaseModel):
    abuseConfidenceScore: int = 0
    countryCode: str = "Unknown"
    isp: str = "Unknown"
    totalReports: int = 0
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
            try:
                data = _AbuseIPDBData.model_validate(
                    response.json().get("data", {})
                )
            except ValidationError as e:
                logger.error(f"Unexpected AbuseIPDB response schema for {ip}: {e}")
                return {"ip": ip, "is_malicious": False, "confidence": 0, "error": "Schema validation failed"}
            result = {
                "ip": ip,
                "is_malicious": data.abuseConfidenceScore >= 50,
                "confidence": data.abuseConfidenceScore,
                "country": data.countryCode,
                "isp": data.isp,
                "total_reports": data.totalReports
            }
            if len(_ip_cache) < 1000:
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
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True