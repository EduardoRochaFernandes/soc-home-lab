#!/usr/bin/env python3
"""
IOC Enricher — SOC Home Lab
Enriches indicators of compromise against free threat intelligence APIs.

Supported IoC types: IP, domain, file hash (MD5/SHA256), URL

Usage:
    python3 ioc_enricher.py --ip 1.2.3.4
    python3 ioc_enricher.py --domain evil.example.com
    python3 ioc_enricher.py --hash d41d8cd98f00b204e9800998ecf8427e
    python3 ioc_enricher.py --file iocs.txt
    python3 ioc_enricher.py --ip 1.2.3.4 --output json
    python3 ioc_enricher.py --demo            # offline, bundled synthetic sample data

Configuration:
    Copy .env.example (repo root) to .env and add your API keys.
    All APIs used have a free tier — no paid keys required for basic use.
    --demo needs no keys and makes no network calls.
"""

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional
import ipaddress

try:
    import requests
    from dotenv import load_dotenv
except ImportError:
    print("Missing dependencies. Run: pip install requests python-dotenv")
    sys.exit(1)

load_dotenv()

# API keys from environment (set in .env file — never hardcode)
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
SHODAN_KEY = os.getenv("SHODAN_API_KEY", "")

SAMPLE_DIR = Path(__file__).resolve().parent / "sample_data"

REQUEST_TIMEOUT = 10
RATE_LIMIT_DELAY = 1  # seconds between API calls


@dataclass
class EnrichmentResult:
    ioc: str
    ioc_type: str
    malicious: Optional[bool] = None
    confidence: Optional[int] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    reports: Optional[int] = None
    tags: Optional[list] = None
    last_seen: Optional[str] = None
    sources: Optional[list] = None
    raw: Optional[dict] = None

    def to_dict(self):
        return {k: v for k, v in asdict(self).items() if v is not None}


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def enrich_ip_abuseipdb(ip: str) -> dict:
    """Check IP reputation via AbuseIPDB (free tier: 1000 req/day)"""
    if not ABUSEIPDB_KEY:
        return {"error": "ABUSEIPDB_API_KEY not set in .env"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}

    try:
        r = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        data = r.json().get("data", {})
        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "total_reports": data.get("totalReports"),
            "last_reported": data.get("lastReportedAt"),
            "is_whitelisted": data.get("isWhitelisted"),
            "usage_type": data.get("usageType"),
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def enrich_hash_virustotal(file_hash: str) -> dict:
    """Check file hash via VirusTotal (free tier: 4 req/min)"""
    if not VIRUSTOTAL_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set in .env"}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_KEY}

    try:
        r = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if r.status_code == 404:
            return {"result": "Not found in VirusTotal"}
        r.raise_for_status()
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "meaningful_name": data.get("meaningful_name"),
            "type_description": data.get("type_description"),
            "first_submission_date": data.get("first_submission_date"),
            "last_analysis_date": data.get("last_analysis_date"),
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def enrich_ip_shodan(ip: str) -> dict:
    """Get Shodan host info (free tier available)"""
    if not SHODAN_KEY:
        return {"error": "SHODAN_API_KEY not set in .env"}

    url = f"https://api.shodan.io/shodan/host/{ip}"
    params = {"key": SHODAN_KEY}

    try:
        r = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
        if r.status_code == 404:
            return {"result": "No Shodan data for this IP"}
        r.raise_for_status()
        data = r.json()
        return {
            "org": data.get("org"),
            "isp": data.get("isp"),
            "country_name": data.get("country_name"),
            "city": data.get("city"),
            "open_ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "tags": data.get("tags", []),
            "vulns": list(data.get("vulns", {}).keys()),
            "last_update": data.get("last_update"),
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def load_demo_data() -> dict:
    """Load the bundled synthetic API responses used by --demo (no network, no keys)."""
    with open(SAMPLE_DIR / "demo_responses.json", encoding="utf-8") as f:
        return json.load(f)


def enrich_ioc(ioc: str, ioc_type: str, demo_data: Optional[dict] = None) -> EnrichmentResult:
    """Enrich one IoC. If demo_data is given, use it instead of calling the live APIs."""
    result = EnrichmentResult(ioc=ioc, ioc_type=ioc_type)
    enrichments = {}
    delay = 0 if demo_data is not None else RATE_LIMIT_DELAY

    def lookup(source: str, live_fn):
        if demo_data is None:
            return live_fn(ioc)
        return demo_data.get(source, {}).get(ioc, {"result": "No demo data for this IoC"})

    if ioc_type == "ip":
        print("  [*] Checking AbuseIPDB...")
        abuse = lookup("abuseipdb", enrich_ip_abuseipdb)
        enrichments["abuseipdb"] = abuse
        time.sleep(delay)

        if not abuse.get("error"):
            score = abuse.get("abuse_confidence_score", 0)
            result.malicious = score > 50
            result.confidence = score
            result.country = abuse.get("country_code")
            result.reports = abuse.get("total_reports")
            result.last_seen = abuse.get("last_reported")

        print("  [*] Checking Shodan...")
        shodan = lookup("shodan", enrich_ip_shodan)
        enrichments["shodan"] = shodan
        time.sleep(delay)

        if not shodan.get("error"):
            result.asn = shodan.get("org")
            result.tags = shodan.get("tags", [])

    elif ioc_type == "hash":
        print("  [*] Checking VirusTotal...")
        vt = lookup("virustotal", enrich_hash_virustotal)
        enrichments["virustotal"] = vt
        time.sleep(delay)

        if not vt.get("error") and "malicious" in vt:
            result.malicious = vt["malicious"] > 0
            result.confidence = min(100, int((vt["malicious"] / max(1, vt["malicious"] + vt.get("undetected", 0))) * 100))

    result.sources = list(enrichments.keys())
    result.raw = enrichments
    return result


def print_result(result: EnrichmentResult, output_format: str = "table"):
    if output_format == "json":
        print(json.dumps(result.to_dict(), indent=2, default=str))
        return

    malicious_str = "🔴 MALICIOUS" if result.malicious else ("🟢 CLEAN" if result.malicious is False else "⚪ UNKNOWN")

    print(f"\n{'='*60}")
    print(f"  IoC: {result.ioc}")
    print(f"  Type: {result.ioc_type.upper()}")
    print(f"  Verdict: {malicious_str}")
    if result.confidence is not None:
        print(f"  Confidence: {result.confidence}%")
    if result.country:
        print(f"  Country: {result.country}")
    if result.asn:
        print(f"  ASN/Org: {result.asn}")
    if result.reports is not None:
        print(f"  Abuse Reports: {result.reports}")
    if result.last_seen:
        print(f"  Last Seen: {result.last_seen}")
    if result.tags:
        print(f"  Tags: {', '.join(result.tags)}")
    print(f"  Sources: {', '.join(result.sources or [])}")
    print(f"{'='*60}\n")


def main():
    # Verdict icons are non-ASCII; make sure legacy Windows consoles don't crash on them.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="IOC Enricher — SOC Home Lab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--ip", help="IP address to enrich")
    parser.add_argument("--hash", help="File hash (MD5 or SHA256) to enrich")
    parser.add_argument("--domain", help="Domain to enrich (not implemented yet: no provider is queried)")
    parser.add_argument("--file", help="File with one IoC per line")
    parser.add_argument("--output", choices=["table", "json"], default="table")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Offline demo: enrich the bundled synthetic sample IoCs (no API keys, no network)",
    )

    args = parser.parse_args()

    if not any([args.ip, args.hash, args.domain, args.file, args.demo]):
        parser.print_help()
        sys.exit(1)

    iocs_to_process = []
    demo_data = None

    if args.demo:
        demo_data = load_demo_data()
        args.file = args.file or str(SAMPLE_DIR / "sample_iocs.txt")
        print("[DEMO MODE] Using bundled synthetic data. Verdicts below are NOT real threat intelligence.")

    if args.ip:
        if not is_valid_ip(args.ip):
            print(f"Error: '{args.ip}' is not a valid IP address")
            sys.exit(1)
        iocs_to_process.append((args.ip, "ip"))

    if args.hash:
        iocs_to_process.append((args.hash, "hash"))

    if args.file:
        try:
            with open(args.file) as f:
                for line in f:
                    ioc = line.strip()
                    if not ioc or ioc.startswith("#"):
                        continue
                    if is_valid_ip(ioc):
                        iocs_to_process.append((ioc, "ip"))
                    elif len(ioc) in (32, 64):  # MD5 or SHA256
                        iocs_to_process.append((ioc, "hash"))
                    else:
                        iocs_to_process.append((ioc, "domain"))
        except FileNotFoundError:
            print(f"Error: File '{args.file}' not found")
            sys.exit(1)

    print("\n[SOC Home Lab — IOC Enricher]")
    print(f"Processing {len(iocs_to_process)} IoC(s)...\n")

    results = []
    for ioc, ioc_type in iocs_to_process:
        print(f"[*] Enriching {ioc_type.upper()}: {ioc}")
        result = enrich_ioc(ioc, ioc_type, demo_data)
        results.append(result)
        print_result(result, args.output)

    # Summary
    if len(results) > 1:
        malicious_count = sum(1 for r in results if r.malicious)
        print(f"\nSummary: {malicious_count}/{len(results)} IoCs flagged as malicious")


if __name__ == "__main__":
    main()
