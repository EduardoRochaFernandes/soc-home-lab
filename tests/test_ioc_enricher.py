"""Offline tests for tools/ioc-enricher (no network, no API keys)."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "ioc-enricher" / "ioc_enricher.py"

spec = importlib.util.spec_from_file_location("ioc_enricher", TOOL)
ioc_enricher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ioc_enricher)


def test_is_valid_ip():
    assert ioc_enricher.is_valid_ip("192.0.2.10")
    assert ioc_enricher.is_valid_ip("2001:db8::1")
    assert not ioc_enricher.is_valid_ip("999.1.1.1")
    assert not ioc_enricher.is_valid_ip("example.com")


def test_missing_keys_return_error_not_exception():
    with mock.patch.object(ioc_enricher, "ABUSEIPDB_KEY", ""), \
         mock.patch.object(ioc_enricher, "VIRUSTOTAL_KEY", ""), \
         mock.patch.object(ioc_enricher, "SHODAN_KEY", ""):
        assert "error" in ioc_enricher.enrich_ip_abuseipdb("192.0.2.10")
        assert "error" in ioc_enricher.enrich_hash_virustotal("0" * 32)
        assert "error" in ioc_enricher.enrich_ip_shodan("192.0.2.10")


def test_abuseipdb_response_is_normalised():
    fake = mock.Mock(status_code=200)
    fake.raise_for_status.return_value = None
    fake.json.return_value = {"data": {"abuseConfidenceScore": 88, "countryCode": "ZZ", "totalReports": 5}}
    with mock.patch.object(ioc_enricher, "ABUSEIPDB_KEY", "test-key"), \
         mock.patch.object(ioc_enricher.requests, "get", return_value=fake) as get:
        out = ioc_enricher.enrich_ip_abuseipdb("192.0.2.10")
    assert get.called
    assert out["abuse_confidence_score"] == 88
    assert out["country_code"] == "ZZ"


def test_demo_enrichment_flags_known_bad_sample_without_network():
    demo = ioc_enricher.load_demo_data()
    with mock.patch.object(ioc_enricher.requests, "get", side_effect=AssertionError("network used")):
        bad = ioc_enricher.enrich_ioc("192.0.2.10", "ip", demo)
        clean = ioc_enricher.enrich_ioc("198.51.100.23", "ip", demo)
        vt = ioc_enricher.enrich_ioc("0123456789abcdef0123456789abcdef", "hash", demo)
    assert bad.malicious is True and bad.confidence == 97
    assert clean.malicious is False
    assert vt.malicious is True


def test_demo_cli_runs_and_exits_zero():
    proc = subprocess.run(
        [sys.executable, str(TOOL), "--demo", "--output", "json"],
        capture_output=True, text=True, encoding="utf-8", timeout=60, check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "DEMO MODE" in proc.stdout
    assert '"ioc": "192.0.2.10"' in proc.stdout
    json_blobs = proc.stdout.count('"ioc_type"')
    assert json_blobs == 6


def test_sample_data_is_valid_json_and_uses_documentation_ips():
    data = json.loads((TOOL.parent / "sample_data" / "demo_responses.json").read_text(encoding="utf-8"))
    for ip in data["abuseipdb"]:
        assert ip.startswith(("192.0.2.", "198.51.100.", "203.0.113."))
