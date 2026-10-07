"""Static sanity checks for the detection content (no SIEM required)."""

import re
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SIGMA_FILES = sorted((ROOT / "detections" / "sigma").rglob("*.yml"))
REQUIRED_SIGMA_FIELDS = {"title", "id", "status", "description", "author", "date", "tags", "logsource", "detection", "level"}


def load_sigma_documents(path):
    return [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]


@pytest.mark.parametrize("path", SIGMA_FILES, ids=lambda p: p.name)
def test_sigma_rule_has_required_fields_and_attack_tag(path):
    base = load_sigma_documents(path)[0]
    assert REQUIRED_SIGMA_FIELDS <= set(base), f"missing: {REQUIRED_SIGMA_FIELDS - set(base)}"
    uuid.UUID(str(base["id"]))
    assert any(re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t) for t in base["tags"]), "no ATT&CK technique tag"
    assert path.name.startswith("SOC-")


def test_sigma_ids_are_unique():
    ids = [doc["id"] for p in SIGMA_FILES for doc in load_sigma_documents(p)]
    assert len(ids) == len(set(ids))


def test_wazuh_rules_are_wellformed_with_unique_ids():
    tree = ET.parse(ROOT / "detections" / "wazuh" / "local_rules.xml")
    ids = [int(r.get("id")) for r in tree.getroot().iter("rule")]
    assert ids, "no rules found"
    assert len(ids) == len(set(ids)), "duplicate Wazuh rule ids"
    assert all(100000 <= i <= 199999 for i in ids), "local rule ids must be 100000-199999"
    for rule in tree.getroot().iter("rule"):
        assert rule.find("description") is not None, f"rule {rule.get('id')} has no description"


def suricata_rules():
    text = (ROOT / "detections" / "suricata" / "local.rules").read_text(encoding="utf-8")
    # Rules may use "\" line continuation; join them, then drop comments/blank lines.
    text = text.replace(chr(92) + chr(10), " ")
    return [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def test_suricata_rules_are_one_per_line_with_unique_sids():
    rules = suricata_rules()
    assert rules
    sids = []
    for rule in rules:
        assert re.match(r"^(alert|drop|pass|reject)\s", rule), rule[:60]
        assert rule.endswith(")"), f"unterminated rule: {rule[:60]}"
        m = re.search(r"\bsid:(\d+);", rule)
        assert m, f"no sid: {rule[:60]}"
        sids.append(int(m.group(1)))
    assert len(sids) == len(set(sids))
    assert all(9000000 <= s <= 9099999 for s in sids), "local SIDs must be in the 9000000-9099999 range"
