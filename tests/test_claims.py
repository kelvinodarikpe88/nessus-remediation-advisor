"""The README makes claims. This test is what makes them true."""
import re
from pathlib import Path

from app.nessus import build_plan, load_intel, parse_nessus

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
CLAIM_RE = re.compile(r"<!--\s*claims:\s*(.*?)\s*-->")


def read_claims() -> dict[str, int]:
    match = CLAIM_RE.search((ROOT / "README.md").read_text())
    assert match, "README.md must carry a <!-- claims: ... --> marker"
    return {
        key: int(value)
        for key, value in re.findall(r"(\w+)=(\d+)", match.group(1))
    }


def test_readme_numbers_match_the_evidence():
    kev, epss = load_intel(FIXTURES)
    plan = build_plan(
        parse_nessus((FIXTURES / "sample.nessus").read_text()),
        kev,
        epss,
        criticality={"web-01": "high", "db-01": "high", "vpn-01": "high"},
        internet_facing={"vpn-01"},
    )
    actual = {
        "findings": plan["summary"]["findings"],
        "hosts": plan["summary"]["hosts"],
        "kev": plan["summary"]["cisa_kev"],
        "wave1": plan["summary"]["wave_sizes"]["1"],
    }
    claims = read_claims()
    for key, value in claims.items():
        assert actual[key] == value, f"README claims {key}={value}, evidence says {actual[key]}"
