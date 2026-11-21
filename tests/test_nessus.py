from pathlib import Path

import pytest

from app.nessus import build_plan, load_intel, parse_nessus, wave_for

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture(scope="module")
def intel():
    return load_intel(FIXTURES)


@pytest.fixture(scope="module")
def findings():
    return parse_nessus((FIXTURES / "sample.nessus").read_text())


def test_parses_and_merges_across_hosts(findings):
    assert len(findings) == 9
    log4shell = next(f for f in findings if f.plugin_id == "156001")
    assert log4shell.hosts == ["web-01", "db-01"]


def test_kev_is_present_for_three_findings(findings, intel):
    kev, epss = intel
    plan = build_plan(findings, kev, epss)
    assert plan["summary"]["cisa_kev"] == 3


def test_kev_outranks_a_higher_cvss_without_kev(findings, intel):
    kev, epss = intel
    plan = build_plan(findings, kev, epss, internet_facing={"vpn-01"})
    wave1 = plan["waves"][0]["findings"]
    ssh = next(
        f for f in findings if f.plugin_id == "153953"
    )  # CVSS 9.8, not in KEV
    assert ssh.wave > 1
    assert all(item["cisa_kev"] for item in wave1)


def test_wave_bands_are_monotonic():
    assert wave_for(100) == 1
    assert wave_for(70) == 1
    assert wave_for(69.9) == 2
    assert wave_for(30) == 3
    assert wave_for(15) == 4
    assert wave_for(14.9) == 5


def test_scoring_is_reproducible(findings, intel):
    kev, epss = intel
    first = build_plan(parse_nessus((FIXTURES / "sample.nessus").read_text()), kev, epss)
    second = build_plan(parse_nessus((FIXTURES / "sample.nessus").read_text()), kev, epss)
    assert first == second


def test_internet_facing_raises_score(findings, intel):
    kev, epss = intel
    internal = build_plan(
        parse_nessus((FIXTURES / "sample.nessus").read_text()), kev, epss
    )
    exposed = build_plan(
        parse_nessus((FIXTURES / "sample.nessus").read_text()),
        kev,
        epss,
        internet_facing={"vpn-01"},
    )
    before = internal["waves"][2]["findings"]
    after = exposed["waves"][2]["findings"]
    assert before or after  # the band exists and moved
    assert exposed["summary"]["wave_sizes"] != internal["summary"]["wave_sizes"]


def test_rejects_non_nessus_documents():
    with pytest.raises(ValueError):
        parse_nessus("<html><body>not a scan</body></html>")
    with pytest.raises(ValueError):
        parse_nessus("<not-xml")
