"""Tenable .nessus parsing, enrichment and deterministic remediation waves.

The scoring is the product. The model never decides what is urgent: it writes
the paragraph a customer reads after the ordering has already been fixed by
rules that can be re-run and audited.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

CRITICALITY_RANK = {"low": 1, "medium": 2, "high": 3}

SEVERITY_NAME = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}

WAVE_BANDS = ((70.0, 1), (50.0, 2), (30.0, 3), (15.0, 4), (0.0, 5))


@dataclass
class Finding:
    plugin_id: str
    name: str
    severity: int
    port: int
    protocol: str
    service: str
    cvss3: float | None
    cves: list[str] = field(default_factory=list)
    exploit_available: bool = False
    solution: str = ""
    synopsis: str = ""
    hosts: list[str] = field(default_factory=list)
    score: float = 0.0
    kev: list[str] = field(default_factory=list)
    epss: float = 0.0
    wave: int = 5

    @property
    def key(self) -> tuple[str, int, str]:
        return (self.plugin_id, self.port, self.protocol)

    def as_dict(self) -> dict:
        return {
            "plugin_id": self.plugin_id,
            "name": self.name,
            "severity": SEVERITY_NAME.get(self.severity, "unknown"),
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "cvss3": self.cvss3,
            "cves": self.cves,
            "cisa_kev": self.kev,
            "epss": self.epss,
            "exploit_available": self.exploit_available,
            "hosts": sorted(self.hosts),
            "score": self.score,
            "wave": self.wave,
            "solution": self.solution,
        }


def _text(node: ET.Element, tag: str) -> str:
    found = node.find(tag)
    return (found.text or "").strip() if found is not None and found.text else ""


def parse_nessus(xml_text: str) -> list[Finding]:
    """Parse a .nessus export and merge the same finding across hosts."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ValueError(f"not a valid .nessus document: {exc}") from exc
    if root.tag != "NessusClientData_v2":
        raise ValueError("root element is not NessusClientData_v2")

    merged: dict[tuple[str, int, str], Finding] = {}
    for host in root.iter("ReportHost"):
        hostname = host.get("name", "unknown")
        for item in host.findall("ReportItem"):
            plugin_id = item.get("pluginID", "")
            port = int(item.get("port", "0") or 0)
            protocol = item.get("protocol", "tcp")
            key = (plugin_id, port, protocol)
            cvss_raw = _text(item, "cvss3_base_score")
            try:
                cvss3 = float(cvss_raw) if cvss_raw else None
            except ValueError:
                cvss3 = None
            existing = merged.get(key)
            if existing is None:
                existing = Finding(
                    plugin_id=plugin_id,
                    name=item.get("pluginName", "unnamed"),
                    severity=int(item.get("severity", "0") or 0),
                    port=port,
                    protocol=protocol,
                    service=item.get("svc_name", ""),
                    cvss3=cvss3,
                    cves=sorted({c.text.strip() for c in item.findall("cve") if c.text}),
                    exploit_available=_text(item, "exploit_available").lower() == "true",
                    solution=_text(item, "solution"),
                    synopsis=_text(item, "synopsis"),
                )
                merged[key] = existing
            if hostname not in existing.hosts:
                existing.hosts.append(hostname)
    return list(merged.values())


def load_intel(fixtures: Path) -> tuple[set[str], dict[str, float]]:
    kev = set(json.loads((fixtures / "kev.json").read_text())["cves"])
    epss = json.loads((fixtures / "epss.json").read_text())["scores"]
    return kev, {k: float(v) for k, v in epss.items()}


def score_finding(
    finding: Finding,
    kev: set[str],
    epss: dict[str, float],
    criticality: dict[str, str],
    internet_facing: set[str],
) -> float:
    """Deterministic, published, and reproducible. No model in this path."""
    finding.kev = sorted(c for c in finding.cves if c in kev)
    finding.epss = max((epss.get(c, 0.0) for c in finding.cves), default=0.0)

    score = 0.0
    if finding.kev:
        score += 60.0
    score += round(finding.epss * 30.0, 2)

    cvss = finding.cvss3 or 0.0
    if cvss >= 9.0:
        score += 15.0
    elif cvss >= 7.0:
        score += 10.0
    elif cvss >= 4.0:
        score += 4.0

    if internet_facing.intersection(finding.hosts):
        score += 15.0

    ranks = [CRITICALITY_RANK.get(criticality.get(h, "medium"), 2) for h in finding.hosts]
    score += {3: 10.0, 2: 5.0, 1: 0.0}[max(ranks)]

    if finding.exploit_available:
        score += 5.0

    return round(min(score, 100.0), 2)


def wave_for(score: float) -> int:
    for threshold, wave in WAVE_BANDS:
        if score >= threshold:
            return wave
    return 5


def build_plan(
    findings: list[Finding],
    kev: set[str],
    epss: dict[str, float],
    criticality: dict[str, str] | None = None,
    internet_facing: set[str] | None = None,
) -> dict:
    criticality = criticality or {}
    internet_facing = internet_facing or set()

    for finding in findings:
        finding.score = score_finding(finding, kev, epss, criticality, internet_facing)
        finding.wave = wave_for(finding.score)

    ordered = sorted(findings, key=lambda f: (-f.score, f.plugin_id, f.port))
    waves: dict[int, list[Finding]] = {n: [] for n in range(1, 6)}
    for finding in ordered:
        waves[finding.wave].append(finding)

    hosts = sorted({h for f in findings for h in f.hosts})
    return {
        "summary": {
            "findings": len(findings),
            "hosts": len(hosts),
            "cisa_kev": sum(1 for f in findings if f.kev),
            "critical_or_high": sum(1 for f in findings if f.severity >= 3),
            "wave_sizes": {str(n): len(items) for n, items in waves.items()},
            "scoring": "kev 60 + epss*30 + cvss + exposure 15 + criticality + exploit 5",
        },
        "waves": [
            {
                "wave": n,
                "findings": [f.as_dict() for f in waves[n]],
                "max_score": waves[n][0].score if waves[n] else 0.0,
            }
            for n in range(1, 6)
        ],
    }
