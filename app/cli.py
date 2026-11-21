"""Demo without a server: python -m app.cli fixtures/sample.nessus"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from . import llm
from .nessus import build_plan, load_intel, parse_nessus

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else FIXTURES / "sample.nessus"
    kev, epss = load_intel(FIXTURES)
    findings = parse_nessus(path.read_text())
    plan = build_plan(
        findings,
        kev,
        epss,
        criticality={"web-01": "high", "db-01": "high", "vpn-01": "high"},
        internet_facing={"vpn-01"},
    )
    for wave in plan["waves"]:
        note = llm.build_note(wave)
        wave["note"] = note["text"]
        wave["note_source"] = note["source"]
    json.dump(plan, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
