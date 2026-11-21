import os

os.environ.setdefault("SERVICE_NAME", "nessus-remediation-advisor")
os.environ.setdefault("SERVICE_VERSION", "1.0.0")

from pathlib import Path  # noqa: E402

from fastapi import FastAPI, HTTPException  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from . import llm  # noqa: E402
from .nessus import build_plan, load_intel, parse_nessus  # noqa: E402
from .runtime import configure_logging, install_runtime  # noqa: E402

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
MAX_XML_CHARS = 5_000_000

KEV, EPSS = load_intel(FIXTURES)

configure_logging()
app = FastAPI(title="nessus-remediation-advisor", version="1.0.0")
install_runtime(app, ready_check=lambda: bool(KEV))


class PlanRequest(BaseModel):
    nessus_xml: str = Field(min_length=32)
    asset_criticality: dict[str, str] = Field(default_factory=dict)
    internet_facing: list[str] = Field(default_factory=list)
    use_model: bool = False


@app.get("/v1/intel")
def intel():
    return {
        "kev_cves": len(KEV),
        "epss_entries": len(EPSS),
        "note": "Offline snapshot bundled with the repo so the build is reproducible.",
    }


@app.post("/v1/plan")
def plan(request: PlanRequest):
    if len(request.nessus_xml) > MAX_XML_CHARS:
        raise HTTPException(status_code=413, detail="nessus_xml exceeds 5 MB")
    try:
        findings = parse_nessus(request.nessus_xml)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not findings:
        raise HTTPException(status_code=422, detail="no findings in document")

    result = build_plan(
        findings,
        KEV,
        EPSS,
        criticality=request.asset_criticality,
        internet_facing=set(request.internet_facing),
    )

    provider = llm.provider_from_env() if request.use_model else None
    for wave in result["waves"]:
        note = llm.build_note(wave, provider)
        wave["note"] = note["text"]
        wave["note_source"] = note["source"]
        if note["rejected"]:
            wave["note_rejected"] = note["rejected"]
    return result
