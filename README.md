# nessus-remediation-advisor

Turns a Tenable `.nessus` export into a prioritised remediation plan a customer can act on — with the ordering decided by rules, not by a model.

<!-- claims: findings=9 hosts=3 kev=3 wave1=3 -->
**Operating procedure:** [docs/SOP.md](docs/SOP.md) — how to run it, who approves, and what to do when it fails.

## The problem this solves

A scan produces a list sorted by CVSS. A customer cannot patch 400 findings on Monday, so the list gets triaged by whoever shouts loudest, and the thing that is actually being exploited this week sits at position 60 because its CVSS is 8.8 instead of 9.8.

CVSS alone is a severity score, not a priority. This service scores on what changes the answer:

| Signal | Weight | Why |
|---|---|---|
| CISA KEV membership | +60 | It is being exploited in the wild. Nothing else outranks that. |
| EPSS | up to +30 | Probability of exploitation in the next 30 days. |
| CVSS v3 base | +4 to +15 | Severity, as a tiebreaker rather than the driver. |
| Internet-facing | +15 | Reachable by someone who is not on your network. |
| Asset criticality | +0 to +10 | What breaks if this host goes down or leaks. |
| Public exploit available | +5 | Lowers the cost of attack. |

Then it cuts the list into five waves and writes the paragraph that goes to the customer.

## Where the model is, and where it is not

```
.nessus  ──► parse ──► merge across hosts ──► enrich (KEV, EPSS)
                                                   │
                                                   ▼
                                          score + wave   ◄── deterministic, auditable
                                                   │
                                                   ▼
                                     model writes the note  ◄── prose only
                                                   │
                                                   ▼
                                   CVE check ──► template fallback
```

- The model **never** sets a score, a wave or an order.
- Input is fenced as untrusted data at render time, control characters stripped and newlines collapsed, so a hostile plugin name cannot add a line to the prompt.
- Every CVE the note names must exist in the input. A note that invents one is **discarded**, not repaired, and the deterministic template is used instead.
- No provider configured means no model call at all. The template note is the default, and it is what CI tests against.

## Run it

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt

# no server needed
python -m app.cli fixtures/sample.nessus

# as a service
export SECOPS_API_KEYS=dev-key-change-me
uvicorn app.main:app --port 8000

curl -s localhost:8000/v1/intel -H "x-api-key: dev-key-change-me"
curl -s localhost:8000/v1/plan -H "x-api-key: dev-key-change-me" \
  -H 'content-type: application/json' \
  -d "{\"nessus_xml\": $(python -c 'import json,sys;print(json.dumps(open("fixtures/sample.nessus").read()))')}"
```

## The runtime

Every service in this portfolio carries the same six controls, because they are the six that get skipped in a demo and audited in production:

- constant-time API-key comparison (`hmac.compare_digest`), and **refusal to start** if no key is configured
- per-caller sliding-window rate limiting with `Retry-After`
- `/healthz`, `/readyz`, `/version`, `/metrics`
- one JSON log line per request with a request ID, never the key
- SIGTERM withdraws readiness before the socket closes
- container runs non-root, read-only root filesystem, all capabilities dropped, health-checked against `/readyz`

## What this does not claim

The KEV and EPSS data are a **bundled offline snapshot**, not a live feed — that is deliberate, so the build is reproducible and the tests mean the same thing in six months. In production these come from the CISA and FIRST feeds with a recorded pull date, and a stale feed should fail readiness rather than silently under-rank a finding.

It runs on my infrastructure against sample scans. It has not been run against a customer's estate.
