# SOP — Operating the remediation advisor

**Service:** `nessus-remediation-advisor`
**Owner:** security engineering
**Audience:** the analyst who runs it, and the service owner who changes it
**Review cadence:** quarterly, or on any change to the scoring table

---

## 1. Purpose and scope

This procedure covers how a Tenable scan becomes a remediation plan a customer can act on: what to feed it, how to read the output, how to handle the failure modes, and how to change the scoring without breaking its guarantees.

**In scope:** scan intake, plan generation, output validation, feed refresh, key rotation, exception handling.
**Out of scope:** running the scan, prioritising business risk the customer has not told you about, and executing remediation.

---

## 2. Roles

| Role | Owns |
|---|---|
| Service owner | scoring thresholds, intel feed refresh, releases |
| Analyst | runs the plan, validates wave 1 before anything leaves the building |
| Account owner | delivers the plan, records customer exceptions, owns the follow-up date |

One rule above all others: **an analyst reads wave 1 before it is sent.** The tool orders; a person is accountable for the order.

---

## 3. Before the first run

You need three things from the customer:

1. **The scan export** — Tenable → *Scans* → the completed scan → *Export* → **Nessus (.nessus)**. Not CSV, not PDF: the XML carries the CVE list, CVSS score and plugin output the tool relies on.
2. **An asset criticality map** — a JSON object of `hostname: low|medium|high`. If the customer has no CMDB extract, default everything to `medium` and say so in the covering note; do not guess per host.
3. **The internet-facing host list** — hostnames reachable from outside the estate. This is the single highest-value input after KEV, and customers routinely get it wrong by listing the load balancer instead of the hosts behind it.

Exports over 5 MB are refused by design. Split the scan by site or subnet rather than raising the limit.

---

## 4. Standard run

```bash
export SECOPS_API_KEYS="$(openssl rand -hex 24)"   # per customer, stored in the secret manager
uvicorn app.main:app --port 8000                   # or: docker compose up -d

curl -s localhost:8000/v1/intel -H "x-api-key: $SECOPS_API_KEYS"
```

1. Confirm the intel endpoint returns the expected KEV count and a `source_date` you would defend. If the date is older than 90 days, refresh the feeds (§8) before running.
2. Submit the plan:

```bash
curl -s localhost:8000/v1/plan -H "x-api-key: $SECOPS_API_KEYS" \
  -H 'content-type: application/json' \
  -d "{\"nessus_xml\": $(python -c 'import json;print(json.dumps(open("scan.nessus").read()))'),
       \"asset_criticality\": {\"web-01\":\"high\"},
       \"internet_facing\": [\"vpn-01\"]}"
```

3. Read `summary.findings`, `summary.cisa_kev` and `summary.wave_sizes`. If `cisa_kev` is 0 on an estate that has not patched since 2021, suspect a truncated export before you celebrate.
4. **Read every note in wave 1.** You are looking for a finding that is technically correct but commercially wrong — a KEV entry against a host the customer already retired, for example.
5. Send. Record the input hash and the returned JSON against the customer and the date.

---

## 5. Reading the output

| Field | Meaning |
|---|---|
| `score` | deterministic 0–100; see §6 |
| `wave` | 1 = act now, 5 = scheduled backlog |
| `cisa_kev` | CVE is in the Known Exploited Vulnerabilities catalogue |
| `epss` | probability of exploitation in the next 30 days |
| `hosts` | every host the finding was merged across |
| `note_source` | `template` = deterministic fallback, `model` = verified model output |
| `note_rejected` | present only when model output was discarded; names the reason |

`note_source: template` is normal and not a fault. It means no provider was configured, or the model produced something that failed verification.

---

## 6. Changing the scoring

The formula is `KEV 60 + EPSS×30 + CVSS band + exposure 15 + criticality + exploit 5`, capped at 100, with bands at 70 / 50 / 30 / 15.

To change it:

1. Change `score_finding` in `app/nessus.py`. Nothing else sets a score.
2. Update the table in `README.md` and the band values in the same commit.
3. Run `pytest`. The reproducibility test and the KEV-dominance test exist to make a careless change fail loudly.
4. If the change alters the sample fixture's counts, update `<!-- claims: -->` in `README.md` — `tests/test_claims.py` fails if the prose and the evidence disagree.
5. Ship as a versioned change. A customer who was told wave 1 last month must be able to see why it is different this month.

**Never** add a signal that cannot be reproduced from the input file. Non-determinism in prioritisation is indistinguishable, from the customer's side, from a bug.

---

## 7. Failure modes

| Symptom | Likely cause | First response |
|---|---|---|
| `/readyz` returns 503 | intel failed to load, or SIGTERM received | check the container logs for `draining`; if not draining, the fixtures are missing — redeploy |
| process exits at start | `SECOPS_API_KEYS` unset | deliberate fail-closed. Set the key; do not add a bypass |
| `422 no findings in document` | wrong export type, or an empty scan | re-export as `.nessus`; confirm the scan actually ran to completion |
| `422 not a valid .nessus document` | CSV/PDF submitted, or truncated upload | re-export |
| `note_rejected: invented_cves=[...]` | the model named a CVE not in the input | keep the template note, send it, and open a defect with the prompt and the response |
| `note_rejected: provider_error` | upstream model unreachable | no action; the template note is already in the output and is safe to send |
| `429 rate_limited` | more than 120 requests/min from one key | batch the scans; if this is legitimate, raise `RATE_LIMIT_PER_MIN` and record why |

The service never fails open: an unverifiable model note is replaced, not repaired, and a missing key stops the process rather than serving unauthenticated.

---

## 8. Intel feed refresh (quarterly, service owner)

The repo ships an offline KEV and EPSS snapshot so that builds are reproducible and tests mean the same thing in six months. It is not a live feed.

1. Download the current CISA KEV catalogue (JSON) and the FIRST EPSS scores (CSV).
2. Rewrite `fixtures/kev.json` with the CVE list and today's date as `source_date`.
3. Rewrite `fixtures/epss.json` with the scores for the CVEs in scope and the same date.
4. Run `pytest`. Feed changes do not alter the sample-scan counts, so the claims test should stay green; if it does not, the fixture was edited by accident.
5. Commit with the date in the subject.

**If you cannot refresh:** say so in the covering note. A plan built on a 90-day-old KEV list is still useful; a plan that claims to be current when it is not is a liability.

---

## 9. Secrets and access

- One API key per consuming system, generated with `openssl rand -hex 24`, held in the secret manager, never in a repo or a ticket.
- Rotation: issue the new key, deploy it to consumers, remove the old key from `SECOPS_API_KEYS` after the last consumer confirms. Because keys are comma-separated, overlap is safe.
- The service logs a six-character key prefix as `caller`. That is enough to attribute a request and not enough to reconstruct a key.

---

## 10. Evidence and retention

Per customer, per run, keep for 12 months:

- the SHA-256 of the submitted `.nessus` file
- the returned plan JSON
- the covering note sent

This is what answers "why did you tell us to patch this first" six months later. Store it wherever the customer's audit evidence lives, not on a laptop.

---

## 11. Known limits — read before quoting a number

- The intel is a snapshot (§8), not a live feed.
- CVSS comes from the plugin, not from the vendor's later re-score.
- `exploit_available` is the scanner's opinion, and scanners are optimistic in both directions.
- Findings are merged by `(plugin, port, protocol)`. Two different root causes on the same port are one row.
- It has been run against sample scans, not against a customer's estate. The first real customer run should be treated as a validation exercise, with the analyst reading all five waves, not just wave 1.

---

## 12. Escalation

| Situation | Route |
|---|---|
| Model invents a CVE in production | service owner same day; keep the template output |
| Scoring looks wrong for a customer | service owner with the input hash and the disputed rows |
| Customer disputes a KEV priority | it is a fact from the catalogue — point at the CVE and the date, and let the customer decide with the evidence in hand |
| Suspected key compromise | rotate every key, review `/metrics` for anomalous callers, then post-incident review |
