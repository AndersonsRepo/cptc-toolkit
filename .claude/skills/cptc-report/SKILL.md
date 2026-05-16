---
name: cptc-report
description: Build a CPTC-style pentest report from a directory of scanner outputs (Nuclei JSONL, SARIF from ZAP/Trivy/Grype/Semgrep/CodeQL, BloodHound path JSON). Enriches CVE-tagged findings against NVD + CISA KEV + EPSS, fills CWE boilerplate, splices into the bundled Typst template, and compiles to PDF. Use when the user wants to convert raw scanner output into a finished report — single command, no manual field-filling.
---

# CPTC Report Pipeline

End-to-end report generation for CPTC and similar pentest engagements.
**Reporting accelerator, not autopwn** — finds nothing; converts what
your scans and manual work found into a polished, accurate PDF.

## When to use this skill

Trigger when the user:
- Says "build a CPTC report" / "build a pentest report" / "generate a finding report"
- Hands over a directory or set of scanner outputs and asks for a report
- References this skill explicitly (`/cptc-report`)
- Mentions Nuclei + ZAP + BloodHound output collection from an engagement

Do NOT trigger when:
- The user wants help *finding* vulnerabilities — this skill writes
  the report, not the test.
- The user is asking general questions about Typst formatting (use
  the regular conversation flow).

## How it works

```
[scans/*.jsonl]  --→  scanner_to_typst.py
[scans/*.sarif]  --→  scanner_to_typst.py  ──┐
                                              ├──→  enrich (NVD + KEV + EPSS + CWE boilerplate)
[scans/bloodhound-*.json] -→ bloodhound_to_typst.py ─┘
                                                       │
                                                       ▼
                       template/vulnerability-report.typ  + report-metadata.json
                                                       │
                                                       ▼
                                                  out/report.pdf
```

## Invocation

```bash
# From the cptc-toolkit repo:
./.claude/skills/cptc-report/scripts/run.sh \
    --scans /path/to/scans \
    --out   /path/to/output-dir \
    --client "OuiCroissant" \
    --engagement "CPTC10-Finals" \
    --enrich

# Or via the Python equivalent:
python3 .claude/skills/cptc-report/scripts/build_report.py \
    --scans /path/to/scans \
    --out   /path/to/output-dir \
    --client "OuiCroissant" \
    --engagement "CPTC10-Finals" \
    --enrich
```

### Input directory layout (auto-detected)

```
scans/
├── nuclei-*.jsonl          # any number, glob: nuclei*.{jsonl,json}
├── zap-*.sarif             # any number, glob: *.sarif
├── trivy-*.sarif
├── semgrep-*.sarif
├── bloodhound-*.json       # one path per file
└── report-metadata.json    # optional: client, engagement, dates, authors
```

### Output

```
out/
├── findings.typ            # scanner-generated findings
├── ad-findings.typ         # BloodHound-generated AD findings
├── report.typ              # template + findings, ready to compile
└── report.pdf              # final PDF (if typst is on PATH)
```

## Critical behavior rules

1. **Never overwrite scanner-provided text.** Boilerplate fills only
   empty fields. The scanner's `description`/`remediation` always wins.
2. **Keep the LLM out of CVSS / CWE / KEV assignment.** Those come from
   NVD canonical data. Don't "improve" them.
3. **The LLM owns only `business-impact` prose and `evidence` narration.**
   After the pipeline runs, the operator (or an interactive Claude
   session) should review every generated `business-impact` field and
   tighten it to the engagement's specific client. The pipeline puts a
   placeholder in every empty one.
4. **The pipeline is deterministic.** Same scan input + same boilerplate
   version = byte-identical findings. Don't introduce LLM steps in the
   pipeline; reserve LLM for the prose review pass.
5. **Don't push findings via the Discord notification queue.** The queue
   is text-only. Report output goes to disk + GitHub.

## Companion repo

[github.com/AndersonsRepo/cptc-toolkit](https://github.com/AndersonsRepo/cptc-toolkit)
— full source for the adapter, BloodHound translator, enrichment
pipeline, CWE boilerplate, and the bundled Typst template (CPTC10-mined).
