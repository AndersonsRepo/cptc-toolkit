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
# Minimum: scans dir + output dir
./.claude/skills/cptc-report/scripts/run.sh \
    --scans /path/to/scans \
    --out   /path/to/output-dir \
    --client "OuiCroissant" \
    --engagement "CPTC10-Finals" \
    --enrich

# With LLM prose-fill (v0.6) — fills business-impact + evidence-intro
# on every finding. Marks each AI-written field with a `// AI-DRAFT`
# comment in the .typ source for review.
ANTHROPIC_API_KEY=sk-ant-... \
./.claude/skills/cptc-report/scripts/run.sh \
    --scans /path/to/scans \
    --out   /path/to/output-dir \
    --client "OuiCroissant" \
    --industry "hospitality" \
    --enrich --draft-prose

# Cheap mode (Haiku instead of Sonnet): ~5× cheaper, slightly less polished prose
... --draft-prose --llm-model claude-haiku-4-5-20251001
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
   NVD canonical data. Don't "improve" them — the API call's system prompt
   forbids it and the input doesn't even hand it to the model for writing.
3. **The LLM owns only `business-impact` prose and `evidence` narration.**
   Every drafted field is tagged with `// AI-DRAFT: <fields>` in the
   `.typ` source. Reviewer greps for `AI-DRAFT` and edits each one before
   delivery. The marker is a hard requirement — never strip it pre-review.
4. **Default pipeline is deterministic.** `--draft-prose` is opt-in. Same
   scan input + same boilerplate version = byte-identical findings when
   the flag is off.
5. **Don't push findings via the Discord notification queue's text channel.**
   The bot's notification queue does support file attachments (via the
   `files:` array — see `bridges/discord/discord-transport.ts:946-994`),
   but the embed-text portion is capped at 4000 chars. Compiled PDFs go
   in the queue as attachments; prose findings stay on disk + GitHub.

## v0.6 cost notes

Per standard 10-finding report:

| Model                      | Per finding | Per report | Notes |
| -------------------------- | ----------- | ---------- | ----- |
| `claude-sonnet-4-6`        | ~$0.01      | ~$0.10     | Default. Best prose. |
| `claude-haiku-4-5-...`     | ~$0.002     | ~$0.02     | `--llm-model claude-haiku-4-5-20251001` |

Cache hits are free — editing the report and re-running costs nothing
for unchanged findings. Cache lives at `~/.cache/cptc-toolkit/prose/`.

## Companion repo

[github.com/AndersonsRepo/cptc-toolkit](https://github.com/AndersonsRepo/cptc-toolkit)
— full source for the adapter, BloodHound translator, enrichment
pipeline, CWE boilerplate, and the bundled Typst template (CPTC10-mined).
