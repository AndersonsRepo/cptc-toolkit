# cptc-toolkit

> Scanner output → Typst pentest report. Built for the Collegiate Penetration Testing Competition (CPTC).

A reporting accelerator, **not** an autopwn. You still find vulns the
normal way — Burp, BloodHound, Impacket, manual chains. This toolkit
turns the structured-output portions of your scans into pre-filled
`#finding(...)` blocks for the bundled Typst report template, so the
last 24 hours of competition can go to the report's narrative instead
of typing CVSS vectors.

---

## What's in here

```
cptc-toolkit/
├── src/
│   └── scanner_to_typst.py     # Single-file adapter (Python 3, stdlib only)
├── template/
│   └── vulnerability-report.typ # Report template (CPTC10-styled)
└── examples/
    ├── nuclei-sample.jsonl     # Sample Nuclei JSONL output
    ├── zap-sample.sarif        # Sample OWASP ZAP SARIF output
    ├── findings.typ            # Adapter-generated findings (regenerated)
    └── test-report.typ         # Inlined template + findings for smoke-test
```

## Quick start

```bash
# 1. One-shot Typst binary (no install, no PATH change)
curl -sSL -o /tmp/typst.tar.xz \
  https://github.com/typst/typst/releases/latest/download/typst-aarch64-apple-darwin.tar.xz
tar -xf /tmp/typst.tar.xz -C /tmp

# 2. Generate findings from sample scans
python3 src/scanner_to_typst.py \
  --nuclei examples/nuclei-sample.jsonl \
  --sarif examples/zap-sample.sarif \
  -o examples/findings.typ

# 3. Compile the smoke-test report
/tmp/typst-aarch64-apple-darwin/typst compile \
  examples/test-report.typ examples/test-report.pdf
```

Open `examples/test-report.pdf` — 24 pages, 5 findings rendered from the
two sample scans, with severity strip, report card, and remediation
roadmap auto-populated.

## Supported scanner inputs

| Scanner                                  | Format                  | Flag         |
| ---------------------------------------- | ----------------------- | ------------ |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | JSONL (`-jle file`) or JSON array | `--nuclei`   |
| [Trivy](https://aquasecurity.github.io/trivy/)       | SARIF 2.1.0             | `--sarif`    |
| [Grype](https://github.com/anchore/grype)            | SARIF 2.1.0             | `--sarif`    |
| [Semgrep](https://semgrep.dev/)                      | SARIF 2.1.0             | `--sarif`    |
| [CodeQL](https://codeql.github.com/)                 | SARIF 2.1.0             | `--sarif`    |
| [OWASP ZAP](https://www.zaproxy.org/)                | SARIF (zap-extensions)  | `--sarif`    |
| [claude-code-security-review](https://github.com/anthropics/claude-code-security-review) | SARIF                   | `--sarif`    |

Each flag may be repeated. Findings are merged, deduped by `(title,
hosts)`, and sorted by severity.

## Field mappings

For every finding the adapter populates:

| Template field         | Source                                                       |
| ---------------------- | ------------------------------------------------------------ |
| `id`                   | Auto-numbered `F-001`, `F-002`, … (override with `--prefix`) |
| `title`                | Nuclei `info.name` / SARIF `rule.shortDescription`           |
| `severity`             | Nuclei `info.severity` / SARIF `level` (re-derived if CVSS present) |
| `cvss-score`           | Nuclei `info.classification.cvss-score` / SARIF `properties.security-severity` |
| `cvss-vector`          | Nuclei `info.classification.cvss-metrics` / SARIF `properties.cvssV3_vector` |
| `cvss-criteria`        | Parsed from `cvss-vector` (AV/AC/PR/UI/S/C/I/A → labels)     |
| `hosts`                | Nuclei `host` + `matched-at` / SARIF `locations[].physicalLocation` |
| `impact`, `likelihood` | Heuristic from severity                                       |
| `axis-risk/sophistication/remediation` | Heuristic from severity                  |
| `description`          | Nuclei `info.description` / SARIF `message.text`             |
| `evidence`             | Nuclei `request` + `response` + `extracted-results` / SARIF snippets |
| `remediation`          | Nuclei `info.remediation` / SARIF `rule.help.text`           |
| `cwe`                  | Nuclei `info.classification.cwe-id` / SARIF `properties.tags` |
| `owasp`                | SARIF `properties.tags` starting with `OWASP`                 |
| `references`           | Nuclei `info.reference` (+ NVD link per CVE) / SARIF `helpUri` |

Empty-by-default fields you must still write yourself: `business-impact`,
sometimes `remediation` (scanner-supplied remediation is generic).

## Workflow for an actual CPTC engagement

1. **During testing** — run scanners in parallel with manual work:
   ```bash
   # Web
   nuclei -t /path/to/templates -u https://target.local \
          -jle /tmp/nuclei-target.jsonl
   zap.sh -cmd -quickurl https://target.local \
          -quickout /tmp/zap.sarif -quickprogress
   # Containers / IaC (if in scope)
   trivy image registry.target.local/app:latest --format sarif \
         --output /tmp/trivy.sarif
   ```

2. **Triage** — manually go through the Nuclei/ZAP findings; delete the
   noise from the JSONL/SARIF or filter with `jq`.

3. **Generate findings** —
   ```bash
   python3 src/scanner_to_typst.py \
     --nuclei /tmp/nuclei-target.jsonl \
     --sarif  /tmp/zap.sarif \
     --sarif  /tmp/trivy.sarif \
     --prefix CPTC \
     -o findings.typ
   ```

4. **Add your manual findings** — open `findings.typ` and copy a generated
   block as a template for each finding the scanners missed (the
   interesting ones — IDOR, business logic, AD attack paths, etc.).

5. **Build the report** — clone `template/vulnerability-report.typ`,
   inline the contents of `findings.typ` where the sample findings sit
   (the file marker is `== Critical Findings`), and compile.

## What it deliberately doesn't do

- **No autopwn.** Doesn't run scanners; it parses their output.
- **No CVSS recalculation.** Trusts the scanner; if the vector is wrong,
  fix it in the generated `findings.typ`.
- **No business-impact prose.** The scanner has no idea what the client
  does. You write that.
- **No attack-narrative generation.** The competition-winning narrative
  is yours to write — it's most of your score.

## v0.2 — BloodHound → attack-path findings

CPTC AD findings are *chains*. `src/bloodhound_to_typst.py` turns a
BloodHound CE path JSON (or a hand-written simplified path) into a
`#finding(...)` whose `evidence:` field is a clean vertical flow of
kind-tagged node boxes connected by edge labels. The flow renders via
the `#attack-path(...)` helper added to the template.

```bash
# Generate from a simplified manual JSON (recommended during competition)
python3 src/bloodhound_to_typst.py examples/bloodhound-kerberoast-esc1.json \
  --prefix AD -o ad-findings.typ

# Or stack multiple paths into one report
python3 src/bloodhound_to_typst.py path1.json path2.json path3.json \
  --prefix AD -o ad-findings.typ
```

### Simplified path format (write these by hand)

```json
{
  "title": "Domain Admin via Kerberoast + ESC1",
  "severity": "critical",
  "cvss_score": 9.0,
  "hosts": ["corp-dc01.corp.local"],
  "description": "...",
  "business_impact": "...",
  "remediation": "...",
  "mitre_attack": ["T1558.003", "T1649"],
  "path": [
    {"kind": "User",         "name": "JANE@CORP.LOCAL",
     "edge_out": "HasSession"},
    {"kind": "User",         "name": "SQLSVC@CORP.LOCAL",
     "edge_out": "Kerberoastable → cracked offline"},
    {"kind": "CertTemplate", "name": "VulnerableUserCert",
     "edge_out": "Enroll → ESC1"},
    {"kind": "Group",        "name": "DOMAIN ADMINS"}
  ]
}
```

### BloodHound CE API format

Also accepted directly:

```bash
# Pull a path from BloodHound CE's REST API and convert
curl -s -H "Authorization: $BH_TOKEN" \
  "https://bh.local/api/v2/graphs/cypher" \
  --data '{"query": "MATCH p=(...)..."}' \
  -o /tmp/path.json
python3 src/bloodhound_to_typst.py /tmp/path.json -o ad-findings.typ
```

The script auto-detects which format you fed it.

## Roadmap

- **v0.3** — CVE enrichment pass (NVD + CISA KEV + EPSS + MITRE ATT&CK
  STIX) so the cross-reference rows are always canonical
- **v0.4** — PwnDoc-NG YAML vuln-DB lookup to back-fill `description` and
  `remediation` from community-maintained boilerplate keyed by CWE
- **v0.5** — Claude skill packaging so an agent can run the pipeline
  end-to-end with a single prompt

## License

MIT. Use it, fork it, win CPTC.
