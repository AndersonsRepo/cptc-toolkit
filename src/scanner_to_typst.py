#!/usr/bin/env python3
"""
scanner_to_typst.py — convert scanner output into Typst #finding(...) blocks
for the cptc-toolkit vulnerability-report template.

Supported inputs
----------------
  --nuclei FILE   Nuclei JSONL (one JSON object per line, from `nuclei -jle FILE`
                  or `nuclei -json-export FILE`).
  --sarif  FILE   SARIF 2.1.0 (Trivy, Grype, Semgrep, CodeQL, OWASP ZAP,
                  claude-code-security-review, etc.).

Multiple inputs of either type may be supplied; their findings are merged and
written sequentially.

Output
------
A `.typ` file containing one `#finding(...)` block per finding, ready to
`#include` from your main report file.

Usage
-----
    python scanner_to_typst.py --nuclei scan.jsonl -o findings.typ
    python scanner_to_typst.py --sarif zap.sarif --sarif semgrep.sarif \\
                               --nuclei nuclei.jsonl -o findings.typ
    python scanner_to_typst.py --nuclei scan.jsonl --start-id 12 \\
                               --prefix CPTC -o findings.typ
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# Normalised finding model
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


@dataclass
class Finding:
    """Tool-agnostic representation, mirrors #finding(...) in Typst."""

    id: str = ""
    title: str = ""
    severity: str = "medium"
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cvss_criteria: dict = field(default_factory=dict)
    hosts: list = field(default_factory=list)
    impact: str = ""
    likelihood: str = ""
    status: str = "open"
    axis_risk: str = ""
    axis_sophistication: str = ""
    axis_remediation: str = ""
    description: str = ""
    business_impact: str = ""
    evidence: str = ""
    evidence_lang: str = ""
    remediation: str = ""
    mitre_attack: list = field(default_factory=list)
    cwe: list = field(default_factory=list)
    owasp: list = field(default_factory=list)
    compliance: list = field(default_factory=list)
    references: list = field(default_factory=list)
    source: str = ""  # which scanner produced this


# ---------------------------------------------------------------------------
# Severity normalisation
# ---------------------------------------------------------------------------

_NUCLEI_SEV = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "unknown": "info",
}

# SARIF level → our severity (very rough; SARIF only has 4 levels)
_SARIF_LEVEL = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


def _impact_likelihood_from_severity(sev: str) -> tuple[str, str]:
    return {
        "critical": ("High", "High"),
        "high": ("High", "Medium"),
        "medium": ("Medium", "Medium"),
        "low": ("Low", "Medium"),
        "info": ("Low", "Low"),
    }.get(sev, ("Medium", "Medium"))


def _triptych_from_severity(sev: str) -> tuple[str, str, str]:
    """Crude defaults: risk = severity; sophistication = inverse;
    remediation = effort (heuristic)."""
    return {
        "critical": ("high", "low", "medium"),
        "high":     ("high", "low", "low"),
        "medium":   ("medium", "medium", "low"),
        "low":      ("low", "high", "low"),
        "info":     ("low", "high", "low"),
    }.get(sev, ("medium", "medium", "medium"))


# ---------------------------------------------------------------------------
# CVSS vector parsing (3.x)
# ---------------------------------------------------------------------------

_CVSS_METRIC_LABELS = {
    "AV": "av", "AC": "ac", "PR": "pr", "UI": "ui", "S": "s",
    "C": "c", "I": "i", "A": "a",
}

_CVSS_VALUE_LABELS = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S":  {"U": "Unchanged", "C": "Changed"},
    "C":  {"N": "None", "L": "Low", "H": "High"},
    "I":  {"N": "None", "L": "Low", "H": "High"},
    "A":  {"N": "None", "L": "Low", "H": "High"},
}


def parse_cvss_vector(vector: str) -> dict:
    """Returns dict of lowercase keys (av, ac, pr, …) → human label."""
    if not vector or "/" not in vector:
        return {}
    out: dict = {}
    parts = vector.split("/")
    for p in parts:
        if ":" not in p:
            continue
        k, v = p.split(":", 1)
        if k in _CVSS_METRIC_LABELS and k in _CVSS_VALUE_LABELS:
            out[_CVSS_METRIC_LABELS[k]] = _CVSS_VALUE_LABELS[k].get(v, v)
    return out


# ---------------------------------------------------------------------------
# Nuclei adapter
# ---------------------------------------------------------------------------

def parse_nuclei(path: Path) -> list[Finding]:
    out: list[Finding] = []
    raw = path.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        return out

    # Nuclei can emit either JSONL (one object per line) or a JSON array
    records: list[dict] = []
    if raw.lstrip().startswith("["):
        try:
            records = json.loads(raw)
        except json.JSONDecodeError:
            pass
    if not records:
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    for r in records:
        info = r.get("info", {}) or {}
        cls = info.get("classification", {}) or {}

        sev = _NUCLEI_SEV.get((info.get("severity") or "info").lower(), "info")
        score = _to_float(cls.get("cvss-score"))
        vector = cls.get("cvss-metrics") or ""

        # If CVSS score is present but no severity, derive from score
        if score and not info.get("severity"):
            sev = _severity_from_cvss(score)

        impact, likelihood = _impact_likelihood_from_severity(sev)
        risk, soph, remed = _triptych_from_severity(sev)

        hosts: list = []
        if r.get("host"):
            hosts.append(r["host"])
        if r.get("matched-at") and r["matched-at"] not in hosts:
            hosts.append(r["matched-at"])

        description = (info.get("description") or "").strip()
        remediation = (info.get("remediation") or "").strip()
        references = _to_list(info.get("reference"))

        # Build evidence from request/response if present
        evidence_parts = []
        if r.get("request"):
            evidence_parts.append(("Request", r["request"], "http"))
        if r.get("response"):
            evidence_parts.append(("Response", r["response"], "http"))
        if r.get("extracted-results"):
            evidence_parts.append(
                ("Extracted",
                 "\n".join(str(x) for x in r["extracted-results"]),
                 "")
            )
        evidence = ""
        if evidence_parts:
            chunks = []
            for label, body, lang in evidence_parts:
                fence = "```" + lang if lang else "```"
                chunks.append(f"*{label}*\n{fence}\n{body.strip()}\n```")
            evidence = "\n\n".join(chunks)

        cwes = _normalise_cwes(_to_list(cls.get("cwe-id")))
        cves = [c.upper() for c in _to_list(cls.get("cve-id"))]
        if cves:
            references = list(dict.fromkeys(references + [
                f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves
            ]))

        title = info.get("name") or r.get("template-id") or "Untitled Finding"

        f = Finding(
            title=title,
            severity=sev,
            cvss_score=score,
            cvss_vector=vector,
            cvss_criteria=parse_cvss_vector(vector),
            hosts=hosts,
            impact=impact,
            likelihood=likelihood,
            axis_risk=risk,
            axis_sophistication=soph,
            axis_remediation=remed,
            description=description,
            evidence=evidence,
            remediation=remediation,
            mitre_attack=_to_list(cls.get("mitre-attack-id")),
            cwe=cwes,
            references=references,
            source=f"nuclei:{info.get('author', 'unknown')}",
        )
        out.append(f)
    return out


# ---------------------------------------------------------------------------
# SARIF adapter
# ---------------------------------------------------------------------------

def parse_sarif(path: Path) -> list[Finding]:
    out: list[Finding] = []
    try:
        doc = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        print(f"[!] SARIF parse failed for {path}: {e}", file=sys.stderr)
        return out

    runs = doc.get("runs", [])
    for run in runs:
        tool = (run.get("tool", {}).get("driver", {}).get("name")
                or "sarif").lower()

        # Build rule index for description/CWE lookup
        rules_idx: dict = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            if rule.get("id"):
                rules_idx[rule["id"]] = rule

        for res in run.get("results", []):
            rule_id = res.get("ruleId") or ""
            rule = rules_idx.get(rule_id, {})

            sev_raw = (res.get("level")
                       or rule.get("defaultConfiguration", {}).get("level")
                       or "warning")
            sev = _SARIF_LEVEL.get(sev_raw.lower(), "medium")

            # CVSS — Semgrep/Trivy/Grype store this in properties
            props = res.get("properties", {}) or {}
            rule_props = rule.get("properties", {}) or {}
            score = (_to_float(props.get("security-severity"))
                     or _to_float(rule_props.get("security-severity"))
                     or _to_float(props.get("cvssV3_baseScore"))
                     or _to_float(rule_props.get("cvssV3_baseScore"))
                     or 0.0)
            vector = (props.get("cvssV3_vector")
                      or rule_props.get("cvssV3_vector")
                      or "")
            if score:
                sev = _severity_from_cvss(score)

            impact, likelihood = _impact_likelihood_from_severity(sev)
            risk, soph, remed = _triptych_from_severity(sev)

            title = (rule.get("shortDescription", {}).get("text")
                     or rule.get("name")
                     or rule_id
                     or "Untitled Finding")

            msg = res.get("message", {})
            description = ((msg.get("text") if isinstance(msg, dict) else msg)
                           or rule.get("fullDescription", {}).get("text")
                           or rule.get("shortDescription", {}).get("text")
                           or "")

            remediation = (rule.get("help", {}).get("text")
                           or rule.get("helpUri", "")
                           or "")
            if remediation.startswith("http"):
                # helpUri isn't remediation text per se — push it to references
                pass

            references = []
            if rule.get("helpUri"):
                references.append(rule["helpUri"])
            for h in res.get("hostedViewerUri", []) if isinstance(
                    res.get("hostedViewerUri", []), list) else []:
                references.append(h)

            # CWE — Semgrep tags or CodeQL tags
            tags = (rule_props.get("tags", []) or []) + (props.get("tags", []) or [])
            cwes = _normalise_cwes([t for t in tags if isinstance(t, str)
                                    and t.lower().startswith("cwe")])
            owasp = [t for t in tags if isinstance(t, str)
                     and t.lower().startswith("owasp")]

            # Locations → hosts (artifact URI + line ranges; works for SAST + DAST)
            hosts = []
            evidence_lines = []
            for loc in res.get("locations", []) or []:
                pl = loc.get("physicalLocation", {}) or {}
                uri = (pl.get("artifactLocation", {}) or {}).get("uri", "")
                region = pl.get("region", {}) or {}
                line = region.get("startLine")
                snippet = (region.get("snippet", {}) or {}).get("text", "")
                if uri:
                    where = f"{uri}:{line}" if line else uri
                    hosts.append(where)
                    if snippet:
                        evidence_lines.append(f"// {where}\n{snippet.strip()}")
            evidence = "\n\n".join(evidence_lines) if evidence_lines else ""

            f = Finding(
                title=title,
                severity=sev,
                cvss_score=score,
                cvss_vector=vector,
                cvss_criteria=parse_cvss_vector(vector),
                hosts=hosts,
                impact=impact,
                likelihood=likelihood,
                axis_risk=risk,
                axis_sophistication=soph,
                axis_remediation=remed,
                description=description,
                evidence=evidence,
                remediation=remediation if not remediation.startswith("http") else "",
                cwe=cwes,
                owasp=owasp,
                references=references,
                source=f"sarif:{tool}",
            )
            out.append(f)
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_list(x: Any) -> list:
    if x is None:
        return []
    if isinstance(x, list):
        return [str(i).strip() for i in x if str(i).strip()]
    return [str(x).strip()] if str(x).strip() else []


def _to_float(x: Any) -> float:
    try:
        return float(x) if x is not None else 0.0
    except (TypeError, ValueError):
        return 0.0


def _normalise_cwes(items: Iterable) -> list:
    out: list = []
    seen = set()
    for raw in items:
        s = str(raw).upper().strip()
        m = re.search(r"CWE[-_:\s]?(\d+)", s)
        if m:
            cwe = f"CWE-{m.group(1)}"
            if cwe not in seen:
                seen.add(cwe)
                out.append(cwe)
    return out


# ---------------------------------------------------------------------------
# Dedup / sort
# ---------------------------------------------------------------------------

def dedupe_and_sort(findings: list[Finding]) -> list[Finding]:
    """Drop duplicates (same title + host set), sort by severity desc."""
    seen = {}
    for f in findings:
        key = (f.title.strip().lower(), tuple(sorted(f.hosts)))
        if key in seen:
            # Merge: union hosts, keep higher severity
            existing = seen[key]
            for h in f.hosts:
                if h not in existing.hosts:
                    existing.hosts.append(h)
            if SEVERITY_ORDER.get(f.severity, 0) > SEVERITY_ORDER.get(existing.severity, 0):
                existing.severity = f.severity
                existing.cvss_score = f.cvss_score
                existing.cvss_vector = f.cvss_vector or existing.cvss_vector
                existing.cvss_criteria = f.cvss_criteria or existing.cvss_criteria
        else:
            seen[key] = f
    findings = list(seen.values())
    findings.sort(key=lambda f: -SEVERITY_ORDER.get(f.severity, 0))
    return findings


# ---------------------------------------------------------------------------
# Typst emitter
# ---------------------------------------------------------------------------

def _typst_str(s: str) -> str:
    """Escape a Python string for use inside Typst `"..."` literal."""
    if s is None:
        return '""'
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    s = s.replace("\n", "\\n").replace("\r", "")
    return f'"{s}"'


def _typst_str_array(xs: list) -> str:
    if not xs:
        return "()"
    inner = ", ".join(_typst_str(x) for x in xs)
    # Trailing comma for single-element tuples
    if len(xs) == 1:
        inner += ","
    return f"({inner})"


def _typst_dict(d: dict) -> str:
    if not d:
        return "none"
    items = ", ".join(f"{k}: {_typst_str(v)}" for k, v in d.items())
    return f"({items})"


def _typst_content_block(text: str) -> str:
    """Wrap a multi-line Python string as Typst content `[...]`.

    Escapes Typst markup-sensitive characters minimally so the prose renders
    as written. Code fences (```lang ... ```) become Typst raw blocks via
    Markdown-style passthrough.
    """
    if not text or not text.strip():
        return "[]"
    # Escape the brackets and # at line start
    safe = text
    safe = safe.replace("\\", "\\\\")
    safe = safe.replace("[", "\\[").replace("]", "\\]")
    # Escape # when it's at the start of a line (would otherwise be an expression)
    safe = re.sub(r"(?m)^#", r"\\#", safe)
    # Convert ``` code fences — Typst already understands triple-backtick raw
    # in markup, but our escaped backslashes break it. Re-introduce raw blocks
    # by splitting on fences and using raw().
    if "```" in safe:
        return _content_with_raw_blocks(text)
    return "[" + safe + "]"


def _content_with_raw_blocks(text: str) -> str:
    """Convert text containing ```lang … ``` fences into a Typst content
    block that mixes escaped markup with raw blocks."""
    fence_re = re.compile(r"```(\w*)\n(.*?)```", re.DOTALL)
    parts = []
    last = 0
    for m in fence_re.finditer(text):
        before = text[last:m.start()]
        if before.strip():
            esc = before
            esc = esc.replace("\\", "\\\\")
            esc = esc.replace("[", "\\[").replace("]", "\\]")
            esc = re.sub(r"(?m)^#", r"\\#", esc)
            parts.append(esc)
        lang = m.group(1) or ""
        body = m.group(2)
        lang_arg = f", lang: {_typst_str(lang)}" if lang else ""
        parts.append(f"#raw({_typst_str(body)}, block: true{lang_arg})")
        last = m.end()
    tail = text[last:]
    if tail.strip():
        esc = tail
        esc = esc.replace("\\", "\\\\")
        esc = esc.replace("[", "\\[").replace("]", "\\]")
        esc = re.sub(r"(?m)^#", r"\\#", esc)
        parts.append(esc)
    return "[" + "\n".join(parts) + "]"


def emit_typst(findings: list[Finding], start_id: int = 1,
               prefix: str = "F") -> str:
    """Produce the Typst output: one #finding(...) per finding."""
    blocks: list = []
    blocks.append(
        "// Generated by scanner_to_typst.py — do not hand-edit blindly.\n"
        "// Each #finding(...) block can be moved to a different severity\n"
        "// chapter; the report card auto-sorts by severity.\n"
    )
    for i, f in enumerate(findings, start=start_id):
        if not f.id:
            f.id = f"{prefix}-{i:03d}"

        # Build the field list
        fields = [
            ("id", _typst_str(f.id)),
            ("title", _typst_str(f.title)),
            ("severity", _typst_str(f.severity)),
            ("cvss-score", str(f.cvss_score)),
        ]
        if f.cvss_vector:
            fields.append(("cvss-vector", _typst_str(f.cvss_vector)))
        if f.cvss_criteria:
            fields.append(("cvss-criteria", _typst_dict(f.cvss_criteria)))
        fields.extend([
            ("hosts", _typst_str_array(f.hosts)),
            ("impact", _typst_str(f.impact)),
            ("likelihood", _typst_str(f.likelihood)),
            ("status", _typst_str(f.status)),
        ])
        if f.axis_risk:
            fields.append(("axis-risk", _typst_str(f.axis_risk)))
        if f.axis_sophistication:
            fields.append(("axis-sophistication", _typst_str(f.axis_sophistication)))
        if f.axis_remediation:
            fields.append(("axis-remediation", _typst_str(f.axis_remediation)))
        fields.append(("description", _typst_content_block(
            f.description or "[Description pending — fill in.]")))
        fields.append(("business-impact", _typst_content_block(
            f.business_impact or
            "[Business impact pending — write 2–4 sentences in client terms.]")))
        if f.evidence:
            fields.append(("evidence", _typst_content_block(f.evidence)))
        fields.append(("remediation", _typst_content_block(
            f.remediation or "[Remediation pending.]")))
        if f.mitre_attack:
            fields.append(("mitre-attack", _typst_str_array(f.mitre_attack)))
        if f.cwe:
            fields.append(("cwe", _typst_str_array(f.cwe)))
        if f.owasp:
            fields.append(("owasp", _typst_str_array(f.owasp)))
        if f.compliance:
            fields.append(("compliance", _typst_str_array(f.compliance)))
        if f.references:
            fields.append(("references", _typst_str_array(f.references)))

        # Render the block
        rendered_fields = ",\n  ".join(f"{k}: {v}" for k, v in fields)
        blocks.append(
            f"// Source: {f.source}\n"
            f"#finding(\n  {rendered_fields},\n)\n"
        )
    return "\n".join(blocks)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Convert scanner output to Typst #finding(...) blocks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--nuclei", action="append", default=[], type=Path,
                   help="Nuclei JSONL output (may be repeated)")
    p.add_argument("--sarif", action="append", default=[], type=Path,
                   help="SARIF 2.1.0 file (may be repeated)")
    p.add_argument("-o", "--output", type=Path, default=Path("findings.typ"),
                   help="Output .typ file (default: findings.typ)")
    p.add_argument("--start-id", type=int, default=1,
                   help="Starting finding ID number (default: 1)")
    p.add_argument("--prefix", default="F",
                   help="Finding ID prefix (default: F → F-001, F-002, ...)")
    p.add_argument("--no-dedupe", action="store_true",
                   help="Skip dedup pass (same title + hosts)")

    args = p.parse_args(argv)

    if not (args.nuclei or args.sarif):
        p.error("Need at least one --nuclei or --sarif input.")

    findings: list = []
    for path in args.nuclei:
        if not path.exists():
            print(f"[!] Missing: {path}", file=sys.stderr)
            return 2
        new = parse_nuclei(path)
        print(f"[+] {path}: {len(new)} Nuclei finding(s)", file=sys.stderr)
        findings.extend(new)
    for path in args.sarif:
        if not path.exists():
            print(f"[!] Missing: {path}", file=sys.stderr)
            return 2
        new = parse_sarif(path)
        print(f"[+] {path}: {len(new)} SARIF finding(s)", file=sys.stderr)
        findings.extend(new)

    if not args.no_dedupe:
        before = len(findings)
        findings = dedupe_and_sort(findings)
        print(f"[+] Dedup + sort: {before} → {len(findings)}", file=sys.stderr)

    out = emit_typst(findings, start_id=args.start_id, prefix=args.prefix)
    args.output.write_text(out, encoding="utf-8")
    print(f"[+] Wrote {len(findings)} finding(s) → {args.output}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
