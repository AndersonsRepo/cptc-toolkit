#!/usr/bin/env python3
"""
bloodhound_to_typst.py — convert BloodHound CE attack paths into Typst
`#finding(...)` blocks with embedded `#attack-path(...)` evidence.

Why this exists
---------------
CPTC AD findings are almost always *chains*: foothold → kerberoast →
ESC1 → domain admin. Pasting BloodHound screenshots into a report loses
the structure; pasting the cypher result is unreadable. This script
turns either format into a clean, branded flow diagram that drops
straight into the `evidence:` field of a `#finding(...)`.

Input formats accepted
----------------------
1. **BloodHound CE API path response** (alternating segments) — the
   shape returned by `POST /api/v2/graphs/search` and the canned-query
   API. Each path is an array alternating node and edge objects:
       [{node fields}, {edge fields}, {node fields}, ...]
2. **Simplified manual format** — easier to write by hand during
   competition:
       {
         "title": "Path to Domain Admin via Kerberoast + ESC1",
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
            "edge_out": "Enroll → ESC1 (alt SAN injection)"},
           {"kind": "Group",        "name": "DOMAIN ADMINS"}
         ]
       }

Usage
-----
    python3 bloodhound_to_typst.py path1.json path2.json -o ad-findings.typ
    python3 bloodhound_to_typst.py kerberoast-esc1.json --prefix AD \
                                   --start-id 1 -o ad-findings.typ

The output appends to the file passed via -o (or stdout). Combine with
scanner_to_typst.py output by concatenating files; the report card
auto-merges everything that goes through `#finding(...)`.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Reuse Typst-string helpers and the Finding dataclass from the sibling
# adapter so the two scripts emit identical block shapes.
sys.path.insert(0, str(Path(__file__).parent))
from scanner_to_typst import (  # noqa: E402
    Finding, _impact_likelihood_from_severity, _triptych_from_severity,
    _typst_str, _typst_str_array, _typst_dict, _typst_content_block,
    parse_cvss_vector, _severity_from_cvss,
)

# ---------------------------------------------------------------------------
# BloodHound CE → step list
# ---------------------------------------------------------------------------

# Node "kind" normalization (BloodHound uses several variants depending on
# whether you're looking at the v2 API, the SharpHound JSON, or Azure Hound).
_KIND_MAP = {
    "user": "User",
    "computer": "Computer",
    "group": "Group",
    "domain": "Domain",
    "ou": "OU",
    "gpo": "GPO",
    "container": "Container",
    "certtemplate": "CertTemplate",
    "enterprise ca": "CertAuthority",
    "rootca": "CertAuthority",
    "aiaca": "CertAuthority",
    "ntauthstore": "NTAuthStore",
    "issuancepolicy": "IssuancePolicy",
    "azureuser": "AZUser",
    "azuregroup": "AZGroup",
    "azureapp": "AZApp",
    "azureserviceprincipal": "AZServicePrincipal",
}


def _normalise_kind(raw: str | None) -> str:
    if not raw:
        return "Node"
    return _KIND_MAP.get(raw.strip().lower(), raw.strip())


def _node_display_name(node: dict) -> str:
    """Pick the most useful label out of a BloodHound node dict."""
    for key in ("name", "label", "objectId", "id"):
        v = node.get(key)
        if v:
            return str(v)
    props = node.get("properties", {}) or {}
    for key in ("name", "displayname", "samaccountname", "objectid"):
        v = props.get(key)
        if v:
            return str(v)
    return "?"


def _edge_label(edge: dict) -> str:
    """Best-effort label for a BloodHound edge."""
    # CE API path edges carry `kind` (the edge type, e.g. "AdminTo",
    # "GenericAll", "MemberOf"). Some endpoints also stash extra context
    # under `properties.traversalReason`.
    label = (edge.get("kind") or edge.get("label") or edge.get("type") or "→")
    extra = (edge.get("properties", {}) or {}).get("traversalReason")
    if extra:
        label = f"{label} ({extra})"
    return label


def _segments_to_steps(segments: list) -> list[dict]:
    """Convert an alternating [node, edge, node, edge, …] list into our
    step-list format. Tolerates trailing edge (drops it)."""
    steps: list[dict] = []
    cur_node: dict | None = None
    for seg in segments:
        if not isinstance(seg, dict):
            continue
        # Heuristic: nodes have `kind` (object class) and a name;
        # edges have `kind` (edge type) but no `properties.objectid`.
        looks_like_node = (
            ("name" in seg)
            or ("label" in seg and (seg.get("properties", {}) or {}).get("objectid"))
            or ("objectId" in seg)
            or (seg.get("kind", "").lower() in _KIND_MAP)
        )
        if looks_like_node:
            if cur_node is not None:
                steps.append(cur_node)
            cur_node = {
                "kind": _normalise_kind(seg.get("kind") or seg.get("label")),
                "name": _node_display_name(seg),
                "edge_out": None,
            }
        else:
            # It's an edge — attach to the previous node
            if cur_node is None:
                continue
            cur_node["edge_out"] = _edge_label(seg)
    if cur_node is not None:
        steps.append(cur_node)
    return steps


# ---------------------------------------------------------------------------
# Top-level loader — handles either input shape
# ---------------------------------------------------------------------------

def load_bloodhound(path: Path) -> dict:
    """Returns a normalised dict with: title, severity, cvss_score,
    cvss_vector, hosts, description, business_impact, remediation,
    mitre_attack, cwe, path (list of step dicts)."""
    raw = json.loads(path.read_text(encoding="utf-8", errors="replace"))

    # Shape A: simplified manual format (top-level keys + "path" list)
    if isinstance(raw, dict) and "path" in raw and isinstance(raw["path"], list):
        steps = []
        for s in raw["path"]:
            steps.append({
                "kind": _normalise_kind(s.get("kind")),
                "name": s.get("name", "?"),
                "edge_out": s.get("edge_out") or s.get("edge-out"),
            })
        return {
            "title": raw.get("title", "AD Attack Path"),
            "severity": raw.get("severity", "high"),
            "cvss_score": float(raw.get("cvss_score", 0.0)),
            "cvss_vector": raw.get("cvss_vector", ""),
            "hosts": list(raw.get("hosts", [])),
            "description": raw.get("description", "").strip(),
            "business_impact": raw.get("business_impact", "").strip(),
            "remediation": raw.get("remediation", "").strip(),
            "mitre_attack": list(raw.get("mitre_attack", [])),
            "cwe": list(raw.get("cwe", [])),
            "references": list(raw.get("references", [])),
            "compliance": list(raw.get("compliance", [])),
            "path_title": raw.get("path_title", "Attack Path"),
            "steps": steps,
        }

    # Shape B: BloodHound CE API response. We expect one of:
    #   {"data": {"nodes": [...], "edges": [...]}}                  ← graph
    #   {"data": [seg1, seg2, ...]}                                 ← single path
    #   {"data": {"paths": [[seg1, seg2, ...], ...]}}               ← multi path
    segments: list = []
    data = raw.get("data") if isinstance(raw, dict) else None
    if isinstance(data, list):
        segments = data
    elif isinstance(data, dict) and isinstance(data.get("paths"), list):
        # Take only the first path; bloodhound_to_typst is one-path-per-file.
        segments = data["paths"][0] if data["paths"] else []
    elif isinstance(raw, list):
        segments = raw

    steps = _segments_to_steps(segments)
    return {
        "title": "AD Attack Path (BloodHound)",
        "severity": "high",
        "cvss_score": 0.0,
        "cvss_vector": "",
        "hosts": [steps[-1]["name"]] if steps else [],
        "description": (
            "Path discovered via BloodHound graph traversal. Each step is a "
            "valid Active Directory permission or session edge that, when "
            "chained, terminates in the target principal."
        ),
        "business_impact": "",
        "remediation": "",
        "mitre_attack": [],
        "cwe": [],
        "references": [],
        "compliance": [],
        "path_title": "Attack Path",
        "steps": steps,
    }


# ---------------------------------------------------------------------------
# Typst emitter
# ---------------------------------------------------------------------------

def _emit_attack_path_call(steps: list[dict], title: str) -> str:
    """Generate the `#attack-path(...)` Typst expression."""
    if not steps:
        return '[_BloodHound path was empty._]'
    lines = ["#attack-path((\n"]
    for s in steps:
        kind = s.get("kind", "Node")
        name = s.get("name", "?")
        edge = s.get("edge_out") or s.get("edge-out")
        parts = [f'kind: {_typst_str(kind)}', f'name: {_typst_str(name)}']
        if edge:
            parts.append(f'edge-out: {_typst_str(edge)}')
        lines.append("    (" + ", ".join(parts) + "),\n")
    lines.append(f"  ), title: {_typst_str(title)})")
    return "".join(lines)


def _ad_finding_to_typst(f: dict, fid: str) -> str:
    """Render one loaded BloodHound finding to a `#finding(...)` block."""
    severity = f.get("severity", "high")
    score = float(f.get("cvss_score", 0.0))
    if score and severity == "high":
        severity = _severity_from_cvss(score)
    impact, likelihood = _impact_likelihood_from_severity(severity)
    risk, soph, remed = _triptych_from_severity(severity)

    vector = f.get("cvss_vector", "")
    criteria = parse_cvss_vector(vector) if vector else {}

    path_evidence = _emit_attack_path_call(
        f.get("steps", []),
        f.get("path_title", "Attack Path"),
    )

    fields = [
        ("id", _typst_str(fid)),
        ("title", _typst_str(f.get("title", "AD Attack Path"))),
        ("severity", _typst_str(severity)),
        ("cvss-score", str(score)),
    ]
    if vector:
        fields.append(("cvss-vector", _typst_str(vector)))
    if criteria:
        fields.append(("cvss-criteria", _typst_dict(criteria)))
    fields.extend([
        ("hosts", _typst_str_array(f.get("hosts", []))),
        ("impact", _typst_str(impact)),
        ("likelihood", _typst_str(likelihood)),
        ("status", _typst_str("open")),
        ("axis-risk", _typst_str(risk)),
        ("axis-sophistication", _typst_str(soph)),
        ("axis-remediation", _typst_str(remed)),
        ("description", _typst_content_block(
            f.get("description") or "[Describe the chain and its preconditions.]")),
        ("business-impact", _typst_content_block(
            f.get("business_impact") or
            "[State, in client terms, what an attacker controls when this path is walked.]")),
        # Evidence: the attack-path flow, plus optional cypher query
        ("evidence", "[\n  " + path_evidence + "\n]"),
        ("remediation", _typst_content_block(
            f.get("remediation") or "[Remove the load-bearing edge(s) — usually a permission, GPO link, or cert template ACL.]")),
    ])
    if f.get("mitre_attack"):
        fields.append(("mitre-attack", _typst_str_array(f["mitre_attack"])))
    if f.get("cwe"):
        fields.append(("cwe", _typst_str_array(f["cwe"])))
    if f.get("compliance"):
        fields.append(("compliance", _typst_str_array(f["compliance"])))
    if f.get("references"):
        fields.append(("references", _typst_str_array(f["references"])))

    rendered = ",\n  ".join(f"{k}: {v}" for k, v in fields)
    marker = ""
    drafted = f.get("_ai_drafted") or []
    if drafted:
        marker = (
            f"// AI-DRAFT: {', '.join(drafted)} "
            f"— review before publication\n"
        )
    return (
        f"// Source: bloodhound — {len(f.get('steps', []))} step(s)\n"
        f"{marker}"
        f"#finding(\n  {rendered},\n)\n"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list | None = None) -> int:
    p = argparse.ArgumentParser(
        description="BloodHound path JSON → Typst #finding(...) with #attack-path(...)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("paths", nargs="+", type=Path,
                   help="One or more BloodHound path JSON files")
    p.add_argument("-o", "--output", type=Path,
                   help="Output .typ file (default: stdout)")
    p.add_argument("--start-id", type=int, default=1,
                   help="Starting finding ID (default 1)")
    p.add_argument("--prefix", default="AD",
                   help="Finding ID prefix (default: AD → AD-001)")
    p.add_argument("--enrich", action="store_true",
                   help="Enrich via NVD + KEV + EPSS (rarely useful for AD chains, but supported)")
    p.add_argument("--draft-prose", action="store_true",
                   help="Use Anthropic API to draft business-impact + evidence-intro. "
                        "Requires ANTHROPIC_API_KEY.")
    p.add_argument("--llm-model", default="claude-sonnet-4-6",
                   help="LLM model (default: claude-sonnet-4-6)")
    p.add_argument("--client", default="[CLIENT NAME]",
                   help="Client name for --draft-prose context")
    p.add_argument("--industry", default="",
                   help="Client industry for --draft-prose context")

    args = p.parse_args(argv)

    out_lines: list[str] = [
        "// Generated by bloodhound_to_typst.py — AD attack chains.\n"
        "// Each #finding(...) contains a #attack-path(...) flow inside\n"
        "// its evidence: field. Splice into the main report after the\n"
        "// adapter-generated scanner findings.\n",
    ]

    kev = None
    if args.enrich:
        from enrich import get_kev_set, enrich_finding_dict
        kev = get_kev_set()
        print(f"[+] Enrichment enabled (KEV: {len(kev)} CVEs)",
              file=sys.stderr)

    n = args.start_id
    for path in args.paths:
        if not path.exists():
            print(f"[!] Missing: {path}", file=sys.stderr)
            return 2
        loaded = load_bloodhound(path)
        if args.enrich:
            enrich_finding_dict(loaded, kev_set=kev, verbose=True)
        if args.draft_prose:
            from draft_prose import apply_drafts
            apply_drafts(loaded, client=args.client, industry=args.industry,
                         model=args.llm_model, verbose=True)
        fid = f"{args.prefix}-{n:03d}"
        out_lines.append(_ad_finding_to_typst(loaded, fid))
        print(f"[+] {path}: {len(loaded['steps'])} step(s) → {fid}",
              file=sys.stderr)
        n += 1

    output = "\n".join(out_lines)
    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"[+] Wrote {n - args.start_id} finding(s) → {args.output}",
              file=sys.stderr)
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
