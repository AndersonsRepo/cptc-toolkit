#!/usr/bin/env python3
"""
build_report.py — one-shot CPTC report builder.

Auto-detects scanner outputs in a directory, runs every adapter with
enrichment, splices the result into the bundled Typst template, and
(optionally) compiles to PDF.

Designed to be invoked from the `cptc-report` Claude skill but also
runnable standalone:

    python3 build_report.py --scans ./scans --out ./out --enrich \\
        --client "OuiCroissant" --engagement "CPTC10-Finals"

The script makes no network calls except the ones --enrich enables
(NVD / KEV / EPSS). All other operations are local.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
TOOLKIT_SRC = REPO_ROOT / "src"
TOOLKIT_TPL = REPO_ROOT / "template" / "vulnerability-report.typ"


def detect_inputs(scans_dir: Path) -> dict:
    """Glob the scans dir into category lists."""
    found = {
        "nuclei": sorted(
            [*scans_dir.glob("nuclei*.jsonl"),
             *scans_dir.glob("nuclei*.json")]
        ),
        "sarif": sorted(scans_dir.glob("*.sarif")),
        "bloodhound": sorted(
            [*scans_dir.glob("bloodhound*.json"),
             *scans_dir.glob("bh-*.json")]
        ),
        "metadata": scans_dir / "report-metadata.json",
    }
    # Don't classify bloodhound files as generic nuclei
    found["nuclei"] = [
        p for p in found["nuclei"]
        if not p.name.startswith("bloodhound")
        and not p.name.startswith("bh-")
    ]
    return found


def load_metadata(scans_dir: Path, overrides: dict) -> dict:
    """Load report-metadata.json if present, override with CLI args."""
    meta_path = scans_dir / "report-metadata.json"
    base: dict = {}
    if meta_path.exists():
        try:
            base = json.loads(meta_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            print(f"[!] report-metadata.json: {e}", file=sys.stderr)
    base.update({k: v for k, v in overrides.items() if v})
    return base


def patch_template(meta: dict, out_path: Path,
                   scanner_findings: str, ad_findings: str) -> None:
    """Inline-edit the template with metadata + findings, write to out_path."""
    tpl = TOOLKIT_TPL.read_text(encoding="utf-8")

    # Metadata substitutions (always-safe: only replace the EDIT block)
    subs = {
        '#let client          = "[CLIENT NAME]"':
            f'#let client          = "{meta.get("client", "[CLIENT NAME]")}"',
        '#let report_title    = "External Penetration Test Report"':
            f'#let report_title    = "{meta.get("report_title", "External Penetration Test Report")}"',
        '#let engagement_id   = "ENG-2026-001"':
            f'#let engagement_id   = "{meta.get("engagement_id", "ENG-2026-001")}"',
        '#let assessor_org    = "[YOUR FIRM]"':
            f'#let assessor_org    = "{meta.get("assessor_org", "[YOUR FIRM]")}"',
    }
    for old, new in subs.items():
        if old in tpl:
            tpl = tpl.replace(old, new)

    # Strip the 3 hand-written sample findings; inject ours
    start = "== Critical Findings"
    end = "// ── 20. REMEDIATION ROADMAP"
    if start in tpl and end in tpl:
        i = tpl.index(start)
        j = tpl.index(end)
        replacement_parts = []
        if scanner_findings.strip():
            replacement_parts.append(
                "== Findings (scanner-generated)\n\n" + scanner_findings + "\n\n"
            )
        if ad_findings.strip():
            replacement_parts.append(
                "== Active Directory Findings\n\n" + ad_findings + "\n\n"
            )
        if not replacement_parts:
            replacement_parts.append(
                "== Findings\n\n_No findings supplied._\n\n"
            )
        tpl = tpl[:i] + "".join(replacement_parts) + tpl[j:]

    out_path.write_text(tpl, encoding="utf-8")


def run_step(label: str, cmd: list) -> bool:
    print(f"[+] {label}: {' '.join(str(c) for c in cmd)}", file=sys.stderr)
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"    stderr: {res.stderr.strip()}", file=sys.stderr)
        return False
    if res.stderr.strip():
        # Adapters write progress to stderr — surface it
        for line in res.stderr.strip().splitlines():
            print(f"    {line}", file=sys.stderr)
    return True


def find_typst() -> str | None:
    """Locate a typst binary. Prefer PATH, fall back to /tmp/ download."""
    p = shutil.which("typst")
    if p:
        return p
    # Try the /tmp install the toolkit uses for compile-tests
    fallback = Path("/tmp/typst-aarch64-apple-darwin/typst")
    if fallback.exists():
        return str(fallback)
    return None


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="One-shot CPTC report builder.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--scans", required=True, type=Path,
                    help="Directory containing scanner outputs")
    ap.add_argument("--out", required=True, type=Path,
                    help="Output directory for findings.typ + report.{typ,pdf}")
    ap.add_argument("--enrich", action="store_true",
                    help="Enable NVD + CISA KEV + EPSS + CWE boilerplate pass")
    ap.add_argument("--client", default="",
                    help="Override report client name")
    ap.add_argument("--engagement", default="",
                    help="Override engagement ID")
    ap.add_argument("--assessor", default="",
                    help="Override assessor / firm name")
    ap.add_argument("--report-title", default="",
                    help="Override report title")
    ap.add_argument("--no-compile", action="store_true",
                    help="Skip the typst compile step (write .typ only)")
    ap.add_argument("--draft-prose", action="store_true",
                    help="LLM pass on business-impact + evidence-intro fields. "
                         "Requires ANTHROPIC_API_KEY.")
    ap.add_argument("--llm-model", default="claude-sonnet-4-6",
                    help="Model for --draft-prose (default: claude-sonnet-4-6)")
    ap.add_argument("--llm-mode", default="auto", choices=("auto", "api", "cli"),
                    help="LLM backend: api | cli (Claude Code subscription) | auto")
    ap.add_argument("--industry", default="",
                    help="Client industry for --draft-prose context")
    args = ap.parse_args(argv)

    if not args.scans.exists():
        print(f"[!] --scans dir not found: {args.scans}", file=sys.stderr)
        return 2
    args.out.mkdir(parents=True, exist_ok=True)

    inputs = detect_inputs(args.scans)
    print(
        f"[+] Detected inputs: "
        f"nuclei={len(inputs['nuclei'])} sarif={len(inputs['sarif'])} "
        f"bloodhound={len(inputs['bloodhound'])}",
        file=sys.stderr,
    )

    meta = load_metadata(args.scans, {
        "client": args.client,
        "engagement_id": args.engagement,
        "assessor_org": args.assessor,
        "report_title": args.report_title,
    })

    prose_args: list = []
    if args.draft_prose:
        prose_args = [
            "--draft-prose",
            "--llm-model", args.llm_model,
            "--llm-mode", args.llm_mode,
            "--client", meta.get("client") or "[CLIENT NAME]",
        ]
        if args.industry:
            prose_args += ["--industry", args.industry]

    # Run scanner_to_typst.py if we have any input it accepts
    scanner_out = args.out / "findings.typ"
    if inputs["nuclei"] or inputs["sarif"]:
        cmd: list = [sys.executable, str(TOOLKIT_SRC / "scanner_to_typst.py")]
        for p in inputs["nuclei"]:
            cmd += ["--nuclei", str(p)]
        for p in inputs["sarif"]:
            cmd += ["--sarif", str(p)]
        cmd += ["-o", str(scanner_out)]
        if args.enrich:
            cmd.append("--enrich")
        cmd += prose_args
        if not run_step("scanner_to_typst", cmd):
            return 3
    else:
        scanner_out.write_text("", encoding="utf-8")

    # Run bloodhound_to_typst.py if we have any path JSON
    ad_out = args.out / "ad-findings.typ"
    if inputs["bloodhound"]:
        cmd = [
            sys.executable, str(TOOLKIT_SRC / "bloodhound_to_typst.py"),
            *[str(p) for p in inputs["bloodhound"]],
            "-o", str(ad_out),
        ]
        if args.enrich:
            cmd.append("--enrich")
        cmd += prose_args
        if not run_step("bloodhound_to_typst", cmd):
            return 4
    else:
        ad_out.write_text("", encoding="utf-8")

    # Splice into template
    report_typ = args.out / "report.typ"
    patch_template(
        meta=meta,
        out_path=report_typ,
        scanner_findings=scanner_out.read_text(encoding="utf-8"),
        ad_findings=ad_out.read_text(encoding="utf-8"),
    )
    print(f"[+] Wrote {report_typ}", file=sys.stderr)

    # Compile
    if args.no_compile:
        print("[i] --no-compile set; skipping PDF render.", file=sys.stderr)
        return 0
    typst = find_typst()
    if not typst:
        print(
            "[i] typst not found on PATH. Install with `brew install typst` "
            "or run the .typ through https://typst.app .",
            file=sys.stderr,
        )
        return 0
    pdf_out = args.out / "report.pdf"
    cmd = [typst, "compile", str(report_typ), str(pdf_out)]
    if not run_step("typst compile", cmd):
        return 5
    print(f"[+] Wrote {pdf_out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
