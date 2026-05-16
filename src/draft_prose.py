#!/usr/bin/env python3
"""
draft_prose.py — fill the prose-only fields on a finding via Anthropic API.

What it drafts (and only these):
  • business-impact  — 2-4 sentence client-language paragraph
  • evidence intro   — 1-2 sentence narration prepended to raw payload

What it never touches:
  • CVSS score / vector / criteria
  • CWE / OWASP / MITRE / compliance / KEV flag
  • Hosts, IDs, references, severity
  These are sourced from scanners + NVD and are sacred. The LLM is shown
  them as context but cannot overwrite them.

Behavior rules (enforced in prompts + by post-processing):
  • Marker injection: every drafted field is tracked in `finding["_ai_drafted"]`
    so emitters can stamp `// AI-DRAFT` comments above the #finding(...) block.
  • Cache: results keyed by sha256 of inputs and cached to
    ~/.cache/cptc-toolkit/prose/. Same finding → free re-render.
  • No-key behavior: raises a clear RuntimeError. Adapters trap and
    fall through (the finding keeps its placeholder).
  • Cost: ~$0.01 per finding on Sonnet 4.6, ~$0.002 on Haiku 4.5.

Standalone usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    python3 src/draft_prose.py --check-key
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-sonnet-4-6"
HAIKU_MODEL = "claude-haiku-4-5-20251001"
USER_AGENT = "cptc-toolkit/0.6 (github.com/AndersonsRepo/cptc-toolkit)"

CACHE_DIR = Path.home() / ".cache" / "cptc-toolkit" / "prose"
CACHE_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Anthropic REST client (stdlib only)
# ---------------------------------------------------------------------------

def _api_key() -> str:
    k = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not k:
        raise RuntimeError(
            "ANTHROPIC_API_KEY env var not set — "
            "required for --draft-prose. Pipeline runs without it; just "
            "drop the flag to skip the LLM step."
        )
    return k


def _call_claude(
    system_prompt: str,
    user_prompt: str,
    model: str = DEFAULT_MODEL,
    max_tokens: int = 400,
) -> str:
    """One-shot Anthropic /v1/messages call. Returns the text content."""
    body = json.dumps({
        "model": model,
        "max_tokens": max_tokens,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_prompt}],
    }).encode("utf-8")
    req = urllib.request.Request(
        API_URL,
        data=body,
        headers={
            "x-api-key": _api_key(),
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
            "user-agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", errors="replace")[:300]
        raise RuntimeError(f"Anthropic API {e.code}: {msg}") from None
    except (urllib.error.URLError, TimeoutError) as e:
        raise RuntimeError(f"Anthropic API network error: {e}") from None

    content = data.get("content") or []
    if not content or content[0].get("type") != "text":
        raise RuntimeError(f"Unexpected response shape: {data}")
    return content[0]["text"].strip()


# ---------------------------------------------------------------------------
# Cache (sha256 of inputs → drafted text)
# ---------------------------------------------------------------------------

def _cache_key(kind: str, payload: dict) -> str:
    body = json.dumps({"kind": kind, **payload}, sort_keys=True)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]


def _cached(kind: str, payload: dict, fresh) -> str:
    """Cache wrapper. `fresh` is a 0-arg lambda producing the value."""
    key = _cache_key(kind, payload)
    f = CACHE_DIR / f"{kind}-{key}.txt"
    if f.exists():
        return f.read_text(encoding="utf-8")
    text = fresh()
    f.write_text(text, encoding="utf-8")
    return text


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

BUSINESS_IMPACT_SYSTEM = """You draft the "Business Impact" paragraph of a penetration-test finding.

OUTPUT FORMAT:
- Plain prose. 2-4 sentences. No bullets. No header. No preamble like "This finding...".
- Use client / business language, NOT technical jargon.
- Describe what an attacker who successfully exploits this CAN DO TO THE BUSINESS:
  data exposure, financial impact, regulatory consequence, operational disruption.

HARD RULES:
- Do NOT invent dollar amounts, customer counts, regulations, or industry-specific
  facts that aren't in the finding context.
- Do NOT restate the CVSS score or technical description.
- Do NOT suggest remediation (that goes in a separate field).
- Output ONLY the paragraph. No quotes, no markdown, no "Here's the paragraph:" framing.
"""

EVIDENCE_INTRO_SYSTEM = """You draft a 1-2 sentence introduction to the "Evidence" section of a pentest finding.

OUTPUT FORMAT:
- 1-2 sentences. Past tense, professional voice.
- State what was tested and the high-level result. The raw payload appears BELOW your intro.
- Refer to the payload as "the following" or "below". Never inline it.

HARD RULES:
- Do NOT restate the finding description verbatim.
- Do NOT include the actual request or response — those are the payload.
- Output ONLY the intro sentence(s). No quotes, no markdown, no preamble.
"""


# ---------------------------------------------------------------------------
# Drafting functions — these take + return plain dicts/strings
# ---------------------------------------------------------------------------

def draft_business_impact(
    finding: dict,
    client: str = "[CLIENT NAME]",
    industry: str = "",
    model: str = DEFAULT_MODEL,
) -> str:
    """Returns a 2-4 sentence business-impact paragraph for this finding."""
    in_kev = any(
        "CISA KEV" in str(c) for c in (finding.get("compliance") or [])
    )
    payload = {
        "client": client,
        "industry": industry,
        "title": finding.get("title", ""),
        "severity": finding.get("severity", ""),
        "cvss_score": finding.get("cvss_score", 0),
        "description": (finding.get("description") or "")[:1500],
        "kev": in_kev,
        "compliance": list(finding.get("compliance") or []),
        "hosts_count": len(finding.get("hosts") or []),
        "model": model,
    }

    def _fresh() -> str:
        ind_str = f" ({industry} industry)" if industry else ""
        user = (
            f"CLIENT: {client}{ind_str}\n\n"
            f"FINDING:\n"
            f"Title: {finding.get('title', '')}\n"
            f"Severity: {finding.get('severity', '')} (CVSS {finding.get('cvss_score', 0)})\n"
            f"Affected hosts: {len(finding.get('hosts') or [])} host(s)\n"
            f"{'CISA KEV — actively exploited in the wild.' if in_kev else ''}\n"
            f"Compliance touched: {', '.join(finding.get('compliance') or []) or 'n/a'}\n\n"
            f"Description:\n{(finding.get('description') or '')[:1500]}\n\n"
            f"Write the business-impact paragraph now."
        )
        return _call_claude(BUSINESS_IMPACT_SYSTEM, user, model=model, max_tokens=400)

    return _cached("impact", payload, _fresh)


def draft_evidence_intro(
    finding: dict,
    model: str = DEFAULT_MODEL,
) -> str:
    """Returns a short narration to prepend to the evidence section.
    Empty string if there's nothing to narrate."""
    raw_ev = (finding.get("evidence") or "").strip()
    if not raw_ev:
        return ""
    payload = {
        "title": finding.get("title", ""),
        "description": (finding.get("description") or "")[:600],
        "evidence_head": raw_ev[:300],
        "model": model,
    }

    def _fresh() -> str:
        user = (
            f"FINDING:\n"
            f"Title: {finding.get('title', '')}\n"
            f"Description: {(finding.get('description') or '')[:600]}\n\n"
            f"EVIDENCE PAYLOAD (first 300 chars, for context):\n{raw_ev[:300]}\n\n"
            f"Write the 1-2 sentence intro now."
        )
        return _call_claude(EVIDENCE_INTRO_SYSTEM, user, model=model, max_tokens=150)

    return _cached("evidence-intro", payload, _fresh)


# ---------------------------------------------------------------------------
# Top-level: apply draft pass to a finding dict (mutates + returns)
# ---------------------------------------------------------------------------

def apply_drafts(
    finding: dict,
    *,
    client: str = "[CLIENT NAME]",
    industry: str = "",
    model: str = DEFAULT_MODEL,
    verbose: bool = False,
) -> dict:
    """Run the LLM passes on a finding. Records which fields were drafted
    in finding['_ai_drafted'] so the emitter can stamp a marker comment."""
    drafted: list = list(finding.get("_ai_drafted") or [])

    # business-impact: only draft if empty / placeholder
    bi = (finding.get("business_impact") or "").strip()
    if len(bi) < 30 or bi.startswith("[Business impact pending"):
        if verbose:
            print(f"[draft] business-impact ← {finding.get('id') or finding.get('title','?')[:60]}",
                  file=sys.stderr)
        try:
            finding["business_impact"] = draft_business_impact(
                finding, client=client, industry=industry, model=model)
            drafted.append("business-impact")
        except RuntimeError as e:
            print(f"[draft] business-impact skipped: {e}", file=sys.stderr)

    # evidence narration: prepend if there's raw evidence and no narration yet
    raw_ev = (finding.get("evidence") or "").strip()
    if raw_ev and "[Evidence" not in raw_ev:
        if verbose:
            print(f"[draft] evidence-intro ← {finding.get('id') or finding.get('title','?')[:60]}",
                  file=sys.stderr)
        try:
            intro = draft_evidence_intro(finding, model=model)
            if intro:
                finding["evidence"] = intro + "\n\n" + raw_ev
                drafted.append("evidence-intro")
        except RuntimeError as e:
            print(f"[draft] evidence-intro skipped: {e}", file=sys.stderr)

    if drafted:
        finding["_ai_drafted"] = drafted
    return finding


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

def _standalone() -> int:
    import argparse
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--check-key", action="store_true",
                   help="Verify ANTHROPIC_API_KEY is set + reachable")
    args = p.parse_args()
    if args.check_key:
        try:
            _api_key()
            print("[+] ANTHROPIC_API_KEY is set.")
            # Send a 3-token ping
            text = _call_claude("You reply with one word.", "Say: ok",
                                model=HAIKU_MODEL, max_tokens=10)
            print(f"[+] API reachable. Haiku replied: {text!r}")
            return 0
        except RuntimeError as e:
            print(f"[!] {e}", file=sys.stderr)
            return 1
    p.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(_standalone())
