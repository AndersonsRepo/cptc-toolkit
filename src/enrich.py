#!/usr/bin/env python3
"""
enrich.py — CVE enrichment against canonical public data sources.

Sources hit (in order, all free, no API key required):
  • NVD API 2.0       (services.nvd.nist.gov)
        → canonical CVSS v3.1 score + vector + CWE list + description
  • CISA KEV catalog  (cisa.gov/sites/default/files/feeds/...)
        → boolean flag: is this CVE in the Known Exploited list?
  • EPSS API          (api.first.org/data/v1/epss)
        → 0–1 exploitation probability → mapped to likelihood label

Cache
-----
Everything caches to ~/.cache/cptc-toolkit/ with sensible TTLs so the same
CVE is never re-fetched within a single competition. Stale cache is
preferred over a hard failure when an API is down.

Usage
-----
Imported by scanner_to_typst.py and bloodhound_to_typst.py via their
`--enrich` flag. Can also be run standalone for ad-hoc lookups:

    python3 src/enrich.py CVE-2021-44228 CVE-2024-3094

Adding an NIST API key (optional, raises NVD rate from 5/30s to 50/30s):

    export NVD_API_KEY=your-key-here
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CACHE_DIR = Path.home() / ".cache" / "cptc-toolkit"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

UA = "cptc-toolkit/0.3 (https://github.com/AndersonsRepo/cptc-toolkit)"
NVD_KEY = os.environ.get("NVD_API_KEY", "").strip()

# Cache TTLs (seconds)
NVD_TTL  = 7 * 86400    # CVE records change rarely
KEV_TTL  =     86400    # KEV catalog updates daily
EPSS_TTL =     86400    # EPSS recomputes daily

# Sleep between NVD calls to respect rate limit (5/30s without key)
_NVD_LAST_CALL: dict = {"t": 0.0}
_NVD_INTERVAL = 6.5 if not NVD_KEY else 0.7

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# ---------------------------------------------------------------------------
# HTTP with cache + graceful fallback
# ---------------------------------------------------------------------------

def _cached_get(url: str, cache_key: str, ttl: int,
                headers: dict | None = None) -> Any:
    """GET with disk cache. Returns parsed JSON or None on failure."""
    cache_file = CACHE_DIR / cache_key
    if cache_file.exists():
        age = time.time() - cache_file.stat().st_mtime
        if age < ttl:
            try:
                return json.loads(cache_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                cache_file.unlink(missing_ok=True)

    req_headers = {"User-Agent": UA, "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        data = json.loads(body)
        cache_file.write_text(json.dumps(data), encoding="utf-8")
        return data
    except (urllib.error.URLError, urllib.error.HTTPError,
            json.JSONDecodeError, TimeoutError) as e:
        print(f"[!] fetch failed for {url}: {e}", file=sys.stderr)
        # Return stale cache if available
        if cache_file.exists():
            print(f"[i] returning stale cache for {cache_key}", file=sys.stderr)
            try:
                return json.loads(cache_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        return None


# ---------------------------------------------------------------------------
# NVD (CVE → CVSS, CWE, description)
# ---------------------------------------------------------------------------

def get_nvd(cve: str) -> dict | None:
    """Return the `cve` object from NVD API 2.0, or None."""
    cve = cve.upper()
    if not CVE_RE.fullmatch(cve):
        return None
    # Rate-limit
    wait = _NVD_INTERVAL - (time.time() - _NVD_LAST_CALL["t"])
    if wait > 0:
        time.sleep(wait)
    _NVD_LAST_CALL["t"] = time.time()

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
    headers = {"apiKey": NVD_KEY} if NVD_KEY else None
    data = _cached_get(url, f"nvd-{cve}.json", NVD_TTL, headers=headers)
    if not data:
        return None
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None
    return vulns[0].get("cve", {})


def nvd_cvss(cve_obj: dict) -> tuple[float, str]:
    """Pull (baseScore, vectorString) from CVSS v3.1 if present, else v3.0."""
    metrics = cve_obj.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        items = metrics.get(key) or []
        if not items:
            continue
        primary = next((m for m in items
                        if m.get("type") == "Primary"), items[0])
        d = primary.get("cvssData", {}) or {}
        return float(d.get("baseScore", 0)), str(d.get("vectorString", ""))
    return 0.0, ""


def nvd_cwes(cve_obj: dict) -> list:
    out: list = []
    seen = set()
    for w in cve_obj.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            v = (d.get("value") or "").strip()
            if v.upper().startswith("CWE-") and v not in seen:
                seen.add(v)
                out.append(v)
    return out


def nvd_description(cve_obj: dict) -> str:
    for d in cve_obj.get("descriptions", []) or []:
        if (d.get("lang") or "").lower() == "en":
            return (d.get("value") or "").strip()
    return ""


# ---------------------------------------------------------------------------
# CISA KEV (single catalog file → set of CVEs)
# ---------------------------------------------------------------------------

_kev_cache: dict = {"set": None, "raw": None, "t": 0.0}


def get_kev_set() -> set:
    """Return the set of all CVEs currently in CISA KEV."""
    if _kev_cache["set"] is not None and (time.time() - _kev_cache["t"]) < KEV_TTL:
        return _kev_cache["set"]
    url = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )
    data = _cached_get(url, "kev.json", KEV_TTL)
    if not data:
        return set()
    s = {v.get("cveID", "").upper()
         for v in (data.get("vulnerabilities") or [])
         if v.get("cveID")}
    _kev_cache["set"] = s
    _kev_cache["raw"] = data
    _kev_cache["t"] = time.time()
    return s


def kev_entry(cve: str) -> dict | None:
    """Return the KEV catalog entry for a CVE, or None."""
    get_kev_set()
    raw = _kev_cache.get("raw") or {}
    for v in raw.get("vulnerabilities", []) or []:
        if (v.get("cveID") or "").upper() == cve.upper():
            return v
    return None


# ---------------------------------------------------------------------------
# EPSS (per-CVE exploit probability 0..1)
# ---------------------------------------------------------------------------

def get_epss(cve: str) -> float:
    """Return the EPSS probability (0..1), or 0.0 if unknown."""
    url = f"https://api.first.org/data/v1/epss?cve={cve.upper()}"
    data = _cached_get(url, f"epss-{cve.upper()}.json", EPSS_TTL)
    if not data:
        return 0.0
    items = data.get("data") or []
    if not items:
        return 0.0
    try:
        return float(items[0].get("epss") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def epss_to_likelihood(score: float) -> str:
    """Map EPSS probability to a likelihood label."""
    if score >= 0.5:
        return "High"
    if score >= 0.1:
        return "Medium"
    if score > 0:
        return "Low"
    return ""


# ---------------------------------------------------------------------------
# CWE boilerplate (v0.4)
# ---------------------------------------------------------------------------

_CWE_BOILERPLATE: dict | None = None


def _load_boilerplate() -> dict:
    """Load and cache the bundled CWE boilerplate JSON."""
    global _CWE_BOILERPLATE
    if _CWE_BOILERPLATE is not None:
        return _CWE_BOILERPLATE
    # data/cwe-boilerplate.json lives two levels up from this file
    candidates = [
        Path(__file__).resolve().parent.parent / "data" / "cwe-boilerplate.json",
        Path(__file__).resolve().parent / "data" / "cwe-boilerplate.json",
        Path.cwd() / "data" / "cwe-boilerplate.json",
    ]
    for p in candidates:
        if p.exists():
            _CWE_BOILERPLATE = json.loads(p.read_text(encoding="utf-8"))
            return _CWE_BOILERPLATE
    print(f"[!] cwe-boilerplate.json not found — searched: {candidates}",
          file=sys.stderr)
    _CWE_BOILERPLATE = {}
    return _CWE_BOILERPLATE


def boilerplate_for_cwe(cwe: str) -> dict | None:
    """Return the boilerplate dict for a CWE (e.g. 'CWE-89'), or None."""
    book = _load_boilerplate()
    return book.get(cwe.upper())


def apply_boilerplate(f: dict) -> dict:
    """Fill empty description/remediation/references from CWE boilerplate.

    Never overwrites scanner-supplied text. Uses the FIRST CWE on the
    finding as the lookup key (most findings tie to a single weakness).
    """
    cwes = f.get("cwe") or []
    if not cwes:
        return f
    bp = boilerplate_for_cwe(cwes[0])
    if not bp:
        return f
    # Description — only fill if scanner produced a short / empty one
    if len((f.get("description") or "").strip()) < 50:
        f["description"] = bp.get("description", f.get("description", ""))
    # Remediation — same rule
    if len((f.get("remediation") or "").strip()) < 30:
        f["remediation"] = bp.get("remediation", f.get("remediation", ""))
    # References — union (preserve scanner-provided refs)
    refs = list(f.get("references") or [])
    for r in bp.get("references", []) or []:
        if r not in refs:
            refs.append(r)
    f["references"] = refs
    return f


# ---------------------------------------------------------------------------
# Finding enrichment
# ---------------------------------------------------------------------------

def extract_cves(finding: dict) -> list:
    """Find every CVE-like string in references, title, description, evidence."""
    blob = " ".join([
        finding.get("title", "") or "",
        finding.get("description", "") or "",
        finding.get("evidence", "") or "",
        " ".join(finding.get("references", []) or []),
    ])
    seen: set = set()
    out: list = []
    for m in CVE_RE.finditer(blob):
        c = m.group(0).upper()
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def enrich_finding_dict(f: dict, *, kev_set: set | None = None,
                        verbose: bool = False,
                        use_boilerplate: bool = True) -> dict:
    """Enrich a finding (mutates and returns it).

    Order of operations:
      1. Online lookups (NVD → CWE list + CVSS, KEV, EPSS) — needs CVE
      2. Boilerplate fill (CWE-keyed local data) — needs CWE, runs even
         when there's no CVE so SAST/DAST findings benefit too
    """
    if kev_set is None:
        kev_set = get_kev_set()

    cves = extract_cves(f)
    if not cves:
        # No CVE — but we may still have a CWE from the scanner, so try
        # the boilerplate pass before returning.
        if use_boilerplate:
            apply_boilerplate(f)
        return f

    # Use the first CVE for canonical lookup (most findings tie to one CVE)
    cve = cves[0]
    if verbose:
        print(f"[enrich] {cve}", file=sys.stderr)

    nvd = get_nvd(cve)
    if nvd:
        score, vector = nvd_cvss(nvd)
        if score and not f.get("cvss_score"):
            f["cvss_score"] = score
        if vector and not f.get("cvss_vector"):
            f["cvss_vector"] = vector
        cwes = nvd_cwes(nvd)
        if cwes:
            existing = list(f.get("cwe") or [])
            merged = list(dict.fromkeys(existing + cwes))
            f["cwe"] = merged
        # Only back-fill description if scanner didn't provide one
        desc = nvd_description(nvd)
        if desc and len((f.get("description") or "").strip()) < 50:
            f["description"] = desc

    # KEV — append compliance tag + bump risk axis
    if cve in kev_set:
        comp = list(f.get("compliance") or [])
        flag = f"CISA KEV (actively exploited)"
        if flag not in comp:
            comp.append(flag)
        f["compliance"] = comp
        f["axis_risk"] = "high"
        f["axis_sophistication"] = "low"
        # KEV entry has dueDate, ransomware use, etc. — append note
        entry = kev_entry(cve)
        if entry and entry.get("knownRansomwareCampaignUse") == "Known":
            f["business_impact"] = (
                (f.get("business_impact") or "").rstrip()
                + ("\n\n" if f.get("business_impact") else "")
                + f"CISA notes this CVE is used in known ransomware campaigns."
            ).strip()

    # EPSS — likelihood
    epss = get_epss(cve)
    if epss > 0:
        lik = epss_to_likelihood(epss)
        if lik:
            # Always prefer EPSS over scanner heuristic — it's empirical
            f["likelihood"] = lik

    # Make sure NVD URL is in references (idempotent)
    refs = list(f.get("references") or [])
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve}"
    if nvd_url not in refs:
        refs.append(nvd_url)
    f["references"] = refs

    # Final pass: CWE boilerplate fill (now that NVD may have given us CWEs)
    if use_boilerplate:
        apply_boilerplate(f)

    return f


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

def _standalone(argv: list) -> int:
    if not argv:
        print("Usage: enrich.py CVE-... [CVE-...]", file=sys.stderr)
        return 2
    kev = get_kev_set()
    print(f"[i] KEV catalog: {len(kev)} CVEs cached.", file=sys.stderr)
    out = {}
    for cve in argv:
        cve = cve.upper()
        if not CVE_RE.fullmatch(cve):
            print(f"[!] not a CVE: {cve}", file=sys.stderr)
            continue
        nvd = get_nvd(cve)
        score, vector = nvd_cvss(nvd or {})
        cwes = nvd_cwes(nvd or {})
        desc = nvd_description(nvd or {})
        out[cve] = {
            "in_kev": cve in kev,
            "cvss_score": score,
            "cvss_vector": vector,
            "cwe": cwes,
            "epss": get_epss(cve),
            "description": desc[:200] + ("..." if len(desc) > 200 else ""),
        }
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_standalone(sys.argv[1:]))
