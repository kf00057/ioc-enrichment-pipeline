#!/usr/bin/env python3
"""
IOC Enrichment Pipeline (Project 2)

Reads Project 1 output (URLhaus IOCs), enriches each record with:
- extracted domain (best-effort)
- risk_level (LOW / MEDIUM / HIGH)
- risk_reason (human-readable explanation)

Exports:
- out/enriched_iocs.json
- out/enriched_iocs.csv
- out/summary.json
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


# ---------------------------
# Data model
# ---------------------------

@dataclass(frozen=True)
class EnrichedIOC:
    url: str
    host: str
    status: str
    date_added: str
    threat: str
    tags: str
    domain: str
    risk_level: str
    risk_reason: str


# ---------------------------
# Risk scoring rules
# ---------------------------

RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"

MEDIUM_THREAT_KEYWORDS = {"phishing", "credential", "scam"}
MEDIUM_TAG_KEYWORDS = {"payload", "exe", "dropper", "ransomware", "stealer", "login", "fake", "spoof"}


# ---------------------------
# Helpers
# ---------------------------

def ensure_dir(path: str) -> None:
    """Create a directory if it doesn't already exist."""
    os.makedirs(path, exist_ok=True)


def load_iocs(path: str) -> List[Dict[str, Any]]:
    """
    Load URLhaus IOC records from Project 1 output JSON.

    Expected Project 1 format:
      {"generated_at": "...", "count": 123, "iocs": [ ...records... ]}
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict) and isinstance(data.get("iocs"), list):
        return data["iocs"]

    if isinstance(data, list):
        return data

    raise ValueError("Unexpected input JSON format. Expected dict with key 'iocs' or a list of records.")


def extract_domain(url: str) -> str:
    """Extract hostname from a URL; return empty string on failure."""
    try:
        parsed = urlparse(url)
        return parsed.hostname or ""
    except Exception:
        return ""


def split_tags(tags: str) -> List[str]:
    """Split comma-separated tag string into normalized list."""
    if not tags:
        return []
    return [t.strip().lower() for t in tags.split(",") if t.strip()]


def norm(s: Any) -> str:
    """Normalize any value into a trimmed string."""
    return str(s or "").strip()


def norm_lower(s: Any) -> str:
    """Normalize any value into a trimmed lowercase string."""
    return norm(s).lower()


def contains_any_word(text: str, keywords: set[str]) -> bool:
    """
    Check if any keyword appears as a word-ish match in text.

    This avoids accidental substring matches (best-effort).
    """
    t = (text or "").lower()
    # simple safe-ish boundary check without regex complexity
    for k in keywords:
        if f" {k} " in f" {t} ":
            return True
    return False


def score_risk(status: str, threat: str, tags: str) -> Tuple[str, str]:
    """
    Simple triage:
    HIGH   = online (active)
    MEDIUM = offline but phishing/scam OR malware-relevant tags
    LOW    = offline + no strong indicators
    """
    st = norm_lower(status)
    threat_l = norm_lower(threat)
    tag_list = split_tags(tags)

    # HIGH: Only active infrastructure
    if st == "online":
        return RISK_HIGH, "Status is online (active malicious infrastructure)."

    # MEDIUM: phishing/scam keywords
    if contains_any_word(threat_l, MEDIUM_THREAT_KEYWORDS):
        return RISK_MEDIUM, f"Threat type suggests phishing/scam activity ({threat})."

    # MEDIUM: malware delivery / severity tags (offline but relevant)
    if any(t in MEDIUM_TAG_KEYWORDS for t in tag_list):
        return RISK_MEDIUM, "Offline but tags indicate malware delivery/severity or deception indicators."

    # LOW: everything else
    if st == "offline":
        return RISK_LOW, "Status is offline; lower urgency but useful for historical hunting."
    return RISK_LOW, "No high/medium indicators detected; treat as low priority."


def enrich_record(rec: Dict[str, Any]) -> Optional[EnrichedIOC]:
    """Convert a raw record into an EnrichedIOC. Returns None if URL is missing."""
    url = norm(rec.get("url"))
    if not url:
        return None

    host = norm(rec.get("host"))
    status = norm(rec.get("url_status") or rec.get("status"))
    date_added = norm(rec.get("date_added"))
    threat = norm(rec.get("threat"))
    tags = norm(rec.get("tags"))

    domain = extract_domain(url) or host
    risk_level, risk_reason = score_risk(status, threat, tags)

    return EnrichedIOC(
        url=url,
        host=host,
        status=status,
        date_added=date_added,
        threat=threat,
        tags=tags,
        domain=domain,
        risk_level=risk_level,
        risk_reason=risk_reason,
    )


def write_json(path: str, payload: Any) -> None:
    """Write JSON to disk (pretty-printed)."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def write_csv(path: str, rows: List[EnrichedIOC]) -> None:
    """Write enriched IOCs to CSV."""
    fieldnames = list(asdict(rows[0]).keys()) if rows else [
        "url", "host", "status", "date_added", "threat", "tags", "domain", "risk_level", "risk_reason"
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(asdict(r))


# ---------------------------
# CLI
# ---------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Enrich URLhaus IOCs with risk scoring")
    p.add_argument("--input", default="data/urlhaus_iocs.json", help="Input JSON from Project 1")
    p.add_argument("--outdir", default="out", help="Output directory")
    p.add_argument("--verbose", action="store_true", help="Print extra dataset diagnostics")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    ensure_dir(args.outdir)

    raw = load_iocs(args.input)

    if args.verbose:
        picked = [norm_lower(r.get("url_status") or r.get("status")) for r in raw]
        print("[info] status counts:", Counter(picked).most_common(5))

    enriched: List[EnrichedIOC] = []
    for r in raw:
        e = enrich_record(r)
        if e is not None:
            enriched.append(e)

    counts = {RISK_HIGH: 0, RISK_MEDIUM: 0, RISK_LOW: 0}
    for e in enriched:
        counts[e.risk_level] += 1

    now = datetime.now(timezone.utc).isoformat()

    json_out = os.path.join(args.outdir, "enriched_iocs.json")
    csv_out = os.path.join(args.outdir, "enriched_iocs.csv")
    summary_out = os.path.join(args.outdir, "summary.json")

    write_json(
        json_out,
        {
            "generated_at": now,
            "input_file": args.input,
            "count": len(enriched),
            "risk_counts": counts,
            "iocs": [asdict(e) for e in enriched],
        },
    )
    write_csv(csv_out, enriched)
    write_json(summary_out, {"generated_at": now, "count": len(enriched), "risk_counts": counts})

    print(f"[*] Loaded {len(raw)} raw IOCs")
    print(f"[+] Exported {len(enriched)} enriched IOCs to {args.outdir}/")
    print(f"[+] Risk counts: {counts}")


if __name__ == "__main__":
    main()
