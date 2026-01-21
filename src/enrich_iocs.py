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

import argparse
import csv
import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse
from collections import Counter


@dataclass
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


MEDIUM_THREAT_KEYWORDS = {"phishing", "credential", "scam"}
MEDIUM_TAG_KEYWORDS = {"payload", "exe", "dropper", "ransomware", "stealer", "login", "fake", "spoof"}


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def load_iocs(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Project 1 format: {"generated_at":..., "count":..., "iocs":[...]}
    if isinstance(data, dict) and isinstance(data.get("iocs"), list):
        return data["iocs"]

    # Fallback: maybe it's already a list
    if isinstance(data, list):
        return data

    raise ValueError("Unexpected input JSON format. Expected dict with key 'iocs' or a list of records.")


def extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.hostname or ""
    except Exception:
        return ""


def split_tags(tags: str) -> List[str]:
    if not tags:
        return []
    return [t.strip().lower() for t in tags.split(",") if t.strip()]


def contains_any(text: str, keywords: set) -> bool:
    t = (text or "").lower()
    return any(k in t for k in keywords)


def score_risk(status: str, threat: str, tags: str) -> (str, str):
    """
    Simple triage:
    HIGH   = online (active)
    MEDIUM = offline but phishing/scam OR malware-relevant tags
    LOW    = offline + no strong indicators
    """
    st = (status or "").strip().lower()
    threat_l = (threat or "").strip().lower()
    tag_list = split_tags(tags)

    if st == "online":
        return "HIGH", "Status is online (active malicious infrastructure)."

    if contains_any(threat_l, MEDIUM_THREAT_KEYWORDS):
        return "MEDIUM", f"Threat type suggests phishing/scam activity ({threat})."

    if any(t in MEDIUM_TAG_KEYWORDS for t in tag_list):
        return "MEDIUM", "Offline but tags indicate malware delivery/severity or deception indicators."

    if st == "offline":
        return "LOW", "Status is offline; lower urgency but useful for historical hunting."
    return "LOW", "No high/medium indicators detected; treat as low priority."


def enrich_record(rec: Dict[str, Any]) -> EnrichedIOC:
    url = str(rec.get("url", "")).strip()
    host = str(rec.get("host", "")).strip()
    status = str(rec.get("url_status") or rec.get("status") or "").strip()
    date_added = str(rec.get("date_added", "")).strip()
    threat = str(rec.get("threat", "")).strip()
    tags = str(rec.get("tags", "")).strip()

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
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def write_csv(path: str, rows: List[EnrichedIOC]) -> None:
    fieldnames = list(asdict(rows[0]).keys()) if rows else [
        "url", "host", "status", "date_added", "threat", "tags", "domain", "risk_level", "risk_reason"
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(asdict(r))


def main() -> None:
    parser = argparse.ArgumentParser(description="Enrich URLhaus IOCs with risk scoring")
    parser.add_argument("--input", default="data/urlhaus_iocs.json", help="Input JSON from Project 1")
    parser.add_argument("--outdir", default="out", help="Output directory")
    args = parser.parse_args()

    ensure_dir(args.outdir)

    raw = load_iocs(args.input)

    # quick visibility into the dataset status distribution
    picked = [str(r.get("url_status") or r.get("status") or "").strip().lower() for r in raw]
    print("[debug] status counts:", Counter(picked).most_common(5))

    enriched = [enrich_record(r) for r in raw if str(r.get("url", "")).strip()]

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for e in enriched:
        counts[e.risk_level] = counts.get(e.risk_level, 0) + 1

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
    print(f"[+] Exported {len(enriched)} enriched IOCs to out/")
    print(f"[+] Risk counts: {counts}")


if __name__ == "__main__":
    main()
