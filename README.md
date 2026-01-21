# IOC Enrichment Pipeline (URLhaus)

A Python pipeline that enriches threat-intel Indicators of Compromise (IOCs) from **URLhaus** and applies **rule-based risk scoring** (HIGH / MEDIUM / LOW). Outputs JSON + CSV files you can use for triage, threat hunting, and reporting.

## What this does
- Loads IOC records from a URLhaus JSON export (Project 1 output format)
- Extracts domains from URLs (best-effort)
- Assigns a risk level:
  - **HIGH**: IOC is `online` (active infrastructure)
  - **MEDIUM**: IOC is `offline` but contains phishing/scam indicators or malware-relevant tags
  - **LOW**: IOC is `offline` and has no strong indicators
- Exports:
  - `out/enriched_iocs.json`
  - `out/enriched_iocs.csv`
  - `out/summary.json`

## Why it matters
This turns a raw threat-intel feed into **actionable output**:
- prioritize what to investigate first (online/high urgency)
- keep offline items for historical hunting and correlation
- produce artifacts that are easy to share and analyze (CSV/JSON + summary)

## Data source
This project is designed to work with **URLhaus** data (abuse.ch).  
Input format matches Project 1 output: `{"generated_at": "...", "count": N, "iocs": [...]}`.

> Note: This repo intentionally does **not** commit large datasets or generated outputs. Run the pipeline locally to generate results.

## Setup
Create a virtual environment (recommended) and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
