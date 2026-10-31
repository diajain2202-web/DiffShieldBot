"""
ingest_osv.py - Offline candidate ingestion from OSV.dev.

Fetches advisory candidates for ecosystem packages and writes to
data/fix_candidates.json ONLY (never the live index).
Promotion from candidates to fix_seed.json is strictly a human step
to prevent automated false-positive regressions.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import List, Dict, Any

import httpx

logger = logging.getLogger("diffshield.osv")


OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def query_osv_package(package_name: str, ecosystem: str = "npm") -> List[Dict[str, Any]]:
    """Query OSV for vulnerabilities in a package."""
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        }
    }
    try:
        resp = httpx.post(OSV_QUERY_URL, json=payload, timeout=10.0)
        if resp.status_code == 200:
            return resp.json().get("vulns", [])
    except Exception as err:
        logger.warning(f"Error querying OSV for {package_name}: {err}")
    return []


def ingest_candidates(packages: List[str], output_path: str = "data/fix_candidates.json") -> int:
    candidates = []
    for pkg in packages:
        vulns = query_osv_package(pkg)
        for v in vulns:
            candidates.append({
                "id": v.get("id"),
                "package": pkg,
                "summary": v.get("summary", ""),
                "details": v.get("details", ""),
                "references": v.get("references", []),
                "requires_human_review": True
            })

    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(candidates, indent=2), encoding="utf-8")
    print(f"Ingested {len(candidates)} candidate advisories into {output_path}")
    return len(candidates)


def main():
    parser = argparse.ArgumentParser(description="Ingest OSV candidate advisories")
    parser.add_argument("--packages", nargs="+", default=["lodash", "minimist", "qs", "semver", "express"])
    parser.add_argument("--out", default="data/fix_candidates.json")
    args = parser.parse_args()
    ingest_candidates(args.packages, args.out)


if __name__ == "__main__":
    main()

