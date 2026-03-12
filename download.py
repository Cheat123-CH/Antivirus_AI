"""
download.py — Database Downloader
Member 4: AI Explanation Module | Sentinel AI Security Suite

Run this ONCE before first launch to download MITRE ATT&CK and NIST SP 800-53
data and save them locally in the databases/ folder.

The app works without this (Gemini falls back to built-in knowledge),
but having local databases makes explanations more accurate and faster.

Usage:
    python download.py
    python download.py --force   # re-download even if files already exist
"""

import requests
import json
import os
import sys
import argparse
import time

DB_DIR = os.path.join(os.path.dirname(__file__), "databases")


def _print_progress(message: str, success: bool = True) -> None:
    icon = "✅" if success else "❌"
    print(f"{icon}  {message}")


def download_mitre(force: bool = False) -> bool:
    """Download and parse MITRE ATT&CK enterprise techniques."""
    out_path = os.path.join(DB_DIR, "mitre_full.json")

    if os.path.exists(out_path) and not force:
        size_kb = os.path.getsize(out_path) // 1024
        _print_progress(f"MITRE database already exists ({size_kb} KB). Use --force to re-download.")
        return True

    print("⏳  Downloading MITRE ATT&CK (enterprise, latest)...")
    url = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "master/enterprise-attack/enterprise-attack-16.1.json"
    )

    try:
        resp = requests.get(url, timeout=90, stream=True)
        resp.raise_for_status()
        raw = resp.json()
    except requests.RequestException as e:
        _print_progress(f"MITRE download failed: {e}", success=False)
        return False

    techniques = []
    for obj in raw.get("objects", []):
        # Only attack-pattern objects that are not revoked
        if obj.get("type") != "attack-pattern" or obj.get("revoked", False):
            continue

        # Extract technique ID from external references
        tech_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id", "")
                break

        # Skip sub-techniques (T1234.001)
        if not tech_id or "." in tech_id:
            continue

        tactics = [
            phase["phase_name"].replace("-", " ").title()
            for phase in obj.get("kill_chain_phases", [])
        ]

        description = obj.get("description", "")
        # Remove citation markers like (Citation: ...) to keep descriptions clean
        import re
        description = re.sub(r"\(Citation:[^)]+\)", "", description).strip()

        techniques.append({
            "id":          tech_id,
            "name":        obj.get("name", ""),
            "tactic":      ", ".join(tactics),
            "description": description[:400],
        })

    # Sort by ID for predictable ordering
    techniques.sort(key=lambda t: t["id"])

    os.makedirs(DB_DIR, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"techniques": techniques}, f, indent=2, ensure_ascii=False)

    size_kb = os.path.getsize(out_path) // 1024
    _print_progress(f"MITRE saved — {len(techniques)} techniques → databases/mitre_full.json ({size_kb} KB)")
    return True


def download_nist(force: bool = False) -> bool:
    """Download and parse NIST SP 800-53 Rev 5 controls."""
    out_path = os.path.join(DB_DIR, "nist_full.json")

    if os.path.exists(out_path) and not force:
        size_kb = os.path.getsize(out_path) // 1024
        _print_progress(f"NIST database already exists ({size_kb} KB). Use --force to re-download.")
        return True

    print("⏳  Downloading NIST SP 800-53 Rev 5...")
    url = (
        "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
        "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
    )

    try:
        resp = requests.get(url, timeout=90)
        resp.raise_for_status()
        raw = resp.json()
    except requests.RequestException as e:
        _print_progress(f"NIST download failed: {e}", success=False)
        return False

    controls = []
    groups = raw.get("catalog", {}).get("groups", [])

    for group in groups:
        family = group.get("title", "")
        for control in group.get("controls", []):
            ctrl_id   = control.get("id", "").upper()
            ctrl_name = control.get("title", "")

            # Extract statement prose
            description = ""
            for part in control.get("parts", []):
                if part.get("name") == "statement":
                    prose = part.get("prose", "")
                    if prose:
                        description = prose[:400]
                        break

            controls.append({
                "id":          ctrl_id,
                "name":        ctrl_name,
                "family":      family,
                "description": description,
            })

    # Sort by ID
    controls.sort(key=lambda c: c["id"])

    os.makedirs(DB_DIR, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"controls": controls}, f, indent=2, ensure_ascii=False)

    size_kb = os.path.getsize(out_path) // 1024
    _print_progress(f"NIST saved — {len(controls)} controls → databases/nist_full.json ({size_kb} KB)")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download MITRE ATT&CK and NIST SP 800-53 databases for Sentinel AI."
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Re-download databases even if they already exist."
    )
    args = parser.parse_args()

    print("=" * 55)
    print("  Sentinel AI — Database Downloader")
    print("=" * 55)
    start = time.time()

    mitre_ok = download_mitre(force=args.force)
    nist_ok  = download_nist(force=args.force)

    elapsed = time.time() - start
    print("=" * 55)

    if mitre_ok and nist_ok:
        print(f"🎉  All databases ready in {elapsed:.1f}s. You can now run app.py")
    else:
        print("⚠️   Some downloads failed. The app will use Gemini's built-in knowledge as fallback.")
        sys.exit(1)


if __name__ == "__main__":
    main()