"""
frameworks.py — Framework Context Engine
Member 4: AI Explanation Module | Sentinel AI Security Suite

Loads MITRE ATT&CK and NIST SP 800-53 databases and maps
security alerts to the relevant techniques and controls.

Strategy:
  1. Try exact rule_id → technique/control ID mapping
  2. Fallback: keyword search across database using alert tags + process name
  3. Final fallback: return empty shells so Gemini uses its own knowledge
"""

import json
import os
import re
import logging

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Static mapping: Rule ID → MITRE Technique IDs
# Add new rules from Member 1 here as the project grows
# ─────────────────────────────────────────────────────────────────────────────
RULE_TO_MITRE: dict[str, list[str]] = {
    "R-DELETE-001": ["T1485", "T1059"],
    "R-RUNKEY-002": ["T1547", "T1060"],
    "R-LOG-003":    ["T1071", "T1562"],
    "R-EXEC-004":   ["T1059", "T1204"],
    "R-NET-005":    ["T1071", "T1105"],
    "R-CRED-006":   ["T1003", "T1110"],
    "R-PERSIST-007":["T1547", "T1053"],
    "R-EXFIL-008":  ["T1041", "T1048"],
    "R-PRIV-009":   ["T1068", "T1134"],
    "R-EVADE-010":  ["T1562", "T1070"],
}

# ─────────────────────────────────────────────────────────────────────────────
# Static mapping: Rule ID → NIST Control IDs
# ─────────────────────────────────────────────────────────────────────────────
RULE_TO_NIST: dict[str, list[str]] = {
    "R-DELETE-001": ["SI-3", "CM-7"],
    "R-RUNKEY-002": ["AC-6", "CM-7"],
    "R-LOG-003":    ["AU-2", "SI-3"],
    "R-EXEC-004":   ["CM-7", "SI-7"],
    "R-NET-005":    ["SC-7", "SI-3"],
    "R-CRED-006":   ["IA-5", "AC-2"],
    "R-PERSIST-007":["CM-7", "AC-6"],
    "R-EXFIL-008":  ["SC-7", "AU-2"],
    "R-PRIV-009":   ["AC-6", "AC-3"],
    "R-EVADE-010":  ["AU-2", "SI-3"],
}

# ─────────────────────────────────────────────────────────────────────────────
# Database loading (with in-memory caching to avoid repeated disk reads)
# ─────────────────────────────────────────────────────────────────────────────
_mitre_cache: dict | None = None
_nist_cache:  dict | None = None

DB_DIR = os.path.join(os.path.dirname(__file__), "databases")

def _load_mitre() -> dict:
    global _mitre_cache
    if _mitre_cache is not None:
        return _mitre_cache
    path = os.path.join(DB_DIR, "mitre_full.json")
    if not os.path.exists(path):
        logger.warning("MITRE database not found at %s. Run download.py first.", path)
        _mitre_cache = {"techniques": []}
    else:
        with open(path, "r", encoding="utf-8") as f:
            _mitre_cache = json.load(f)
        logger.info("MITRE database loaded: %d techniques", len(_mitre_cache.get("techniques", [])))
    return _mitre_cache


def _load_nist() -> dict:
    global _nist_cache
    if _nist_cache is not None:
        return _nist_cache
    path = os.path.join(DB_DIR, "nist_full.json")
    if not os.path.exists(path):
        logger.warning("NIST database not found at %s. Run download.py first.", path)
        _nist_cache = {"controls": []}
    else:
        with open(path, "r", encoding="utf-8") as f:
            _nist_cache = json.load(f)
        logger.info("NIST database loaded: %d controls", len(_nist_cache.get("controls", [])))
    return _nist_cache


# ─────────────────────────────────────────────────────────────────────────────
# Keyword fallback: search MITRE techniques by alert tags + process name
# Used when rule_id is unknown or not in the static map
# ─────────────────────────────────────────────────────────────────────────────
def _keyword_search_mitre(alert: dict, max_results: int = 2) -> list[dict]:
    """Search MITRE database using keywords extracted from the alert."""
    tags        = alert.get("tags", [])
    process     = alert.get("process_name", "")
    description = alert.get("description", "")

    # Build a set of lowercase keywords
    keywords = set()
    for tag in tags:
        keywords.update(re.split(r"[-_\s]", tag.lower()))
    keywords.update(re.split(r"[-_\s]", process.lower()))
    keywords.update(re.split(r"[-_\s]", description.lower()))
    keywords.discard("")

    # Common stop words to ignore
    stop = {"the", "a", "an", "is", "in", "on", "at", "to", "of", "and", "or", "for", "exe", "dll"}
    keywords -= stop

    if not keywords:
        return []

    mitre_db = _load_mitre()
    scored: list[tuple[int, dict]] = []

    for tech in mitre_db.get("techniques", []):
        haystack = (
            tech.get("name", "") + " " +
            tech.get("tactic", "") + " " +
            tech.get("description", "")
        ).lower()
        score = sum(1 for kw in keywords if kw in haystack)
        if score > 0:
            scored.append((score, tech))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [t for _, t in scored[:max_results]]


def _keyword_search_nist(alert: dict, max_results: int = 2) -> list[dict]:
    """Search NIST database using keywords extracted from the alert."""
    tags        = alert.get("tags", [])
    severity    = alert.get("severity", "")
    description = alert.get("description", "")

    keywords = set()
    for tag in tags:
        keywords.update(re.split(r"[-_\s]", tag.lower()))
    keywords.update(re.split(r"[-_\s]", description.lower()))

    # Map severity to control families
    if severity == "HIGH":
        keywords.update(["incident", "malicious", "protection", "detect"])
    elif severity == "MEDIUM":
        keywords.update(["monitor", "audit", "access"])
    keywords.discard("")

    stop = {"the", "a", "an", "is", "in", "on", "at", "to", "of", "and", "or", "for"}
    keywords -= stop

    if not keywords:
        return []

    nist_db = _load_nist()
    scored: list[tuple[int, dict]] = []

    for ctrl in nist_db.get("controls", []):
        haystack = (
            ctrl.get("name", "") + " " +
            ctrl.get("description", "")
        ).lower()
        score = sum(1 for kw in keywords if kw in haystack)
        if score > 0:
            scored.append((score, ctrl))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [c for _, c in scored[:max_results]]


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────
def get_mitre_context(alert: dict) -> list[dict]:
    """
    Return a list of relevant MITRE ATT&CK technique dicts for this alert.
    Priority: static rule_id map → keyword search → empty fallback.
    """
    rule_id      = alert.get("rule_id", "")
    mapped_ids   = RULE_TO_MITRE.get(rule_id, [])
    mitre_db     = _load_mitre()
    all_techs    = mitre_db.get("techniques", [])

    # 1. Static map lookup
    if mapped_ids:
        matched = [t for t in all_techs if t["id"] in mapped_ids]
        if matched:
            return matched
        # IDs defined but not found in DB — return stubs
        return [{"id": tid, "name": tid, "tactic": "", "description": ""} for tid in mapped_ids]

    # 2. Keyword fallback
    keyword_matches = _keyword_search_mitre(alert)
    if keyword_matches:
        logger.info("MITRE: using keyword fallback for rule_id='%s'", rule_id)
        return keyword_matches

    # 3. Empty fallback — Gemini will use its own knowledge
    return []


def get_nist_context(alert: dict) -> list[dict]:
    """
    Return a list of relevant NIST SP 800-53 control dicts for this alert.
    Priority: static rule_id map → keyword search → empty fallback.
    """
    rule_id    = alert.get("rule_id", "")
    mapped_ids = RULE_TO_NIST.get(rule_id, [])
    nist_db    = _load_nist()
    all_ctrls  = nist_db.get("controls", [])

    # 1. Static map lookup
    if mapped_ids:
        matched = [c for c in all_ctrls if c["id"] in mapped_ids]
        if matched:
            return matched
        return [{"id": cid, "name": cid, "description": ""} for cid in mapped_ids]

    # 2. Keyword fallback
    keyword_matches = _keyword_search_nist(alert)
    if keyword_matches:
        logger.info("NIST: using keyword fallback for rule_id='%s'", rule_id)
        return keyword_matches

    # 3. Empty fallback
    return []


def get_framework_context(alert: dict) -> dict:
    """
    Master context builder. Called by prompt.py.
    Returns a dict with 'mitre' and 'nist' lists.
    """
    return {
        "mitre": get_mitre_context(alert),
        "nist":  get_nist_context(alert),
        # SANS: Gemini uses built-in knowledge (no public free API exists)
    }