"""
prompt.py — Gemini Prompt Builder
Member 4: AI Explanation Module | Sentinel AI Security Suite

Assembles a structured, context-rich prompt for Gemini that combines:
  - The raw alert data from Member 1
  - MITRE ATT&CK techniques (from local database via frameworks.py)
  - NIST SP 800-53 controls (from local database via frameworks.py)
  - SANS Incident Response phases (from Gemini's built-in knowledge)

Output format is strict JSON so app.py can parse it reliably.
"""

import json
from frameworks import get_framework_context


def _format_mitre(techniques: list[dict]) -> str:
    """Render MITRE techniques as a clean, readable block for the prompt."""
    if not techniques:
        return "No specific technique matched. Use your MITRE ATT&CK knowledge based on the alert details."

    lines = []
    for t in techniques:
        line = f"• [{t['id']}] {t['name']}"
        if t.get("tactic"):
            line += f"  |  Tactic: {t['tactic']}"
        lines.append(line)
        if t.get("description"):
            # Truncate long descriptions to keep the prompt focused
            desc = t["description"][:250].rstrip()
            lines.append(f"  Description: {desc}...")
    return "\n".join(lines)


def _format_nist(controls: list[dict]) -> str:
    """Render NIST controls as a clean, readable block for the prompt."""
    if not controls:
        return "No specific control matched. Use your NIST SP 800-53 knowledge based on the alert details."

    lines = []
    for c in controls:
        line = f"• [{c['id']}] {c['name']}"
        lines.append(line)
        if c.get("description"):
            desc = c["description"][:250].rstrip()
            lines.append(f"  Description: {desc}...")
    return "\n".join(lines)


def build_prompt(alert: dict) -> str:
    """
    Build the full Gemini prompt for a given alert dict.
    Returns a prompt string ready to send to the Gemini API.
    """
    alert_json = json.dumps(alert, indent=2)
    fw         = get_framework_context(alert)
    mitre_text = _format_mitre(fw["mitre"])
    nist_text  = _format_nist(fw["nist"])

    # Severity-specific tone instruction
    severity = alert.get("severity", "LOW").upper()
    tone_instruction = {
        "HIGH":   "Use urgent, clear language. The user must act NOW.",
        "MEDIUM": "Use calm but firm language. The user should act soon.",
        "LOW":    "Use informative, reassuring language. This is worth noting.",
    }.get(severity, "Use neutral, informative language.")

    prompt = f"""
You are a cybersecurity awareness assistant inside a Windows security tool.
Your job is to explain a detected security event to a NON-TECHNICAL user
(think: an office worker, student, or home user with no IT background).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DETECTED SECURITY ALERT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{alert_json}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MITRE ATT&CK REFERENCE  (official MITRE database)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{mitre_text}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
NIST SP 800-53 REFERENCE  (official NIST database)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{nist_text}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SANS INCIDENT RESPONSE PHASES  (use your built-in knowledge)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TONE INSTRUCTION  (severity = {severity})
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{tone_instruction}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
YOUR TASK
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Write THREE sections:

1. WHAT HAPPENED
   - Explain in 2-3 simple sentences what this security event means in everyday language.
   - Reference the MITRE technique (include the ID and name in plain English).
   - Example: "A program called cmd.exe tried to delete files on your computer.
     This matches a known attack method called Data Destruction (T1485), where attackers
     try to erase your files to cause damage."

2. WHY THIS IS A CONCERN
   - Explain in 2-3 simple sentences what security rule was broken or what risk this creates.
   - Reference the NIST control (include the ID and name in plain English).
   - Example: "Your system's malware protection policy (NIST SI-3) was challenged.
     This rule exists to block harmful programs from running on your computer."

3. WHAT YOU SHOULD DO  (4 to 6 steps)
   - Each step must be a clear, actionable instruction a non-technical person can follow.
   - Each step must include its SANS phase in brackets at the end.
   - Steps must follow the logical SANS order: Identification → Containment → Eradication → Recovery → Lessons Learned
   - Example: "Do not open or run any new programs until this is resolved. [SANS: Containment]"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STRICT RULES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
- NO technical jargon unless immediately explained in simple words
- MUST name the MITRE technique (ID + name) in what_happened
- MUST name the NIST control (ID + name) in why_concern
- MUST label every action with its SANS phase
- NEVER suggest actions that could harm the system (no "delete system32", etc.)
- NEVER mention this AI system, Gemini, or that this explanation was AI-generated
- Return ONLY valid JSON — no markdown, no code fences, no extra text

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RETURN EXACTLY THIS JSON STRUCTURE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
{{
  "what_happened": "2-3 sentence plain-English explanation with MITRE reference...",
  "why_concern": "2-3 sentence plain-English explanation with NIST reference...",
  "recommended_actions": [
    "Step 1 [SANS: Identification]",
    "Step 2 [SANS: Containment]",
    "Step 3 [SANS: Eradication]",
    "Step 4 [SANS: Recovery]",
    "Step 5 [SANS: Lessons Learned]"
  ]
}}
"""
    return prompt.strip()