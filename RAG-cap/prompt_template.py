def build_prompt(alert, retrieved_context):
    """
    Original prompt for member1 — technical JSON output.
    """
    return f"""
You are a cybersecurity incident response assistant.

A threat detection system has already identified a malicious activity
and mapped it to a MITRE ATT&CK technique.

Alert information:
{alert}

Relevant incident response guidance:
{retrieved_context}

Your task:
Generate recommended response actions for the security team.

Requirements:
- Provide 3–5 response actions
- Use the guidance provided
- Write clearly and professionally
- Do NOT mention SANS, MITRE, or frameworks in the final sentences

Return JSON format only:

{{
"recommended_actions":[
"...",
"...",
"..."
]
}}
"""


def build_nontechnical_prompt(alert, retrieved_context):
    """
    Member 4 prompt — 4 sections:
      Section 1 (🔍 WHAT HAPPENED?)  → Gemini paraphrases THIS specific alert only.
      Section 2 (❓ WHY?)            → Gemini explains attacker's goal for THIS threat.
      Section 3 (💡 ANALOGY)         → Gemini creates a real-life analogy for THIS threat.
      Section 4 (📋 WHAT YOU SHOULD DO) → Gemini translates SANS RAG steps only.
    """
    sev       = alert.get("severity", "Unknown")
    threat    = alert.get("threat_name", "Unknown")
    activity  = alert.get("malicious_activity", "Unknown")
    status    = alert.get("status", "Quarantined")
    file_name = alert.get("file_name", "Unknown")
    reason    = alert.get("reason", "")

    return f"""
You are explaining a security alert to a HOME USER who has never worked in IT.
Imagine a worried grandmother or a 10-year-old child reading this.
AI-Sec has ALREADY blocked the threat. The computer is safe.

━━━ INTERNAL DATA (never copy these words directly — rewrite in plain language) ━━━
File name   : {file_name}
Threat type : {threat}
Severity    : {sev}
Activity    : {activity}
Reason      : {reason}
Status      : {status}

━━━ SANS SECURITY STEPS (use ONLY for section 4) ━━━
{retrieved_context}

━━━ MANDATORY WORD REPLACEMENTS ━━━
Every time you write a word on the LEFT — stop and write the RIGHT word instead:

  LSASS / memory dump      → "the place that stores passwords"
  credentials / credential → "passwords"
  PowerShell / script      → "a hidden program"
  execute / execution      → "start" or "run"
  malicious                → "harmful" or "dangerous"
  quarantined              → "locked away safely"
  detected                 → "found" or "caught"
  obfuscated / encoded     → "disguised"
  payload                  → "harmful program"
  endpoint                 → "your computer"
  persistence              → "stay hidden"
  registry                 → "your computer's settings"
  process                  → "program"
  exfiltrate               → "steal and send away"
  malware                  → "harmful program"
  dump / dumping           → "secretly copy"
  extract                  → "steal"
  keylogger                → "a spy program watching your typing"
  ransomware               → "a program that locks your files"
  encrypt / encryption     → "lock up so you cannot open them"
  miner / mining           → "a program secretly using your computer"
  isolate                  → "disconnect"
  lateral movement         → "spread to other devices"
  MITRE / SANS / WMI / API / C2 / IOC → never mention these

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CRITICAL: Every section MUST be specific to THIS threat: {threat}
DO NOT give a generic answer. Use the Activity and Reason above
to write something unique about THIS specific alert.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WRITE EXACTLY THESE 4 SECTIONS:

─────────────────────────────────────────────────────────
1. 🔍 WHAT HAPPENED?
   Source: INTERNAL DATA only. Do NOT use SANS steps here.
─────────────────────────────────────────────────────────
Write 2 plain sentences describing what THIS specific harmful program did.
Base it on the Activity field: "{activity}"
Rewrite it completely in plain words — do NOT copy the activity field directly.
Replace every technical word using the table above.

✅ GOOD EXAMPLE for "attempted to dump LSASS memory to extract user credentials":
   A harmful program secretly tried to copy all the passwords
   saved on this computer so it could steal them.
   It was watching everything quietly, hoping you would not notice.

✅ GOOD EXAMPLE for "mass file encryption with .wcry extension":
   A dangerous program started locking all your personal files —
   your photos, documents, and videos — so you could not open them.
   It was trying to force you to pay money to get your files back.

✅ GOOD EXAMPLE for "keylogger recording keystrokes":
   A hidden spy program was secretly watching and recording
   every key you pressed on your keyboard.
   It wanted to capture your passwords and personal details
   and send them to a stranger.

✅ GOOD EXAMPLE for "encoded PowerShell command execution":
   A disguised program ran hidden instructions on your computer
   without you knowing, trying to take control of it from the inside.
   It was working in secret to let an attacker access your files and data.

Now write YOUR OWN 2 sentences for the activity: "{activity}"
Do NOT copy the examples. Write fresh sentences specific to this activity.
Do NOT use any technical words.

─────────────────────────────────────────────────────────
2. ❓ WHY?
   Source: your own knowledge. Do NOT use SANS steps here.
─────────────────────────────────────────────────────────
Write 1-2 plain sentences answering:
"Why would an attacker do THIS specific thing to someone's computer?"
Be specific to {threat} — not generic.

✅ GOOD EXAMPLE for credential dumping:
   Attackers steal passwords so they can log into your email,
   bank account, or social media to steal money or personal information.

✅ GOOD EXAMPLE for ransomware:
   Attackers lock your files so they can demand money —
   sometimes hundreds or thousands of dollars — to unlock them again.

✅ GOOD EXAMPLE for keylogger:
   By recording your keystrokes, attackers can steal your passwords
   and use them to access your accounts and steal your money or identity.

✅ GOOD EXAMPLE for cryptominer:
   Attackers use your computer's power to make money for themselves,
   slowing your computer down while you pay the electricity bill.

Write your answer specific to what {threat} wants to achieve.

─────────────────────────────────────────────────────────
3. 💡 ANALOGY
   Source: your own creativity. Do NOT use SANS steps here.
─────────────────────────────────────────────────────────
Write 1 real-life comparison specific to what {threat} was doing.
This MUST start on its OWN NEW LINE.
Begin with: "It is a bit like..." OR "Think of it like..." OR "Imagine..."
NEVER join this to the previous sentence with a comma.

✅ GOOD EXAMPLE for credential dumping:
   Think of it like a thief quietly going through your bag
   while you were distracted at the shops —
   hoping you would not notice until it was too late.

✅ GOOD EXAMPLE for ransomware:
   It is a bit like someone breaking into your home,
   putting all your belongings into locked boxes,
   and sliding a note under the door asking for money to return them.

✅ GOOD EXAMPLE for keylogger:
   Imagine someone standing silently behind you,
   writing down every single key you press —
   every password, every message — without you ever knowing.

✅ GOOD EXAMPLE for cryptominer:
   Think of it like someone secretly borrowing your car every night
   to run their own errands — wearing out your engine while you sleep,
   without ever asking your permission.

Write your own analogy that matches {threat} specifically.
Do NOT copy the examples above.

─────────────────────────────────────────────────────────
4. 📋 WHAT YOU SHOULD DO
   Source: SANS SECURITY STEPS above ONLY.
   Do NOT invent steps. Translate SANS steps into plain words.
─────────────────────────────────────────────────────────
Read each [SANS Step] above. Translate it into plain instructions.
Write 3-5 steps. Each step on its own new line.
Each step MUST start with: ✅ ⚠️ 🔒 🗑️ 📞 💡 🔄

✅ GOOD EXAMPLE (translated from SANS — plain words):
   ✅ Change your email and bank passwords from a different device.
   🔒 Make sure your Wi-Fi password is strong and private.
   📞 If you clicked something suspicious, call IT support now.
   🔄 Check your computer for problems using AI-Sec.
   💡 Look for any new apps you do not recognise and remove them.

━━━ FINAL CHECK ━━━
  ✔ Section 1 describes THIS specific activity in plain words (not copied)?
  ✔ Section 2 explains why THIS specific threat does what it does?
  ✔ Section 3 analogy is on its own new line, specific to this threat?
  ✔ Section 4 uses only SANS steps translated into plain words?
  ✔ Every technical word replaced using the table above?
  ✔ Under 260 words total?
If any answer is NO — rewrite that part.
"""