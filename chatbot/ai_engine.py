# ai_engine.py - General cybersecurity knowledge AI using activity context
import re
import time
import threading
import random
from typing import Dict, Optional, Callable, List, Tuple
from .api_key import GEMINI_API_KEY
from google import genai

# Initialize Gemini client
client = genai.Client(api_key=GEMINI_API_KEY)

# ============================================
# ACTIVITY DATA (from scan_file.py)
# ============================================

def get_activities():
    """Get the list of activities - matching scan_file.py"""
    activities = [
        ("2:34 PM Today",  "invoice_2024.exe",   "Quarantined", True),
        ("1:15 PM Today",  "report.docx",         "Suspicious",  False),
        ("11:42 AM Today", "update_patch.msi",    "Low",         False),
    ]*8
    return activities

STATUS_COLORS = {
    "Quarantined": ("#FFECEC", "#D32F2F"),  # red
    "Suspicious":  ("#FFF3E0", "#E65100"),  # orange
    "Low":         ("#E3F2FD", "#1565C0"),  # blue
}

def get_file_status(filename: str) -> Tuple[str, bool]:
    """
    Get the status and quarantine status of a file from activities
    Returns (status, is_quarantined)
    """
    activities = get_activities()
    for _, file, status, quarantined in activities:
        if file.lower() == filename.lower():
            return status, quarantined
    return "Unknown", False

# ============================================
# THREAT TYPE MAPPING
# ============================================

def get_threat_type_from_filename(filename: str) -> str:
    """Determine likely threat type based on filename and extension"""
    filename_lower = filename.lower()
    
    # Map file extensions to threat categories
    if ".exe" in filename_lower:
        if "invoice" in filename_lower or "payment" in filename_lower:
            return "Trojan (Fake Invoice)"
        elif "update" in filename_lower or "patch" in filename_lower:
            return "Fake Update Malware"
        elif "crack" in filename_lower or "keygen" in filename_lower:
            return "Pirated Software Malware"
        else:
            return "Executable Trojan"
    
    elif ".doc" in filename_lower or ".docx" in filename_lower:
        if "report" in filename_lower:
            return "Macro-Infected Document"
        else:
            return "Malicious Document"
    
    elif ".pdf" in filename_lower:
        return "Malicious PDF"
    
    elif ".msi" in filename_lower:
        if "update" in filename_lower or "patch" in filename_lower:
            return "Fake Installer"
        else:
            return "Suspicious Installer"
    
    elif ".zip" in filename_lower or ".rar" in filename_lower:
        return "Archive Containing Malware"
    
    elif ".js" in filename_lower or ".vbs" in filename_lower:
        return "Malicious Script"
    
    else:
        return "Suspicious File"

def get_threat_description(threat_type: str, status: str) -> Dict:
    """
    Get a simple description of the threat type
    Returns dict with summary, how it works, why dangerous, and actions
    """
    descriptions = {
        "Trojan (Fake Invoice)": {
            "summary": "This file pretends to be an invoice but is actually a harmful program.",
            "how_it_works": "It tricks you into opening it by looking like a normal bill or receipt. Once opened, it can install other harmful software.",
            "why_dangerous": "It could steal your personal information or let hackers into your computer.",
            "actions": ["Keep the file in quarantine", "Delete it permanently", "Be careful with unexpected invoices"]
        },
        "Fake Update Malware": {
            "summary": "This file pretends to be a software update but is actually malware.",
            "how_it_works": "It disguises itself as an important update from Microsoft or other companies to trick you into installing it.",
            "why_dangerous": "It can lock your files, steal passwords, or give hackers control of your computer.",
            "actions": ["Don't trust unexpected updates", "Always update through official settings", "Keep this file quarantined"]
        },
        "Executable Trojan": {
            "summary": "This is a Trojan horse - a program that looks useful but does harmful things.",
            "how_it_works": "It hides inside what looks like a normal program. When you run it, it does bad things in the background.",
            "why_dangerous": "It can spy on you, steal your files, or let other malware in.",
            "actions": ["Delete this file", "Run a full system scan", "Be careful what you download"]
        },
        "Macro-Infected Document": {
            "summary": "This document has hidden malicious instructions inside it.",
            "how_it_works": "Documents can have small programs called macros. This one has harmful macros that run when you open the file.",
            "why_dangerous": "It can infect your computer with malware or spread to other documents.",
            "actions": ["Don't enable macros in documents", "Delete this file", "Be careful with email attachments"]
        },
        "Malicious Document": {
            "summary": "This document is designed to harm your computer.",
            "how_it_works": "It contains hidden code that tries to exploit weaknesses in your document viewer.",
            "why_dangerous": "It could install malware or give hackers access to your system.",
            "actions": ["Delete this file", "Keep your software updated", "Don't open unexpected documents"]
        },
        "Fake Installer": {
            "summary": "This looks like a software installer but is actually harmful.",
            "how_it_works": "It pretends to install useful software but installs malware instead.",
            "why_dangerous": "It could install ransomware, spyware, or other harmful programs.",
            "actions": ["Don't trust installers from unknown sites", "Delete this file", "Use official sources only"]
        },
        "Suspicious Installer": {
            "summary": "This installer was flagged as potentially harmful.",
            "how_it_works": "It tries to install software, but its behavior looks suspicious to your security software.",
            "why_dangerous": "It might install unwanted programs or change your browser settings.",
            "actions": ["Research the software before installing", "Check reviews", "Use trusted sources"]
        },
        "Malicious PDF": {
            "summary": "This PDF file contains hidden harmful code.",
            "how_it_works": "PDFs can have JavaScript and other features. This one uses them maliciously.",
            "why_dangerous": "It could infect your computer or steal information when opened.",
            "actions": ["Delete this file", "Use PDF reader with security features", "Don't open unexpected PDFs"]
        },
        "Archive Containing Malware": {
            "summary": "This compressed file contains harmful software inside.",
            "how_it_works": "It's like a box that has dangerous items hidden inside. When unpacked, the malware is released.",
            "why_dangerous": "Extracting it could release malware onto your computer.",
            "actions": ["Delete this archive", "Don't extract unknown archives", "Scan archives before extracting"]
        },
        "Malicious Script": {
            "summary": "This is a script file designed to run harmful commands.",
            "how_it_works": "It contains instructions that tell your computer to do bad things, like download malware or change settings.",
            "why_dangerous": "It can modify your system or download more malware.",
            "actions": ["Delete this file", "Disable scripts from unknown sources", "Keep antivirus active"]
        },
        "Suspicious File": {
            "summary": "This file was flagged as suspicious by your security software.",
            "how_it_works": "It behaves in ways that are unusual or similar to known threats.",
            "why_dangerous": "It might be new malware that hasn't been fully identified yet.",
            "actions": ["Keep it quarantined", "Submit to your security vendor", "Run additional scans"]
        }
    }
    
    return descriptions.get(threat_type, {
        "summary": "This file was flagged as potentially harmful by your security software.",
        "how_it_works": "It was detected because it behaves suspiciously or matches known threat patterns.",
        "why_dangerous": "It could potentially harm your computer or steal your information.",
        "actions": ["Keep it quarantined", "Run a full system scan", "Be careful with unknown files"]
    })

# ============================================
# SAFETY CHECKS
# ============================================

def is_harmful_request(question: str) -> bool:
    """Check if user question is asking for harmful information"""
    question_lower = question.lower()
    
    forbidden_patterns = [
        r'how to (hack|bypass|break|crack|exploit)',
        r'create (virus|malware|ransomware|trojan)',
        r'make (virus|malware|ransomware)',
        r'steal (password|data|information|credit card)',
        r' illegal ',
        r'hack (someone|account|computer|system)',
        r'spy on',
        r'keylogger',
        r' cheat ',
        r'bypass (security|protection|firewall)',
        r'crack (software|password|license)',
        r'friend.?password',
        r'get.?password',
        r'steal.?password',
        r'someone.?password',
    ]
    
    for pattern in forbidden_patterns:
        if re.search(pattern, question_lower):
            return True
    
    return False

def contains_harmful_keywords(text: str) -> bool:
    """Check if text contains harmful keywords (for response filtering)"""
    harmful_keywords = [
        "how to hack", "create virus", "make malware", "bypass", "crack",
        "steal password", "break into", "illegal", "hack someone",
        "spy on", "keylogger", "ransomware create", "cheat", "exploit"
    ]
    
    text_lower = text.lower()
    return any(keyword in text_lower for keyword in harmful_keywords)

def get_harmful_request_response() -> str:
    """Polite, friendly refusal for harmful requests"""
    responses = [
        "Hey friend! 👋 I'd love to help you understand this file better, but I can't provide information that could be used for harmful purposes. Is there something about this specific file or computer safety you'd like to know? 😊",
        
        "Hi there! 😊 I'm here to explain about this suspicious file and help you stay safe. I can't help with that request, but I'd be happy to explain why this file was blocked! 🛡️",
        
        "Oh, I can't help with that! But you know what I CAN do? Explain what kind of threat this file might be and how to stay protected. Want to learn about that? 🌟",
        
        "That's not something I can discuss, but I'm really good at explaining computer safety in simple words! Ask me about this file and I'll help you understand it! 🎉"
    ]
    return random.choice(responses)

# ============================================
# ANALOGIES
# ============================================

def get_analogy_for_threat(threat_type: str) -> str:
    """Get a simple analogy based on threat type"""
    
    analogies = {
        "Trojan (Fake Invoice)": "someone dressing up as a delivery person to get inside your house. They look legit, but they're not!",
        "Fake Update Malware": "someone calling you pretending to be from Microsoft, asking to 'fix' your computer remotely.",
        "Executable Trojan": "a wolf in sheep's clothing - looks harmless but is actually dangerous.",
        "Macro-Infected Document": "a regular book that has hidden instructions that only activate when you open it.",
        "Malicious Document": "a letter that looks normal but has a tiny camera hidden inside.",
        "Fake Installer": "someone offering to install something for you, but actually planting a bug in your house.",
        "Suspicious Installer": "a stranger offering to help you carry groceries, but you're not quite sure about them.",
        "Malicious PDF": "a picture frame that actually contains a hidden camera.",
        "Archive Containing Malware": "a gift box that looks nice but has something dangerous inside.",
        "Malicious Script": "a recipe that tells you to do things that could burn down the kitchen!",
        "Suspicious File": "a locked box with no return address - better to leave it unopened!"
    }
    
    return analogies.get(threat_type, "someone trying to sneak into your house through an unlocked window.")

def get_simple_analogy_from_filename(filename: str) -> str:
    """Get a simple analogy based on file extension"""
    filename_lower = filename.lower()
    
    if ".exe" in filename_lower:
        return "a package that looks like a gift but actually has something dangerous inside"
    elif ".doc" in filename_lower or ".docx" in filename_lower:
        return "a letter that looks normal but has hidden instructions between the lines"
    elif ".pdf" in filename_lower:
        return "a document that seems normal but has a hidden surprise inside"
    elif ".msi" in filename_lower:
        return "someone trying to install something on your computer without asking permission"
    elif ".zip" in filename_lower or ".rar" in filename_lower:
        return "a box that claims to have toys but actually has something harmful inside"
    else:
        return "a fake message pretending to be from someone you trust"

# ============================================
# PROMPT GENERATION
# ============================================

def generate_conversational_prompt(filename: str, user_question: str) -> str:
    """Create a prompt for Gemini about this specific file"""
    
    # Get file info
    status, is_quarantined = get_file_status(filename)
    threat_type = get_threat_type_from_filename(filename)
    threat_info = get_threat_description(threat_type, status)
    analogy = get_analogy_for_threat(threat_type)
    
    quarantine_status = "Yes (file is isolated and can't harm you)" if is_quarantined else "No (file was blocked but not isolated)"
    
    # Build actions list
    actions = threat_info.get('actions', ['Keep the file quarantined', 'Run a system scan'])
    actions_text = "\n".join([f"• {action}" for action in actions[:3]])
    
    prompt = f"""You are a friendly, cheerful cybersecurity assistant helping a NON-TECHNICAL person understand a suspicious file on their computer.

--- YOUR PERSONALITY ---
- Be warm, friendly, and encouraging like a helpful neighbor
- Use a happy and reassuring tone - make them feel safe, not scared
- Start with a friendly greeting like "Hey there! ✨" or "Hi friend! 🌈"
- End with something positive or encouraging
- NEVER sound robotic, technical, or scary

--- FILE INFORMATION (USE THIS FOR ACCURACY) ---
Filename: {filename}
Status: {status}
Threat Type: {threat_type}
Quarantined: {quarantine_status}

Simple Summary: {threat_info.get('summary', 'This file was flagged as suspicious')}
How It Works: {threat_info.get('how_it_works', 'It behaves in ways that concern your security software')}
Why It's Dangerous: {threat_info.get('why_dangerous', 'It could potentially harm your computer')}

Recommended Actions:
{actions_text}

USER QUESTION: "{user_question}"

--- STRICT RULES (FOLLOW EXACTLY) ---
1. 🎯 ANSWER ONLY THE QUESTION using ONLY the information above
2. 🗣️ SIMPLE LANGUAGE: Use words a grandmother would understand
3. ✂️ SHORT & SWEET: 3-4 sentences maximum
4. 🔒 NEVER explain how to do anything harmful
5. 📋 USE ANALOGIES: Compare to everyday situations
6. 💡 BE REASSURING: Emphasize they're safe

--- FORMATTING RULES ---

🎯 **MATCH THE FORMAT TO THE QUESTION TYPE:**

1. **If they ask "What is this?" or "Explain this file":**
   Hey there! ✨ Imagine {analogy}
   
   In simple words: {threat_info.get('summary', 'This is a suspicious file')}
   
   Your computer caught it - you're safe! 🔒

2. **If they ask "Is it dangerous?" or "What's the risk?":**
   Hi friend! 🌈 Great question!
   
   Yes, this {threat_type.lower()} is risky. {threat_info.get('why_dangerous', 'It could harm your computer')}
   
   But good news! Your computer {status.lower()} it immediately! 🛡️

3. **If they ask "What should I do?" or "What now?":**
   Good news! ⭐ Your computer already handled most of it:
   
   ✅ **Already done:** File is {status.lower()}
   
   📝 **Quick checklist:**
   {actions_text}
   
   That's it! You're protected! ✨

4. **If they ask "How does it work?" or "How?":**
   Oh, let me explain! 📚
   
   {threat_info.get('how_it_works', 'It tries to trick your computer into letting it in')}
   
   Think of it like {analogy}
   
   Your computer was too smart for it! 💪

5. **If they ask "Why was it blocked?" or "Why suspicious?":**
   Great question! 🔎 Your computer noticed:
   
   ⚠️ **The red flag:** {threat_info.get('how_it_works', 'It behaved suspiciously')}
   
   Think of it like {analogy}
   
   Your computer caught it immediately! 🕵️

6. **For any other question:**
   Hi there! ☀️ About your question:
   
   [Answer using the file information above in 1-2 simple sentences]
   
   Hope that helps! ✨

--- YOUR RESPONSE (FOLLOW ALL RULES ABOVE) ---"""
    
    return prompt

# ============================================
# FALLBACK RESPONSES
# ============================================

def get_fallback_response(filename: str, question: str) -> str:
    """Simple fallback if AI fails"""
    
    status, is_quarantined = get_file_status(filename)
    threat_type = get_threat_type_from_filename(filename)
    threat_info = get_threat_description(threat_type, status)
    analogy = get_simple_analogy_from_filename(filename)
    
    question_lower = question.lower()
    
    if 'risk' in question_lower or 'dangerous' in question_lower:
        return f"""Hey there! 👋 Great question about safety!

{threat_info.get('why_dangerous', 'This file could potentially harm your computer')}

Think of it like {analogy}.

🛡️ **The good news:** Your computer {status.lower()} it and kept you safe!"""
    
    elif 'what' in question_lower or 'explain' in question_lower:
        return f"""Hi friend! 😊 Here's what this file is in simple words:

{threat_info.get('summary', 'This is a suspicious file')}

Think of it like {analogy}

✅ Your computer caught it - you're protected!"""
    
    elif 'do' in question_lower or 'action' in question_lower or 'should' in question_lower:
        actions = threat_info.get('actions', ['Keep it quarantined', 'Run a scan'])
        action_list = "\n• ".join(actions[:3])
        return f"""Good news! 😊 Your computer already handled the hard part. Here's your simple checklist:

✅ **Already done:** The file was {status.lower()}

📋 **Quick things to know:**
• {action_list}

That's all! You're safe! 🛡️"""
    
    elif 'how' in question_lower:
        return f"""Oh, let me explain it simply! 📖

{threat_info.get('how_it_works', 'It tries to trick your computer')}

Imagine {analogy}

But don't worry - your computer was too smart! 💪"""
    
    else:
        return f"""Hey friend! 👋 About {filename}:

{threat_info.get('summary', 'This file was flagged as suspicious')}

🛡️ **You're all good!** Your security caught it and {status.lower()} it."""

# ============================================
# CORE AI FUNCTION
# ============================================

def generate_ai_response(filename: str, user_question: str, update_callback: Optional[Callable] = None) -> str:
    """Use Gemini to generate response about the file"""
    
    try:
        # Show loading indicator
        if update_callback and callable(update_callback):
            update_callback("⏳ Thinking")
        
        # Generate the prompt
        prompt = generate_conversational_prompt(filename, user_question)
        
        # Call Gemini with animated dots
        done_loading = False
        
        def animate_loading():
            dots = 0
            while not done_loading:
                if update_callback and callable(update_callback):
                    dots_text = "." * dots
                    update_callback(f"⏳ Thinking{dots_text}")
                else:
                    print(".", end="", flush=True)
                
                dots += 1
                if dots > 3:
                    dots = 0
                time.sleep(0.3)
        
        loading_thread = threading.Thread(target=animate_loading)
        loading_thread.daemon = True
        loading_thread.start()
        
        # Make the API call
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt
        )
        
        done_loading = True
        loading_thread.join(timeout=1.0)
        
        if update_callback and callable(update_callback):
            update_callback("")  # Clear loading
        else:
            print(" ✅")
        
        ai_response = response.text
        
        # Final safety check
        if contains_harmful_keywords(ai_response):
            return "I'm here to explain this file and help you stay safe, not to provide potentially harmful information. Is there something about this specific file you'd like to know? 😊"
        
        return ai_response
        
    except Exception as e:
        done_loading = True
        if update_callback and callable(update_callback):
            update_callback("")
        else:
            print(f" ❌ AI Service Unavailable")
        
        # Check if it's an API limit/quota error
        error_str = str(e).lower()
        is_api_limit = any(term in error_str for term in [
            'quota', 'limit', 'rate', 'exhausted', '429', 'resource exhausted', 
            'too many requests', 'billing', 'payment required'
        ])
        
        if is_api_limit:
            service_msg = "⚠️ **AI service temporarily unavailable** (API limit reached). Here's what I can tell you:\n\n"
        else:
            service_msg = "⚠️ **AI service temporarily unavailable**. Here's the basic information:\n\n"
        
        # Get static answer
        static_answer = get_fallback_response(filename, user_question)
        
        return service_msg + static_answer

# ============================================
# MAIN FUNCTION
# ============================================

def get_chatbot_response(filename: str, user_question: str, update_callback: Optional[Callable] = None) -> str:
    """
    Main function: Provide cybersecurity knowledge about the file
    Uses activity data from scan_file.py for context
    """
    # STEP 1: Safety check with polite refusal
    if is_harmful_request(user_question):
        return get_harmful_request_response()
    
    # STEP 2: Generate AI response using filename for context
    return generate_ai_response(filename, user_question, update_callback)