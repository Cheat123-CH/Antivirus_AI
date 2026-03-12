# ai_engine.py - Using explain_result.json as context for Gemini
# import json
# import re
# from typing import Dict, Optional
# from .api_key import GEMINI_API_KEY
# from google import genai
# import google.generativeai as genai

import json
import re
from typing import Dict, Optional
from .api_key import CHATBOT_API_KEY
import google.generativeai as genai

# Initialize Gemini client
# client = genai.Client(api_key=GEMINI_API_KEY)
genai.configure(api_key=CHATBOT_API_KEY)

# ============================================
# CONSTANTS & CONFIGURATION
# ============================================

HARMFUL_PATTERNS = [
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
]

# ============================================
# LOAD EXPLANATION DATA
# ============================================

def load_explain_result() -> Dict:
    """Load the explanation data from JSON file"""
    # Try multiple possible paths
    possible_paths = [
        'chatbot/explain_result.json',
        'explain_result.json',
        './chatbot/explain_result.json'
    ]
    
    for path in possible_paths:
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            continue
        except Exception as e:
            print(f"⚠️ Error loading {path}: {e}")
    
    print("⚠️ explain_result.json not found in any location")
    return {"events": []}

def find_event_by_filename(filename: str) -> Optional[Dict]:
    """Find event details from explain_result.json by filename"""
    data = load_explain_result()
    
    for event in data.get('events', []):
        if event.get('file_name', '').lower() == filename.lower():
            return event
    
    return None

# ============================================
# SAFETY CHECKS
# ============================================

def is_harmful_request(question: str) -> bool:
    """Check if user question is asking for harmful information"""
    question_lower = question.lower()
    
    # List of forbidden topics - expanded
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
        r'friend.?password',  # Specifically catch "friend password" requests
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

# ============================================
# CONTEXT BUILDING
# ============================================

def build_context_from_event(event: Dict) -> str:
    """Extract and format context from event JSON"""
    threat_info = event.get('threat_information', {})
    explanation = event.get('explanation', {})
    prevention = event.get('prevention_guidance', {})
    
    return f"""
File: {event.get('file_name', 'Unknown')}
Status: {event.get('status', 'Unknown')}
Attack Type: {threat_info.get('attack_type', 'Unknown')}
Severity: {threat_info.get('severity', 'Unknown')}

Simple Summary: {explanation.get('simple_summary', 'No summary available')}
How It Works: {explanation.get('how_the_attack_works', 'No explanation available')}
Why It's Dangerous: {explanation.get('why_it_is_dangerous', 'No risk information available')}

Recommended Actions: {', '.join(prevention.get('recommended_actions', ['No specific actions provided']))}
"""

def get_examples_for_threat(filename: str) -> str:
    """Get relevant examples based on file type"""
    filename_lower = filename.lower()
    
    if ".exe" in filename_lower:
        return """
Example: "Think of this file like someone dressing up as a delivery person to get inside your house. It looks like a normal invoice, but it's actually a program that can do bad things."
Example: "Imagine getting a package that looks like a gift but actually contains something dangerous. That's what this file was trying to do."
"""
    elif ".doc" in filename_lower or "document" in filename_lower:
        return """
Example: "This is like a regular book that has hidden instructions inside. When you open it, those hidden instructions tell your computer to do things you didn't want."
Example: "Think of it as a greeting card that tries to run commands when you open it, instead of just playing music."
"""
    elif ".msi" in filename_lower or "installer" in filename_lower:
        return """
Example: "This file is trying to install something on your computer, like when you install a new app. But since it's marked as suspicious, your computer stopped it just in case."
Example: "Think of it as someone trying to install something on your phone without asking permission first."
"""
    else:
        return """
Example: "This is like a locked door that someone tried to open with a fake key. Our security caught it and locked the door again."
Example: "Think of it as someone trying to sneak in without a ticket. The security guard caught them immediately."
"""

# ============================================
# COMPLETE GENERATE_CONVERSATIONAL_PROMPT FUNCTION - FIXED
# ============================================

# ============================================
# COMPLETE GENERATE_CONVERSATIONAL_PROMPT FUNCTION - BETTER EMOJIS
# ============================================

def generate_conversational_prompt(event: Dict, user_question: str) -> str:
    """Create a prompt that instructs Gemini to humanize the JSON data"""
    
    context = build_context_from_event(event)
    filename = event.get('file_name', 'this file')
    examples = get_examples_for_threat(filename)
    
    # Get threat information for context
    threat_info = event.get('threat_information', {})
    explanation = event.get('explanation', {})
    prevention = event.get('prevention_guidance', {})
    
    prompt = f"""You are a friendly, cheerful cybersecurity assistant helping a NON-TECHNICAL person understand what happened on their computer.

--- YOUR PERSONALITY ---
- Be warm, friendly, and encouraging like a helpful neighbor
- Use a happy and reassuring tone - make them feel safe, not scared
- Start with a friendly greeting like "Hey there! ✨" or "Hi friend! 🌈"
- End with something positive or encouraging
- NEVER sound robotic, technical, or scary

--- YOUR ONLY MISSION ---
Answer ONLY the user's specific question using ONLY the incident data below. Do NOT add extra information.

--- INCIDENT DATA (USE ONLY THIS FOR ACCURACY) ---
{context}

USER QUESTION: "{user_question}"

--- STRICT RULES (FOLLOW EXACTLY) ---
1. 🎯 ANSWER ONLY THE QUESTION: If they ask "what is this file?" - ONLY explain what the file is. If they ask "is it dangerous?" - ONLY say yes/no and why. Do NOT add unrelated information.

2. 🗣️ SIMPLE LANGUAGE: Use words a grandmother would understand. NO technical terms like: malware, executable, payload, script, exploit, vulnerability, trojan, virus, etc. Use everyday words.

3. ✂️ EXTREMELY SHORT: Maximum 3-4 sentences. People get overwhelmed by long explanations.

4. 🚫 NO NEW INFORMATION: ONLY use the incident data above. NEVER add facts from outside training.

5. 🔒 ABSOLUTELY FORBIDDEN: NEVER explain how to do anything harmful, illegal, or unethical. If the question asks for harmful things (like passwords, hacking, etc.), politely refuse.

6. 💡 CYBER AWARENESS (SANS STYLE): If relevant, include ONE simple safety tip based on SANS principles, but ONLY if it directly relates to their question.

7. 📋 USE ANALOGIES: Compare to everyday situations (like mail, locks, gifts, packages, deliveries, etc.) but keep it brief.

--- FORMATTING RULES (FOLLOW EXACTLY) ---

🎯 **MATCH THE FORMAT TO THE QUESTION TYPE:**

1. **If they ask "What is this?" or "Explain this file" or "What happened?":**
   Use a friendly analogy format with emojis:
   
   Hey there! ✨ Imagine [simple analogy comparing to everyday situation - like "a package that looks like a gift but actually has something dangerous inside"].
   
   In simple words: [1-sentence plain explanation from the incident data]
   
   Your computer caught it quickly - you're safe! 🔒


2. **If they ask "Is it dangerous?" or "What's the risk?" or "Should I worry?":**
   Use a gentle warning format:
   
   Hi friend! 🌈 Great question!
   
   [Yes/No], this file is [danger level from incident data - like "high risk" or "suspicious"]. Think of it like [simple analogy about risk - like "someone trying to pick the lock on your front door"].
   
   But here's the good news: [positive reassurance like "your computer stopped it immediately" or "it was blocked before it could do anything"]
   
   You're totally protected! 🛡️


3. **If they ask "What should I do?" or "What action should I take?" or "What now?":**
   Use a clear, friendly list format:
   
   Good news! ⭐ Your computer already handled most of it. Here's what's happening:
   
   ✅ **Already done:** [what system already did - e.g., "the file was blocked and quarantined"]
   
   📝 **Quick checklist for you:**
   • [simple action 1 - e.g., "just keep using your computer normally"]
   • [simple action 2 - e.g., "be careful with unexpected email attachments"]
   • [simple action 3 - e.g., "run updates when prompted"]
   
   That's it! You're all set! ✨


4. **If they ask "How does it work?" or "How did it get in?" or "How?":**
   Use a story-like format:
   
   Oh, let me tell you a little story! 📚
   
   Imagine [simple story analogy about how it works - e.g., "someone mailing you a fake letter that looks real, but when you open it, it tries to trick you"].
   
   That's exactly what this file tried to do - but your computer was too smart for it! 💪
   
   So you're safe and sound! ☀️


5. **If they ask "Can you give me an example?" or "Like what?":**
   Use a comparison format:
   
   Of course! Think of it this way:
   
   ❌ **What it TRIED to do:** [simple bad action from incident data]
   
   ✅ **What your computer DID instead:** [simple good action from incident data]
   
   See? Your computer is like a superhero watching over you! 🦸


6. **If they ask "Why was it blocked?" or "Why is it suspicious?":**
   Use a detective-style format:
   
   Great question! 🔎 Your computer noticed something fishy about this file:
   
   ⚠️ **The red flag:** [what made it suspicious - e.g., "it was pretending to be a document but was actually a program"]
   
   Think of it like [simple analogy - e.g., "someone wearing a police uniform who isn't really a police officer"]
   
   Your computer saw through the disguise immediately! 🕵️


7. **If they ask "What type of threat is this?" or "What kind of file?":**
   Use a simple identification format:
   
   Hi there! ⭐ This file is called a [threat type in simple words - like "a pretending program" or "a trick file"].
   
   Think of it like [simple analogy for that threat type - like "a wolf in sheep's clothing"].
   
   But don't worry - your computer recognized it and stopped it cold! 🛡️


8. **If they ask something harmful/inappropriate (like "how to hack", "friend password", "steal data", "bypass", "crack"):**
   Use a kind but firm refusal:
   
   Hey friend! 🤗 I'd love to help, but I can only explain what happened on YOUR computer and keep you safe.
   
   Is there something about this specific file you'd like to understand better? 
   I'm really good at explaining things in simple words with fun analogies! ☀️


9. **If they ask "Thank you" or "Thanks" or "Thx":**
   Use a warm appreciation format:
   
   You're so welcome! 🌟 That's what I'm here for!
   
   Stay safe out there, and remember - your computer's got your back! 🔒✨


10. **If they ask "Who are you?" or "What can you do?" or "Help":**
    Use a friendly introduction format:
    
    Hi friend! ✨ I'm your personal cybersecurity assistant!
    
    I'm here to explain anything about this suspicious file in simple words. Just ask me:
    • "What is this file?"
    • "Is it dangerous?"
    • "What should I do?"
    • "How did it work?"
    
    Whatever you want to know, I'll explain it like I'm talking to a friend! 🌈


11. **If they ask "Is my computer infected?" or "Am I safe?":**
    Use a reassuring format:
    
    Great question! 🌟 Here's the honest answer:
    
    ✅ **Good news:** Your computer caught this file and stopped it. You're protected!
    
    Think of it like [simple analogy - e.g., "a security guard catching someone at the door before they could come in"]
    
    So yes, you're safe! Your computer did its job perfectly! 🛡️


12. **For any other question not covered above:**
    Use a simple friendly format with emojis:
    
    Hi there! ☀️ About your question:
    
    [1-2 sentence direct answer using simple words from the incident data]
    
    [optional short analogy if it helps explain better]
    
    Hope that helps! Anything else about this file? ✨


--- GENERAL FORMATTING TIPS ---
- Use emojis sparingly but effectively (✨, 🌈, ⭐, 🔒, 🛡️, ✅, 📝, 🔎, ⚠️, 🕵️, 🦸, 🤗, ☀️, 🌟, 📚)
- Break text into short, readable chunks
- Use bullet points (•) for lists
- Use **bold** for important words or key points
- Maximum 4-5 lines total
- Always end with a positive, reassuring note
- Use line breaks between sections for readability

--- HELPFUL ANALOGIES YOU CAN USE (ADAPT AS NEEDED) ---
{examples}

--- SAFETY TIP (SANS STYLE - include only if relevant) ---
If the question is about prevention or safety, and it fits naturally, include ONE simple tip at the end:

🔐 **Quick safety tip:** [one simple SANS-based tip in everyday language]

Example SANS tips:
- "If you didn't expect a file, let your security software check it first - like looking through the peephole before opening the door!"
- "Think before you click - if something feels fishy, it probably is! 🎣"
- "Keep your computer updated - it's like getting stronger locks for your doors! 🔒"
- "When in doubt, throw it out - don't open files you weren't expecting! 🗑️"
- "Be careful with email attachments - they're like packages from strangers at your door!"

--- YOUR RESPONSE (FOLLOW ALL RULES ABOVE - BE FRIENDLY, SHORT, AND MATCH THE FORMAT) ---"""
    
    return prompt

def get_harmful_request_response() -> str:
    """Polite, friendly refusal for harmful requests"""
    responses = [
        "Hey friend! 👋 I'd love to help, but I'm here to explain what happened on YOUR computer and keep you safe. Is there something about this specific file you'd like to understand better? 😊",
        
        "Hi there! 😊 I can't help with that, but I'd be happy to explain why this file was blocked and how your computer protected you. Want to know more? 🛡️",
        
        "Oh, I'm not able to help with that! But you know what I CAN do? Explain exactly what this file tried to do and why your computer stopped it. Sound good? 🌟",
        
        "That's not something I can help with, but I'm really good at explaining computer safety in simple words! Ask me about this file and I'll tell you a fun analogy! 🎉"
    ]
    import random
    return random.choice(responses)

# ============================================
# FALLBACK RESPONSES
# ============================================

def get_fallback_response(event: Dict, question: str) -> str:
    """Simple fallback if AI fails - with beautiful formatting"""
    filename = event.get('file_name', 'this file')
    status = event.get('status', 'flagged')
    threat_info = event.get('threat_information', {})
    explanation = event.get('explanation', {})
    prevention = event.get('prevention_guidance', {})
    
    question_lower = question.lower()
    
    if 'risk' in question_lower or 'dangerous' in question_lower:
        why = explanation.get('why_it_is_dangerous', '')
        severity = threat_info.get('severity', '')
        
        if why:
            return f"""Hey there! 👋 Great question about safety!

{why}

Think of it like {get_simple_analogy(filename)}.

🛡️ **The good news:** Your computer spotted it right away and kept you safe!"""
    
    elif 'happen' in question_lower or 'what' in question_lower:
        summary = explanation.get('simple_summary', '')
        if summary:
            return f"""Hi friend! 😊 Here's what happened in simple words:

{summary}

✅ Your computer caught it and stopped it cold. You're safe!"""
    
    elif 'do' in question_lower or 'action' in question_lower or 'should' in question_lower:
        actions = prevention.get('recommended_actions', [])
        if actions:
            action_list = "\n• ".join(actions[:3])  # Max 3 actions
            return f"""Good news! 😊 Your computer already handled the hard part. Here's your simple checklist:

✅ **Already done:** The file was {status.lower()} automatically

📋 **Quick things to know:**
• {action_list}

That's all! You're protected! 🛡️"""
    
    elif 'work' in question_lower or 'how does' in question_lower:
        how = explanation.get('how_the_attack_works', '')
        if how:
            return f"""Oh, let me explain it simply! 📖

{how}

Imagine {get_simple_analogy(filename)}.

But don't worry - your computer was too smart to fall for it! 💪"""
    
    else:
        summary = explanation.get('simple_summary', '')
        return f"""Hey friend! 👋 About that file called {filename}:

{summary if summary else f"Your computer detected something suspicious and {status.lower()} it to keep you safe."}

🛡️ **You're all good!** Your security caught it immediately."""

def get_simple_analogy(filename: str) -> str:
    """Get a simple analogy based on file type"""
    filename_lower = filename.lower()
    
    if ".exe" in filename_lower:
        return "a package that looks like a gift but actually has something dangerous inside"
    elif ".doc" in filename_lower or ".pdf" in filename_lower:
        return "a letter that looks normal but has hidden instructions between the lines"
    elif ".zip" in filename_lower or ".rar" in filename_lower:
        return "a box that claims to have toys but actually has something harmful inside"
    elif ".msi" in filename_lower:
        return "someone trying to install something on your phone without asking"
    else:
        return "a fake message pretending to be from someone you trust"
    
# ============================================
# CORE AI FUNCTIONS - WITH SERVICE UNAVAILABLE MESSAGE
# ============================================

def generate_ai_response(event: Dict, user_question: str) -> str:
    """Use Gemini to humanize the JSON data"""
    
    try:
        # Show loading indicator
        print("🤔 Thinking", end="", flush=True)
        
        # Generate the prompt
        prompt = generate_conversational_prompt(event, user_question)
        
        # Call Gemini with animated dots
        import time
        import threading
        
        def animate_loading():
            dots = 0
            while not done_loading:
                print(".", end="", flush=True)
                dots += 1
                if dots > 3:
                    print("\b\b\b   \b\b\b", end="", flush=True)
                    dots = 0
                time.sleep(0.3)
        
        done_loading = False
        loading_thread = threading.Thread(target=animate_loading)
        loading_thread.start()
        
        # Make the API call
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt
        )
        
        done_loading = True
        loading_thread.join()
        print(" ✅")  # Clear loading and show done
        
        ai_response = response.text
        
        # Final safety check
        if contains_harmful_keywords(ai_response):
            return "I can only help explain what happened to your computer, not provide harmful information."
        
        return ai_response
        
    except Exception as e:
        done_loading = True
        print(f" ❌ AI Service Unavailable")  # Clear loading and show error
        
        # Check if it's an API limit/quota error
        error_str = str(e).lower()
        is_api_limit = any(term in error_str for term in [
            'quota', 'limit', 'rate', 'exhausted', '429', 'resource exhausted', 
            'too many requests', 'billing', 'payment required'
        ])
        
        if is_api_limit:
            service_msg = "⚠️ **AI service temporarily unavailable** (API limit reached). Here's the basic information:\n\n"
        else:
            service_msg = "⚠️ **AI service temporarily unavailable**. Here's the basic information:\n\n"
        
        # Get static answer from JSON
        static_answer = get_fallback_response(event, user_question)
        
        # Combine the warning message with the static answer
        return service_msg + static_answer

# ============================================
# MAIN FUNCTION
# ============================================

def get_chatbot_response(filename: str, user_question: str) -> str:
    """
    Main function: Humanize JSON data using Gemini
    """
    # STEP 1: Safety check with polite refusal
    if is_harmful_request(user_question):
        return get_harmful_request_response()
    
    # STEP 2: Find the incident in JSON
    event = find_event_by_filename(filename)
    
    if not event:
        return f"I couldn't find information about '{filename}'. Could you select a file from the list?"
    
    # STEP 3: Use Gemini to generate response
    return generate_ai_response(event, user_question)