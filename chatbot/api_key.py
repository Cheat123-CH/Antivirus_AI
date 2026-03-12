import os
from dotenv import load_dotenv

load_dotenv()
CHATBOT_API_KEY = os.getenv("CHATBOT_API_KEY", "").strip()