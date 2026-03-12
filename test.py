import os
from dotenv import load_dotenv
import google.generativeai as genai

# Load API key
load_dotenv('chatbot/.env')
api_key = os.getenv("GEMINI_API_KEY")

print(f"API Key found: {'Yes' if api_key else 'No'}")

if api_key:
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-pro')
        response = model.generate_content("Say hello")
        print(f"API Response: {response.text}")
    except Exception as e:
        print(f"API Error: {e}")