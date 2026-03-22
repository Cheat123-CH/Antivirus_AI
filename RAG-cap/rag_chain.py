import os
from dotenv import load_dotenv

from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_google_genai import ChatGoogleGenerativeAI

from prompt_template import build_prompt

load_dotenv()

# Embedding model
embeddings = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2"
)

# Load vector database
vector_db = Chroma(
    persist_directory="vector_db",
    embedding_function=embeddings
)

retriever = vector_db.as_retriever(search_kwargs={"k":3})

# Gemini model
llm = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash",
    google_api_key=os.getenv("GEMINI_API_KEY")
)

def generate_actions(alert):

    query = f"{alert['mitre_technique']} {alert['malicious_activity']}"

    # New LangChain retrieval
    docs = retriever.invoke(query)

    context = "\n".join([d.page_content for d in docs])

    prompt = build_prompt(alert, context)

    response = llm.invoke(prompt)

    return response.content