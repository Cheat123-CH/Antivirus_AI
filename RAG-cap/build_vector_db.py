"""
build_vector_db.py — rebuilds the Chroma vector database from sans_documents.txt.

Key fix: chunks by SECTION (one chunk per response type) instead of by character
count. This ensures that when RAG retrieves chunks for "Ransomware", it gets ALL
the ransomware steps together — not half of ransomware + half of keylogger.
"""

import os
try:
    from langchain_core.documents import Document
except ImportError:
    from langchain.schema import Document
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings


# ── Load and split by section ─────────────────────────────────────────────────

def load_sections(filepath):
    """
    Reads sans_documents.txt and splits it into one Document per section.
    A section starts on any line that ends with 'Response' (the header line).
    Each Document's metadata carries the section title so it can be retrieved
    and displayed for debugging.
    """
    docs = []
    current_title = None
    current_lines = []

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip()

            # Blank lines separate sections — flush current section
            if line == "":
                if current_title and current_lines:
                    content = current_title + "\n" + "\n".join(current_lines)
                    docs.append(Document(
                        page_content=content,
                        metadata={"section": current_title}
                    ))
                    current_title = None
                    current_lines = []
                continue

            # A line ending with "Response" is a section header
            if line.endswith("Response"):
                # Save any previous section that wasn't terminated by a blank line
                if current_title and current_lines:
                    content = current_title + "\n" + "\n".join(current_lines)
                    docs.append(Document(
                        page_content=content,
                        metadata={"section": current_title}
                    ))
                current_title = line
                current_lines = []
            else:
                if current_title:
                    current_lines.append(line)

    # Flush the final section
    if current_title and current_lines:
        content = current_title + "\n" + "\n".join(current_lines)
        docs.append(Document(
            page_content=content,
            metadata={"section": current_title}
        ))

    return docs


# ── Build vector database ─────────────────────────────────────────────────────

SANS_FILE   = "data/sans_documents.txt"
VECTOR_DIR  = "vector_db"

print(f"[1/4] Loading sections from {SANS_FILE} ...")
docs = load_sections(SANS_FILE)
print(f"      Loaded {len(docs)} sections:")
for d in docs:
    steps = len([l for l in d.page_content.splitlines() if l and not l.endswith("Response")])
    print(f"        · {d.metadata['section']}  ({steps} steps)")

print(f"\n[2/4] Loading embedding model ...")
embeddings = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2"
)

print(f"\n[3/4] Building Chroma vector database at '{VECTOR_DIR}' ...")
# Delete old database first so we start completely fresh
import shutil
if os.path.exists(VECTOR_DIR):
    shutil.rmtree(VECTOR_DIR)
    print(f"      Deleted old vector_db.")

vectorstore = Chroma.from_documents(
    docs,
    embeddings,
    persist_directory=VECTOR_DIR
)

vectorstore.persist()

print(f"\n[4/4] Done. Vector database created with {len(docs)} sections.")
print(f"\nTo verify retrieval is working, run:")
print(f"  python test.py")