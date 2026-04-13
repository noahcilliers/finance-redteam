import os
from dotenv import load_dotenv
load_dotenv(".env")

# ── 1. OpenAI (GPT-4o + GPT-3.5-turbo) ───────────────────────────────────────
from openai import OpenAI
client_oai = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

for model in ["gpt-4o", "gpt-3.5-turbo"]:
    try:
        resp = client_oai.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "Say hi"}],
            max_tokens=20,
        )
        print(f"✅ {model}: {resp.choices[0].message.content.strip()}")
    except Exception as e:
        print(f"❌ {model}: {e}")

# ── 2. Anthropic (Claude Sonnet 4.6) ──────────────────────────────────────────
import anthropic
client_ant = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

try:
    resp = client_ant.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=20,
        messages=[{"role": "user", "content": "Say hi"}],
    )
    print(f"✅ claude-sonnet-4-6: {resp.content[0].text.strip()}")
except Exception as e:
    print(f"❌ claude-sonnet-4-6: {e}")

# ── 3. Google (Gemini 2.5 Flash) ──────────────────────────────────────────────
from google import genai
client_google = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))

try:
    resp = client_google.models.generate_content(
        model="gemini-2.5-flash",
        contents="Say hi",
    )
    print(f"✅ gemini-2.5-flash: {resp.text.strip()}")
except Exception as e:
    print(f"❌ gemini-2.5-flash: {e}")

# ── 4. Ollama (Llama 2 — local) ───────────────────────────────────────────────
import urllib.request, json

try:
    payload = json.dumps({"model": "llama2", "prompt": "Say hi", "stream": False}).encode()
    req = urllib.request.Request("http://localhost:11434/api/generate", data=payload)
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read())
    print(f"✅ llama2 (ollama): {data['response'].strip()}")
except Exception as e:
    print(f"❌ llama2 (ollama): {e}")

