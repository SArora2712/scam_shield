import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=True)

ROOT=Path(__file__).resolve().parent.parent
USE_EMBEDDINGS=os.getenv("USE_EMBEDDINGS","1")=="1"
EMBED_MODEL=os.getenv("EMBED_MODEL","paraphrase-multilingual-MiniLm-L12-v2")
MATCH_THRESHOLD=float(os.getenv("MATCH_THRESHOLD","0.65"))
ALERT_THRESHOLD=float(os.getenv("ALERT_THRESHOLD","70"))
GNANI_API_KEY=os.getenv("GNANI_API_KEY")
EMBED_BACKEND = os.getenv("EMBED_BACKEND", "fastembed")   # "fastembed" or "torch"
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")
VERDICT_MODE = os.getenv("VERDICT_MODE", "balanced")   # "balanced" (rules keep a veto) or "ai_first"
ALERT_COOLDOWN = float(os.getenv("ALERT_COOLDOWN", "30"))        # seconds between real sends
AI_ALONE_MIN = float(os.getenv("AI_ALONE_MIN", "0.9"))   # AI-only "scam" below this confidence is shown as "Suspicious"
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_WHATSAPP_FROM = os.getenv("TWILIO_WHATSAPP_FROM", "")
TWILIO_CONTENT_SID = os.getenv("TWILIO_CONTENT_SID", "")
ALERT_TO_WHATSAPP = os.getenv("ALERT_TO_WHATSAPP", "")
ALERT_AUTO_MIN = float(os.getenv("ALERT_AUTO_MIN", "85"))