"""Optional second alert channel: a Telegram bot message to your own chat (no approval step, works in minutes)."""
import time
import requests
from . import config

_last_sent = 0.0


def configured():
    return bool(config.TELEGRAM_BOT_TOKEN and config.TELEGRAM_CHAT_ID)


def send_telegram(message):
    """-> None if Telegram is not set up, else {"mode": "telegram" | "mock", "sent": bool, "detail": str}"""
    global _last_sent
    if not configured():
        return None
    if time.time() - _last_sent < config.ALERT_COOLDOWN:
        return {"mode": "mock", "sent": False,
                "detail": f"Not sent again: only one real Telegram message per {config.ALERT_COOLDOWN:.0f} s."}
    try:
        r = requests.post(f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage",
                          json={"chat_id": config.TELEGRAM_CHAT_ID, "text": message[:3500]}, timeout=20)
    except requests.RequestException as e:
        return {"mode": "mock", "sent": False, "detail": f"Could not reach Telegram ({e.__class__.__name__})."}
    try:
        body = r.json()
    except ValueError:
        body = {}
    if r.status_code == 200 and body.get("ok"):
        _last_sent = time.time()
        return {"mode": "telegram", "sent": True, "detail": "Delivered to the Telegram chat (test message)."}
    return {"mode": "mock", "sent": False,
            "detail": f"Telegram error {r.status_code}: {str(body.get('description', ''))[:140]}"}


def find_chat_ids():
    """After you send any message to your bot, this lists the chat ids it has seen."""
    r = requests.get(f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/getUpdates", timeout=20).json()
    seen = {}
    for u in r.get("result", []):
        chat = (u.get("message") or {}).get("chat") or {}
        if "id" in chat:
            seen[chat["id"]] = chat.get("first_name") or chat.get("title") or ""
    return seen