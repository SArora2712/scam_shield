"""F6: family alert through the Twilio WhatsApp sandbox (plain REST call, no extra library).
Sends a plain text message (Body only). No Content API and no template SID is needed for the sandbox.
Without Twilio settings it only returns a mock, and the dashboard shows the message on screen."""
import time
import requests
from . import config
from .alerts_telegram import send_telegram

_last_sent = 0.0
HINTS = {
    63015: "The phone has not joined the sandbox. Send the 'join ...' message from that phone to the sandbox number.",
    63016: "Outside the allowed window. Send 'hi' to the sandbox number from that phone, then try again.",
    20003: "Authentication failed. Check the Account SID and Auth Token in .env.",
}


def alert_text(peak, reason, tactics):
    what = ", ".join(t.replace("_", " ") for t in tactics[:3]) or "scam tactics"
    why = (reason.strip() + " ") if reason else ""
    return (f"TEST ALERT from Scam Shield (simulated demo): a monitored call looks like a scam "
            f"(risk {peak}/100; {what}). {why}Do not share OTP/PIN or send money. Call the person directly.")


def _wa(number):
    number = number.strip()
    return number if number.startswith("whatsapp:") else "whatsapp:" + number


def send_alert(message):
    """Tries WhatsApp (Twilio sandbox) first, then Telegram if it is set up, else a mock for the screen.
    -> {"mode": "whatsapp" | "telegram" | "mock", "sent": bool, "detail": str}"""
    res = _send_whatsapp(message)
    if res["sent"]:
        return res
    tg = send_telegram(message)
    if tg is None:
        return res
    if tg["sent"]:
        tg["detail"] += " WhatsApp was not used: " + res["detail"][:90]
        return tg
    res["detail"] += " | Telegram: " + tg["detail"]
    return res


def _send_whatsapp(message):
    """-> {"mode": "whatsapp" | "mock", "sent": bool, "detail": str}"""
    global _last_sent
    sid, token = config.TWILIO_ACCOUNT_SID, config.TWILIO_AUTH_TOKEN
    frm, to = config.TWILIO_WHATSAPP_FROM, config.ALERT_TO_WHATSAPP
    if not (sid and token and frm and to):
        return {"mode": "mock", "sent": False, "detail": "Twilio is not set up, so this is shown on screen only."}
    if time.time() - _last_sent < config.ALERT_COOLDOWN:
        return {"mode": "mock", "sent": False,
                "detail": f"Not sent again: only one real WhatsApp message per {config.ALERT_COOLDOWN:.0f} s."}
    try:
        r = requests.post(f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json", auth=(sid, token),
                          data={"From": _wa(frm), "To": _wa(to), "Body": message[:1500]}, timeout=20)
    except requests.RequestException as e:
        return {"mode": "mock", "sent": False, "detail": f"Could not reach Twilio ({e.__class__.__name__})."}
    if r.status_code in (200, 201):
        _last_sent = time.time()
        return {"mode": "whatsapp", "sent": True, "detail": "Accepted by Twilio (WhatsApp sandbox)."}
    code, msg = None, ""
    try:
        body = r.json()
        code, msg = body.get("code"), body.get("message", "")
    except ValueError:
        pass
    hint = HINTS.get(code, "")
    return {"mode": "mock", "sent": False,
            "detail": f"Twilio error {r.status_code} (code {code}): {msg[:140]} {hint}".strip()}