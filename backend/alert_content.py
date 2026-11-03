"""Wording for the spoken warning and the family alert, built from what was actually detected."""

# first match wins; each entry: (tactics that trigger it, advice sentence, spoken Hinglish line for Timbre)
GUIDE = [
    ({"otp_pin_request"}, "Do not share any OTP or PIN.",
     "Savdhaan! Yeh call suspicious lag rahi hai. Apna OTP ya PIN kisi ko na batayein."),
    ({"sensitive_info_request"}, "Do not share card, bank or Aadhaar details.",
     "Savdhaan! Yeh call suspicious lag rahi hai. Apne card ya bank ki details kisi ko na batayein."),
    ({"payment_transfer_demand", "advance_fee_prize"}, "Do not send money or pay any fee.",
     "Savdhaan! Yeh call suspicious lag rahi hai. Kisi ko paise ya fees na bhejein."),
    ({"remote_app_install"}, "Do not install any app or give remote access.",
     "Savdhaan! Yeh call suspicious lag rahi hai. Koi bhi app install na karein."),
    ({"family_emergency"}, "Call the family member on their known number before doing anything.",
     "Savdhaan! Pehle apne parivar ke sadasya ko khud call karke confirm karein."),
    ({"fake_kyc_block"}, "Banks do not ask for details on calls. Verify on the bank's official number.",
     "Savdhaan! Bank kabhi phone par OTP ya details nahi maangta. Bank ke official number par verify karein."),
    ({"fake_parcel_courier"}, "Do not pay or click links for a parcel. Check on the courier's official site.",
     "Savdhaan! Parcel ke naam par paise ya link se bachein. Official website par check karein."),
    ({"authority_claim", "urgency_fear", "secrecy_isolation"},
     "Real officials do not ask for money or secrecy on a call. Hang up and verify on an official number.",
     "Savdhaan! Asli police ya adhikari phone par paise nahi maangte. Call kaat dein aur official number par verify karein."),
]
GENERIC_ADVICE = "Verify the caller on an official number before sharing or paying anything."
GENERIC_LINE = "Savdhaan! Yeh call suspicious lag rahi hai. Kuch bhi batane ya bhejne se pehle verify karein."


def _matches(tactics):
    got = set(tactics)
    return [g for g in GUIDE if g[0] & got]


def spoken_line(tactics):
    m = _matches(tactics)
    return m[0][2] if m else GENERIC_LINE


def alert_text(peak, level, reason, advice, tactics):
    """The alert says only what was found: 'scam' or 'suspicious', why, and advice that fits."""
    head = "looks like a SCAM" if level == "scam" else "looks SUSPICIOUS"
    names = ", ".join(t.replace("_", " ") for t in list(dict.fromkeys(tactics))[:3])
    why = reason.strip() if reason else (f"It shows: {names}." if names else "")
    tips = [advice.strip()] if advice else [g[1] for g in _matches(tactics)[:2]] or [GENERIC_ADVICE]
    risk = f"risk {peak}/100" if peak else "flagged by the AI analyst"
    return (f"TEST ALERT from Scam Shield (simulated demo): a monitored call {head} ({risk}). "
            f"{why} {' '.join(tips)}").replace("  ", " ").strip()