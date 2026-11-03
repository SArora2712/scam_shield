"""Rule-based cues for scam tactics. Works together with the embedding matcher.
Strong, specific phrases only. Requests (OTP, card details, money) must be a request, not a warning."""
import re

DONE_FORMS = {"rahi", "raha", "rahe", "rahin", "diya", "di", "liya", "chuka", "chuki", "chuke"}
NEG = {"not", "never", "mat", "nahi", "nahin", "na", "kabhi", "dont", "don", "cannot"}
VERB_EXACT = {"de", "do", "dena", "dedo", "dijiye", "boliye", "bolo", "read", "tell", "give", "type", "send", "share",
              "enter", "confirm", "provide", "forward", "likh", "dalo"}
VERB_STEMS = ("bata", "bol", "bhej", "daal", "dij", "share", "send", "enter", "confirm", "provide", "forward")
PAY_VERBS = {"pay", "payment", "transfer", "send", "deposit", "jama", "dedo", "dena", "karni", "karna", "padegi",
             "padega", "hogi", "chahiye"}
PAY_STEMS = ("bhej", "daal", "transfer", "jama")
MONEY = {"rs", "rupees", "rupee", "rupaye", "rupya", "hazar", "hajar", "thousand", "lakh", "lac", "crore",
         "fee", "fees", "charges", "deposit", "amount", "tax", "paisa", "paise"}

OTP_TERMS = [("otp",), ("pin",), ("mpin",), ("cvv",), ("passcode",), ("password",)]
SENSITIVE_TERMS = [("account", "number"), ("account", "details"), ("card", "number"), ("card", "details"),
                   ("debit", "card"), ("credit", "card"), ("aadhaar",), ("aadhar",), ("pan", "card"), ("pan", "number"),
                   ("bank", "details"), ("bank", "balance"), ("balance", "details"), ("login", "details"),
                   ("login", "credentials"), ("net", "banking"), ("netbanking",), ("expiry",)]

RULES = [
    # authority
    ("authority_claim", .85, r"\b(main|mai|hum|this is|i am|i m)\b.{0,45}\b(inspector|cbi|cyber ?crime|crime branch|police|customs|narcotics|enforcement|income tax|trai|rbi|ncb|court|sebi)\b"),
    ("authority_claim", .8, r"\b(instagram|facebook|whatsapp|google|amazon|microsoft|apple|paytm|phonepe|flipkart)\b.{0,15}\b(support|security|team|helpline)\b"),
    ("authority_claim", .75, r"\b(electricity|bijli|power|gas|water|telecom|bsnl|jio|airtel)\b.{0,25}\b(department|office|board)\b"),
    # urgency / fear
    ("urgency_fear", .85, r"\b(arrest|arrested|warrant|jail|gireftar|legal action|case darj)\b"),
    ("urgency_fear", .8, r"\b(block|blocked|suspend|suspended|freeze|frozen|disconnect|disconnected|cut|band|deactivate|expire)\b.{0,12}\b(ho jayega|ho jayegi|ho sakta|ho sakti|kar diya jayega|hoga|ho jaega|ho jaayega)\b"),
    ("urgency_fear", .75, r"\b(abhi turant|turant|immediately|right now|aaj hi|aaj raat|last chance|sirf \d+ (minute|minutes|min|ghante|hours?))\b"),
    ("urgency_fear", .75, r"\b(offer|payment|deadline|link)\b.{0,25}\b(valid|expire|expires|expired)\b"),
    # secrecy / isolation
    ("secrecy_isolation", .85, r"\b(kisi ko|kisiko|kisi se|ghar (walon|wale|walo)|family|parivar)\b(?:(?!\botp\b|\bpin\b|\bcvv\b|\bpassword\b|\bcard\b).){0,30}\b(mat|na|nahi|nahin)\b.{0,12}\b(bata|batana|batao|bolna|bolo|share)"),
    ("secrecy_isolation", .85, r"\b(do not|dont|don t|never)\b.{0,15}\b(tell|inform)\b"),
    ("secrecy_isolation", .8, r"\b(confidential|secret|gupt)\b|\bapne tak (hi )?rakh"),
    ("secrecy_isolation", .85, r"\bline (par|pe)\b.{0,12}\b(bane|rahiye|rahein|rehna|rahna|bani)\b|\b(call|phone) (mat )?(kaat|cut|disconnect)\b"),
    ("secrecy_isolation", .85, r"\b(digital arrest|digital verification|video call (par|pe|mein)|camera (on|chalu)|under surveillance)\b|\binvestigation\b.{0,30}\b(mat|na) bata"),
    # remote access / install
    ("remote_app_install", .9, r"\b(anydesk|any desk|teamviewer|team viewer|quicksupport|quick support|rustdesk|ultraviewer|screen ?share|screenshare|remote access|apk)\b"),
    ("remote_app_install", .8, r"\b(install|download)\b.{0,30}\b(application|software|file)\b|\b(application|software)\b.{0,25}\b(install|download)\b"),
    ("remote_app_install", .8, r"\blink\b.{0,20}\b(click|open|kholiye|khol)\b|\b(click|open)\b.{0,15}\blink\b"),
    ("remote_app_install", .8, r"\bpermissions?\b.{0,20}\b(allow|dijiye|do|enable)\b"),
    # fake KYC / account block
    ("fake_kyc_block", .8, r"\b(kyc|pan (card )?(link|update)|aadhaar (link|update)|aadhar (link|update)|sim (band|block))\b"),
    ("fake_kyc_block", .8, r"\baccount\b.{0,20}\b(block|blocked|freeze|frozen|suspend|suspended|deactivate|close|closed|band)\b|\b(block|suspend|freeze|deactivate)\b.{0,15}\baccount\b"),
    ("fake_kyc_block", .75, r"\bsuspicious (login|activity|transaction)\b|\bunauthori[sz]ed\b"),
    # fake parcel / courier / customs
    ("fake_parcel_courier", .85, r"\b(parcel|courier|package|shipment|fedex|dhl|bluedart|blue dart|india post)\b.{0,60}\b(customs|held|hold|pakda|pakde|seize|seized|illegal|drugs?|narcotics|contraband|return ho)\b|\b(customs|narcotics)\b.{0,40}\b(parcel|courier|package)\b"),
    ("fake_parcel_courier", .8, r"\b(aadhaar|aadhar)\b.{0,40}\b(parcel|courier|package|sim|illegal|bank account)\b|\billeg(al)? (bank )?account\b"),
    # advance fee / prize / job lure
    ("advance_fee_prize", .85, r"\b(registration|processing|joining|security|refundable|clearance|insurance|delivery|customs|gst|tax|advance|verification)\b.{0,8}\b(fee|fees|charges|deposit|amount|payment)\b"),
    ("advance_fee_prize", .85, r"\b(lottery|lucky draw|jackpot|inaam|prize|winner|jeeti|jeete)\b"),
    ("advance_fee_prize", .8, r"\b(interview ki zarurat nahi|bina interview|no interview|directly selected|without interview)\b"),
    ("advance_fee_prize", .75, r"\bcashback\b.{0,30}\b(pending|expire|claim|receive|milega)\b|\b(pending|claim)\b.{0,15}\bcashback\b"),
    # payment mechanics
    ("payment_transfer_demand", .85, r"\b(payment|pay) link\b|\bcollect request\b|\b(safe|secure|rbi|government) account\b"),
    # family emergency
    ("family_emergency", .85, r"\b(beta|beti|son|daughter|bhai|brother|sister|behen|husband|pati|wife|patni|papa|mummy|mother|father)\b.{0,60}\b(accident|hospital|custody|arrest|arrested|kidnap|kidnapped|bail|lockup|police station)\b"),
    # investment lure
    ("investment_lure", .85, r"\b(guaranteed|pakka|fixed|assured)\b.{0,25}\b(return|returns|profit|munafa|double)\b|\bdouble (your )?(money|paisa)\b|\b(paisa|paise|money) double\b|\brisk[- ]?free\b|\bdaily (profit|income|earning)\b"),
    ("investment_lure", .75, r"\b(crypto|bitcoin|forex|stock tips?|trading)\b.{0,40}\b(invest|profit|returns?|earn|munafa)\b"),
    # spam / robocall
    ("spam_promotion", .8, r"\b(final|last) courtesy call\b|\bpre[- ]?approved\b|\bpress (1|one|2|two|5|five|9|nine)\b|\blimited[- ]time offer\b|\bexclusive (offer|deal)\b|\byou (have been|are) selected\b|\blowest interest\b|\binterest rates? as low\b|\bspecial offer\b|\bcongratulations\b"),
]
_COMPILED = [(t, c, re.compile(p)) for t, c, p in RULES]


def _normalise(text):
    t = text.lower().replace("\u20b9", " rs ")
    t = re.sub(r"(?<=\d),(?=\d)", "", t)
    t = re.sub(r"\bo t p\b", "otp", t)
    t = re.sub(r"[^\w\s\u0900-\u097f]", " ", t)
    return " ".join(t.split())


def _is_verb(tok):
    return tok in VERB_EXACT or tok.startswith(VERB_STEMS)


def _is_pay_verb(tok):
    return tok in PAY_VERBS or tok.startswith(PAY_STEMS)


def _is_money(tok):
    return tok in MONEY or (tok.isdigit() and len(tok) >= 3)


def _spans(tokens, seqs):
    for i in range(len(tokens)):
        for seq in seqs:
            if tuple(tokens[i:i + len(seq)]) == seq:
                yield i, i + len(seq) - 1


def _asks(tokens, spans, is_verb, window=5):
    """True if a term is near a request verb with no negation word in between (or just before the verb)."""
    for a, b in spans:
        for j in range(max(0, a - window), min(len(tokens), b + window + 1)):
            if a <= j <= b or not is_verb(tokens[j]):
                continue
            if j + 1 < len(tokens) and tokens[j + 1] in DONE_FORMS:      # "bata rahi thi" = telling, not asking
                continue
            between = tokens[b + 1:j] if j > b else tokens[j + 1:a]
            neg = any(t in NEG for t in between) or (j < a and any(t in NEG for t in tokens[max(0, j - 2):j]))
            if not neg:
                return True
    return False


def lexical_hits(text):
    """-> [(tactic, confidence)]"""
    s = _normalise(text)
    if not s:
        return []
    tokens = s.split()
    hits = {}
    for tactic, conf, rx in _COMPILED:
        if rx.search(s):
            hits[tactic] = max(hits.get(tactic, 0), conf)
    if _asks(tokens, list(_spans(tokens, OTP_TERMS)), _is_verb):
        hits["otp_pin_request"] = max(hits.get("otp_pin_request", 0), .85)
    if _asks(tokens, list(_spans(tokens, SENSITIVE_TERMS)), _is_verb):
        hits["sensitive_info_request"] = max(hits.get("sensitive_info_request", 0), .85)
    money = [(i, i) for i, t in enumerate(tokens) if _is_money(t)]
    if _asks(tokens, money, _is_pay_verb, window=6):
        hits["payment_transfer_demand"] = max(hits.get("payment_transfer_demand", 0), .8)
    return sorted(hits.items(), key=lambda x: -x[1])