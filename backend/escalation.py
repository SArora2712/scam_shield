WEIGHTS = {
    "authority_claim": 12, "urgency_fear": 14, "secrecy_isolation": 18,
    "otp_pin_request": 25, "payment_transfer_demand": 25, "remote_app_install": 22,
    "fake_kyc_block": 15, "fake_parcel_courier": 12,
    "sensitive_info_request": 25, "advance_fee_prize": 22,
    "family_emergency": 14, "investment_lure": 14,  "spam_promotion": 6, 
}
SETUP = {"authority_claim", "urgency_fear", "fake_kyc_block", "fake_parcel_courier",
         "family_emergency", "investment_lure"}
PAYOFF = {"otp_pin_request", "payment_transfer_demand", "remote_app_install",
          "sensitive_info_request", "advance_fee_prize"}
LLM_FLOOR = {"low": 10, "medium": 40, "high": 70, "critical": 90}
ARC_JUMP = 75       # score floor when a payoff request follows setup tactics
PAYOFF_MIN = 0.75   # the payoff match must be clear (similarity) to trigger the jump


def level_for(score):
    return "safe" if score < 30 else "suspicious" if score < 60 else "likely_scam" if score < 80 else "scam"


def strength(c):
    """Similarity 0.65 -> 0.5 (weak), 0.85+ -> 1.0 (strong)."""
    return max(0.5, min(1.0, (c - 0.55) / 0.30))


class Scorer:
    def __init__(self):
        self.seen = {}      # tactic -> confidence (fades during normal talk)
        self.order = []     # tactics in first-seen order
        self.score = 0.0
        self.quiet = 0

    def update(self, signals, llm_level=None):
        """signals: [(tactic, confidence)] for this segment."""
        before = set(self.seen)                      # evidence from EARLIER segments only
        if signals:
            self.quiet = 0
            for t, c in signals:
                if t not in self.order:
                    self.order.append(t)
                self.seen[t] = max(self.seen.get(t, 0), c)
        else:
            self.quiet += 1
            if self.quiet >= 3:                      # normal talk: old evidence fades
                for t in list(self.seen):
                    self.seen[t] *= 0.85
                    if self.seen[t] < 0.5:
                        del self.seen[t]

        target = sum(WEIGHTS[t] * strength(c) for t, c in self.seen.items())
        first_payoff = next((i for i, t in enumerate(self.order) if t in PAYOFF), None)
        if first_payoff is not None and any(t in SETUP and t in self.seen for t in self.order[:first_payoff]):
            target += 12
        if sum(1 for t, c in self.seen.items() if t in PAYOFF and c >= PAYOFF_MIN) >= 2:
            target += 20                              # two different kinds of ask (money, OTP, card, app)
        if llm_level:
            target = max(target, LLM_FLOOR.get(llm_level, 0) * 0.9)
        target = min(100.0, target)

        if target > self.score:                       # rise fast
            self.score = 0.35 * self.score + 0.65 * target
        else:                                         # fall slowly
            self.score = 0.9 * self.score + 0.1 * target

        # decisive moment: a CLEAR payoff request arrives after setup tactics from earlier segments
        new_payoff = any(t in PAYOFF and t not in before and c >= PAYOFF_MIN for t, c in signals)
        if new_payoff and any(t in SETUP for t in before):
            self.score = max(self.score, ARC_JUMP)

        s = round(self.score)
        return {"score": s, "level": level_for(s), "tactics": list(self.order)}