import asyncio, base64, io, json, re, time, traceback, wave
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from . import config
from .embeddings import Matcher
from .escalation import Scorer
from .llm_context import analyse_window,classify_call
from .segmenter import split_segments
from .audio_utils import wav_to_pcm, split_pcm, pcm_to_wav_bytes
from .noise import degrade, LEVELS
from .tts_gnani import synthesize_cached, WARNING_LINES
from .alerts_whatsapp import send_alert
from .alert_content import alert_text, spoken_line
from .stt_gnani import transcribe_turn, transcribe_clip_cached

app = FastAPI(title="Scam Shield")
SCRIPTS = config.ROOT / "data" / "scripts"
matcher = Matcher()

CALLER_WORDS = {"caller", "scammer", "agent", "officer", "bank", "fraudster"}
VICTIM_WORDS = {"victim", "customer", "user", "me", "you", "person"}
MAX_AUDIO_SECONDS = 180


def parse_script(text):
    """'CALLER: ...' / 'VICTIM: ...' lines. No known prefix = caller. Long lines are split into sentences."""
    turns = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^([A-Za-z]+)\s*:\s*(.+)$", line)
        if m and m.group(1).lower() in CALLER_WORDS | VICTIM_WORDS:
            who = "caller" if m.group(1).lower() in CALLER_WORDS else "victim"
            body = m.group(2).strip()
        else:
            who, body = "caller", line
        for seg in split_segments(body):
            turns.append((who, seg))
    return turns[:300]


def load_script(name):
    return parse_script((SCRIPTS / f"{name}.txt").read_text(encoding="utf-8"))


def pcm_to_wav_b64(pcm, rate):
    return base64.b64encode(pcm_to_wav_bytes(pcm, rate)).decode()


class Analysis:
    """Keeps the running state for one call and produces the final verdict."""

    def __init__(self):
        self.scorer, self.history, self.evidence = Scorer(), [], {}
        self.alerted, self.peak, self.out, self.n, self.spam = False, 0, None, 0, 0
        self.lines=[]

    def step(self, seg, who="caller"):
        signals = matcher.match(seg) if who == "caller" else []
        self.history.append(seg)
        self.lines.append({"who": who, "text": seg, "signals": signals})
        llm = analyse_window(self.history[-12:]) if self.n % 3 == 2 else None
        self.n += 1
        self.out = self.scorer.update(signals, llm["risk_level"] if llm else None)
        self.peak = max(self.peak, self.out["score"])
        for t, s in signals:
            if t == "spam_promotion":
                self.spam += 1
            self.evidence.setdefault(t, {"quote": seg, "sim": s})
        fire = self.out["score"] >= config.ALERT_THRESHOLD and not self.alerted
        self.alerted = self.alerted or fire
        return signals, self.out, fire
    def transcript(self):
        return "\n".join(
            f"{line['who'].upper()}: {line['text']}"
            for line in self.lines
        )
    def verdict(self):
        if self.peak >= config.ALERT_THRESHOLD:
            label, level = "Likely scam", "scam"
        elif self.peak >= 30:
            label, level = "Suspicious", "suspicious"
        elif self.spam >= 2:
            label, level = "Likely spam (unsolicited promotion)", "spam"
        elif self.n == 0:
            label, level = "Nothing to analyse", "safe"
        else:
            label, level = "Looks normal", "safe"
        return {"label": label, "level": level, "peak": self.peak, "lines": self.n,
                "spam_lines": self.spam,
                "evidence": [{"tactic": t, **v} for t, v in self.evidence.items()]}
def combine_verdict(v, ai):
    """Merge the rule/embedding verdict with the AI analyst's.
    balanced: rules can still raise a warning on their own (AI 'normal' never makes a rules 'scam' fully safe).
    ai_first: when the AI is confident, its label decides; the rules only act as a safety net.
    If the AI is the only signal (rules saw nothing) it needs AI_ALONE_MIN confidence to say 'Likely scam'."""
    v = dict(v)
    v["ai"], v["decided_by"] = ai, "rules"
    if not ai:
        return v
    rules, label, conf = v["level"], ai["label"], ai["confidence"]

    def scam():
        if rules == "safe" and conf < config.AI_ALONE_MIN:
            v.update(label="Suspicious (AI only, not fully sure)", level="suspicious", decided_by="ai")
        else:
            v.update(label="Likely scam", level="scam", decided_by="rules+ai" if rules == "scam" else "ai")

    if config.VERDICT_MODE == "ai_first" and conf >= 0.6:
        if label == "scam":
            scam()
        elif rules == "scam":
            v.update(label="Suspicious (rules and AI disagree)", level="suspicious", decided_by="disagree")
        elif label == "spam":
            v.update(label="Likely spam (unsolicited promotion)", level="spam", decided_by="ai")
        else:
            v.update(label="Looks normal", level="safe", decided_by="rules+ai" if rules == "safe" else "ai")
        return v
    if label == "scam" and conf >= 0.6:
        scam()
    elif rules == "scam" and label == "normal" and conf >= 0.7:
        v.update(label="Suspicious (rules and AI disagree)", level="suspicious", decided_by="disagree")
    elif label == "spam" and conf >= 0.6 and rules == "safe":
        v.update(label="Likely spam (unsolicited promotion)", level="spam", decided_by="ai")
    elif label == "normal" and rules == "safe":
        v["decided_by"] = "rules+ai"
    return v

@app.get("/")
def index():
    return FileResponse(config.ROOT / "frontend" / "index.html")


@app.get("/scripts")
def scripts():
    return sorted(p.stem for p in SCRIPTS.glob("*.txt"))


@app.get("/levels")
def levels():
    return list(LEVELS)


@app.websocket("/ws")
async def ws(sock: WebSocket):
    await sock.accept()
    state = {"stop": False}
    task = None

    async def status(text, done=None, total=None):
        await sock.send_json({"type": "status", "text": text, "done": done, "total": total})

    
    async def raise_alert(an, v=None):
        """Spoken warning and family alert, both worded from what was actually detected."""
        try:
            v = v or an.verdict()
            ai = v.get("ai") or {}
            tactics = [e["tactic"] for e in v["evidence"]]
            line = spoken_line(tactics)
            msg = alert_text(an.peak, v.get("level", "scam"), ai.get("reason", ""), ai.get("advice", ""), tactics)
            try:
                wav = await asyncio.to_thread(synthesize_cached, line, "Nalini", "hi-IN")
                await sock.send_json({"type": "warning", "b64": base64.b64encode(wav).decode(), "text": line})
            except Exception as e:
                await sock.send_json({"type": "notice", "text": f"Spoken warning unavailable: {e}"})
            res = await asyncio.to_thread(send_alert, msg)
            await sock.send_json({"type": "alert_card", "message": msg, **res})
        except Exception as e:
            traceback.print_exc()
            try:
                await sock.send_json({"type": "notice", "text": f"Alert failed: {e}"})
            except Exception:
                pass

    async def send_test_alert():
        msg = "TEST from Scam Shield (simulated demo): this is a channel check, not a real alert."
        try:
            res = await asyncio.to_thread(send_alert, msg)
            await sock.send_json({"type": "alert_card", "message": msg, **res})
        except Exception as e:
            traceback.print_exc()
            await sock.send_json({"type": "notice", "text": f"Test alert failed: {e}"})

    async def guarded(coro):
        """Whatever happens inside a run, the page always gets an 'end' so the Analyse button comes back."""
        try:
            await coro
        except asyncio.CancelledError:
            raise
        except Exception as e:
            traceback.print_exc()
            try:
                await sock.send_json({"type": "notice", "text": f"Analysis stopped by an error: {e}"})
                await sock.send_json({"type": "end", "final": None, "verdict": None})
            except Exception:
                pass                                  # the connection may have closed meanwhile
    async def emit(an, seg, who, source, lat=None, said=None, noise="clean"):
        signals, out, fire = an.step(seg, who)
        await sock.send_json({
            "type": "segment", "who": who, "text": seg, "said": said,
            "source": source, "latency_ms": lat, "noise": noise,
            "flags": [{"tactic": t, "sim": s} for t, s in signals],
            "alert": fire, **out})
        if fire:
            asyncio.create_task(raise_alert(an))
    async def finish(an):
        v, ai = an.verdict(), None
        if config.GROQ_API_KEY and an.n > 0:
            await status("Asking the AI analyst")
            try:
                ai = await asyncio.to_thread(classify_call, an.transcript())
            except Exception as e:
                await sock.send_json({"type": "notice", "text": f"AI analysis unavailable: {e}"})
        final = combine_verdict(v, ai)
        await sock.send_json({"type": "end", "final": an.out, "verdict": final,
                              "ai_enabled": bool(config.GROQ_API_KEY), "ai": ai})
        if final["level"] == "scam" and not an.alerted:      # the final verdict says scam but the meter never crossed
            an.alerted = True
            await raise_alert(an, final)    
    async def run_text(turns, mode, noise, fresh):
        an = Analysis()
        total = len(turns)
        callers = sum(1 for w, _ in turns if w == "caller")
        spoken = 0
        for i, (who, text) in enumerate(turns):
            if state["stop"]:
                break
            if mode == "voice" and who == "caller":
                spoken += 1
                try:
                    await status(f"Speaking line {spoken} of {callers} (Timbre)", i, total)
                    wav = await asyncio.to_thread(synthesize_cached, text)
                    pcm, rate = degrade(wav_to_pcm(wav, 16000), noise)
                    dur = len(pcm) / 2 / rate
                    await sock.send_json({"type": "audio", "b64": pcm_to_wav_b64(pcm, rate),
                                          "seconds": round(dur, 1)})
                    await status(f"Transcribing line {spoken} of {callers} (Prisma)", i, total)
                    t0 = time.monotonic()
                    res = await transcribe_turn(pcm, rate, "en-IN", cache_key=f"{text}|{noise}",
                                                use_cache=not fresh)
                except Exception as e:
                    await sock.send_json({"type": "notice", "text": f"Voice step failed: {e}"})
                    continue
                if res["error"]:
                    await sock.send_json({"type": "notice", "text": f"Prisma returned nothing: {res['error']}"})
                    continue
                if res["source"] == "cached":     # keep the timing of a real call
                    await asyncio.sleep(max(0.0, dur - (time.monotonic() - t0)))
                for seg, lat in zip(res["segments"], res["latency_ms"]):
                    await emit(an, seg, who, res["source"], lat, said=text, noise=noise)
            else:
                await status(f"Analysing line {i + 1} of {total}", i, total)
                if mode == "voice":               # victim line: shown, not spoken, not scored
                    await asyncio.sleep(1.0)
                await emit(an, text, who, "script")
                await asyncio.sleep(0.25 if total <= 24 else 0.05)
        await status("Done", total, total)
        await finish(an)

    async def run_audio(pcm, fresh):
        an = Analysis()
        chunks = split_pcm(pcm)
        for k, chunk in enumerate(chunks, 1):
            if state["stop"]:
                break
            await status(f"Transcribing part {k} of {len(chunks)} (Prisma)", k - 1, len(chunks))
            try:
                res = await asyncio.to_thread(transcribe_clip_cached, pcm_to_wav_bytes(chunk), "en-IN", not fresh)
            except Exception as e:
                await sock.send_json({"type": "notice", "text": f"Part {k} failed: {e}"})
                continue
            if not res["text"].strip():
                await sock.send_json({"type": "notice", "text": f"Part {k}: no speech detected"})
                continue
            for seg in split_segments(res["text"]):
                await emit(an, seg, "caller", res["source"])
        await status("Done", len(chunks), len(chunks))
        await finish(an)

    try:
        while True:
            msg = json.loads(await sock.receive_text())
            a = msg.get("action")
            if a == "start":
                state["stop"] = True
                if task and not task.done():
                    task.cancel()
                if task:
                    try:
                        await task
                    except (asyncio.CancelledError, Exception):
                        pass
                state["stop"] = False
                noise = msg.get("noise") if msg.get("noise") in LEVELS else "clean"
                fresh = bool(msg.get("fresh"))
                try:
                    if msg.get("audio_b64"):
                        pcm = base64.b64decode(msg["audio_b64"])
                        if len(pcm) > MAX_AUDIO_SECONDS * 16000 * 2:
                            raise ValueError(f"audio is longer than {MAX_AUDIO_SECONDS} seconds")
                        task = asyncio.create_task(run_audio(pcm, fresh))
                    else:
                        turns = parse_script((msg.get("text") or "")[:20000])
                        if not turns:
                            raise ValueError("there is no text to analyse")
                        mode = "voice" if msg.get("mode") == "voice" else "quick"
                        task = asyncio.create_task(run_text(turns, mode, noise, fresh))
                except Exception as e:
                    await sock.send_json({"type": "notice", "text": f"Could not start: {e}"})
                    await sock.send_json({"type": "end", "final": None, "verdict": None})
            elif a == "test_alert":
                asyncio.create_task(send_test_alert())
            elif a == "end":
                state["stop"] = True
    except WebSocketDisconnect:
        state["stop"] = True