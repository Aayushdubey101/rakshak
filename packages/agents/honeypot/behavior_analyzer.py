import logging

# 🔹 NEW: Hugging Face sentiment model
from packages.ml.inference.hf import analyze_sentiment

logger = logging.getLogger("uvicorn")


class ScammerBehaviorAnalyzer:
    @staticmethod
    def analyze_message(text: str, history: list) -> dict:
        """
        Analyzes the scammer's message for behavior traits
        using heuristics + sentiment analysis.
        """
        text_lower = text.lower()

        # =========================
        # 1️⃣ Aggression / Urgency (EXISTING)
        # =========================
        aggression_keywords = [
            "immediately", "now", "hurry", "stupid", "idiot",
            "fast", "waste", "police", "jail"
        ]
        aggression_score = sum(1 for w in aggression_keywords if w in text_lower)
        is_aggressive = aggression_score >= 1 or text.isupper()

        # =========================
        # 2️⃣ Patience / Frustration (EXISTING)
        # =========================
        frustration_keywords = ["???", "why", "hell", "taking long", "waiting"]
        is_frustrated = any(w in text_lower for w in frustration_keywords)

        # =========================
        # 3️⃣ Sophistication (EXISTING)
        # =========================
        word_count = len(text.split())
        is_sophisticated = word_count > 20 and aggression_score == 0

        # =========================
        # 🔹 4️⃣ Sentiment Analysis (NEW)
        # =========================
        sentiment = analyze_sentiment(text)
        sentiment_label = sentiment["label"]       # positive / neutral / negative
        sentiment_score = sentiment["score"]

        # =========================
        # FINAL BEHAVIOR PROFILE
        # =========================
        behavior_profile = {
            "aggression": "HIGH" if is_aggressive else "LOW",
            "patience": "LOW" if is_frustrated else "HIGH",
            "sophistication": "HIGH" if is_sophisticated else "LOW",
            # 🔹 NEW SIGNALS
            "sentiment": sentiment_label,
            "sentiment_score": sentiment_score
        }

        logger.debug(f"Behavior profile (with sentiment): {behavior_profile}")
        return behavior_profile

    @staticmethod
    def get_adaptation_guidance(profile: dict) -> str:
        """
        Returns instructions for the AI agent based on behavior + sentiment.
        """
        guidance = []

        # =========================
        # EXISTING RULES (UNCHANGED)
        # =========================
        if profile["aggression"] == "HIGH":
            guidance.append(
                "Scammer is AGGRESSIVE. Be apologetic, submissive, and scared. Do not fight back."
            )

        if profile["patience"] == "LOW":
            guidance.append(
                "Scammer is FRUSTRATED. Pretend to hurry but make clumsy mistakes. Assure them you are trying."
            )

        if profile["sophistication"] == "HIGH":
            guidance.append(
                "Scammer seems SOPHISTICATED. Act slightly more impressed by their professionalism."
            )

        # =========================
        # 🔹 NEW: SENTIMENT-BASED TUNING
        # =========================
        sentiment = profile.get("sentiment")

        if sentiment == "negative":
            guidance.append(
                "Tone detected as NEGATIVE. Respond calmly, avoid confrontation, and slow the interaction subtly."
            )

        elif sentiment == "positive":
            guidance.append(
                "Tone detected as POSITIVE. Show trust and curiosity, but do not complete any transaction."
            )

        elif sentiment == "neutral":
            guidance.append(
                "Tone detected as NEUTRAL. Ask innocent clarifying questions to extract more details."
            )

        if not guidance:
            guidance.append(
                "Scammer behavior is normal. Maintain standard persona."
            )

        return " ".join(guidance)
