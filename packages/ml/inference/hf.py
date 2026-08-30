"""
Central Hugging Face Model Loader

- Loads all ML/NLP models ONCE at import time
- Exposes safe helper functions
- Never crashes the app if models fail
- Supports LITE MODE (skips loading entirely)
"""

from loguru import logger
from packages.shared.config.settings import get_settings

# ==============================
# GLOBAL STATE & PIPELINES
# ==============================
MODELS_AVAILABLE = False

spam_classifier = None
scam_type_classifier = None
ner_extractor = None
sentiment_analyzer = None
language_detector = None

settings = get_settings()

def load_models():
    """Dynamically load Hugging Face models into memory."""
    global MODELS_AVAILABLE, spam_classifier, scam_type_classifier, ner_extractor, sentiment_analyzer, language_detector
    
    if MODELS_AVAILABLE:
        logger.info("Models already loaded.")
        return

    logger.info("Loading Hugging Face models (Full Mode)...")
    
    try:
        # Lazy import to avoid memory usage in Lite Mode
        from transformers import pipeline
        
        # 1️⃣ Spam / Scam Detection (SMS-focused)
        try:
            spam_classifier = pipeline(
                task="text-classification",
                model="mrm8488/bert-tiny-finetuned-sms-spam-detection"
            )
        except Exception as e:
            logger.warning(f"Failed to load spam_classifier: {e}")

        # 2️⃣ Scam Type Classification (Zero-Shot)
        try:
            scam_type_classifier = pipeline(
                task="zero-shot-classification",
                model="microsoft/deberta-v3-small"
            )
        except Exception as e:
            logger.warning(f"Failed to load scam_type_classifier: {e}")

        # 3️⃣ Named Entity Recognition (NER)
        try:
            ner_extractor = pipeline(
                task="ner",
                model="dslim/bert-base-NER",
                aggregation_strategy="simple"
            )
        except Exception as e:
             logger.warning(f"Failed to load ner_extractor: {e}")

        # 4️⃣ Sentiment Analysis
        try:
            sentiment_analyzer = pipeline(
                task="sentiment-analysis",
                model="cardiffnlp/twitter-roberta-base-sentiment"
            )
        except Exception as e:
            logger.warning(f"Failed to load sentiment_analyzer: {e}")

        # 5️⃣ Language Detection
        try:
            language_detector = pipeline(
                task="text-classification",
                model="papluca/xlm-roberta-base-language-detection"
            )
        except Exception as e:
             logger.warning(f"Failed to load language_detector: {e}")

        # Check if at least critical models are loaded
        if spam_classifier or ner_extractor:
            MODELS_AVAILABLE = True
            logger.success("Critical Hugging Face models loaded successfully!")
        else:
            logger.error("No critical models could be loaded.")
            MODELS_AVAILABLE = False

    except ImportError:
         logger.error("Transformers library not installed or failed to import. Running in degraded mode.")
         MODELS_AVAILABLE = False
    except Exception as e:
        logger.error(f"Critical failure loading Hugging Face models: {e}")
        MODELS_AVAILABLE = False
        # ❗ DO NOT raise — app must still run

def unload_models():
    """Dynamically unload Hugging Face models to free memory."""
    global MODELS_AVAILABLE, spam_classifier, scam_type_classifier, ner_extractor, sentiment_analyzer, language_detector
    import gc
    
    logger.info("Unloading Hugging Face models to free memory...")
    MODELS_AVAILABLE = False
    spam_classifier = None
    scam_type_classifier = None
    ner_extractor = None
    sentiment_analyzer = None
    language_detector = None
    gc.collect()

if settings.DEPLOYMENT_MODE == "lite" or settings.HF_LITE_MODE:
    logger.warning("⚡ LITE MODE ACTIVE: Hugging Face models are DISABLED. Using fallback logic only.")
    MODELS_AVAILABLE = False
else:
    load_models()

# ==============================
# HELPER FUNCTIONS (SAFE)
# ==============================
def detect_spam(text: str) -> dict:
    """
    Detect spam/scam text.
    Returns: {label: 'spam' | 'ham', score: float}
    """
    if not MODELS_AVAILABLE or not spam_classifier:
        return {"label": "unknown", "score": 0.0}

    try:
        result = spam_classifier(text)[0]

        # FIX: Map HF labels to explicit meaning
        # LABEL_0 → ham
        # LABEL_1 → spam
        raw_label = result["label"].upper()

        # mrm8488/bert-tiny-finetuned-sms-spam-detection usually uses SMS_0 (ham) and SMS_1 (spam) or LABEL_0/1
        final_label = "spam" if "LABEL_1" in raw_label or "SMS_1" in raw_label or "SPAM" in raw_label else "ham"

        return {
            "label": final_label,
            "score": float(result["score"])
        }

    except Exception as e:
        logger.error(f"ML inference failed (detect_spam): {e}")
        return {"label": "error", "score": 0.0}


def classify_scam_type(text: str, labels: list) -> dict:
    """
    Zero-shot classification for scam types.
    """
    if not MODELS_AVAILABLE or not scam_type_classifier:
        current_labels = labels if labels else ["unknown"]
        return {
            "labels": current_labels,
            "scores": [0.0] * len(current_labels),
            "top_label": "unknown",
            "top_score": 0.0
        }

    try:
        result = scam_type_classifier(text, candidate_labels=labels)
        return {
            "labels": result["labels"],
            "scores": [float(s) for s in result["scores"]],
            "top_label": result["labels"][0],
            "top_score": float(result["scores"][0])
        }

    except Exception as e:
        logger.error(f"ML inference failed (classify_scam_type): {e}")
        return {
            "labels": [],
            "scores": [],
            "top_label": "error",
            "top_score": 0.0
        }


def extract_entities(text: str) -> list:
    """
    Transformer-based NER extraction.
    """
    if not MODELS_AVAILABLE or not ner_extractor:
        return []

    try:
        entities = ner_extractor(text)
        return [
            {
                "text": ent["word"],
                "label": ent["entity_group"],
                "confidence": float(ent["score"])
            }
            for ent in entities
        ]

    except Exception as e:
        logger.error(f"ML inference failed (extract_entities): {e}")
        return []


def analyze_sentiment(text: str) -> dict:
    """
    Sentiment analysis.
    """
    if not MODELS_AVAILABLE or not sentiment_analyzer:
        return {"label": "neutral", "score": 0.0}

    try:
        result = sentiment_analyzer(text)[0]
        return {
            "label": result["label"].lower(),
            "score": float(result["score"])
        }

    except Exception as e:
        logger.error(f"ML inference failed (analyze_sentiment): {e}")
        return {"label": "error", "score": 0.0}


def detect_language(text: str) -> dict:
    """
    Language detection.
    """
    if not MODELS_AVAILABLE or not language_detector:
        return {"language": "en", "confidence": 0.0}

    try:
        result = language_detector(text)[0]
        return {
            "language": result["label"],
            "confidence": float(result["score"])
        }

    except Exception as e:
        logger.error(f"ML inference failed (detect_language): {e}")
        return {"language": "error", "confidence": 0.0}
