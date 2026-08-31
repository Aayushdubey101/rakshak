"""Risk signals — the common currency between detection layers.

Patterns, each ML model, and threat intelligence all emit `RiskSignal`. Risk
fusion (phase 8) consumes nothing else, which is what keeps ML and the LLM
independent layers rather than one pipeline that happens to call a model.
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class SignalSource(str, Enum):
    PATTERN = "pattern"
    ML_TEXT = "ml.text"
    ML_VISION = "ml.vision"
    ML_URL = "ml.url"
    THREAT_INTEL = "threat_intel"
    LLM = "llm"


class RiskSignal(BaseModel):
    """One layer's opinion, with the evidence needed to reproduce it.

    `weight` is the fusion weight this signal type carries; it lives on the
    signal so a stored investigation can be re-fused later and produce the same
    number it produced at the time.
    """

    model_config = ConfigDict(frozen=True)

    source: SignalSource
    score: float = Field(ge=0.0, le=1.0, description="Risk contribution, 0 = benign")
    label: str = Field(min_length=1, description="What was detected, e.g. 'phishing'")
    confidence: float = Field(ge=0.0, le=1.0)
    model_id: str | None = Field(default=None, description="Model or ruleset identifier")
    weight: float = Field(default=1.0, ge=0.0)
