"""Local OCR (EasyOCR) -- a fast, deterministic, no-network text extraction
path for packages/ingestion/image, tried before the gateway vision LLM call.

Phase 4's original choice ("gateway vision, no new dependency") was made
before this codebase carried torch at all; Phase 10 (packages/ml/text/semantic.py)
already pulls in the CPU-only torch wheel, so EasyOCR is no longer a new
dependency category -- it reuses that same wheel. The gateway vision LLM
(Gemini) stays as the fallback: it reads context/layout an OCR pass alone
misses ("this is a bank SMS", sender identity inferred from formatting), but
it is slow (5-15s, thinking-model latency) and depends on external API
availability. Local OCR is neither -- it runs in well under a second once
warm, entirely offline, and doesn't care whether any LLM provider is up.

Same lazy-singleton, "absent, not a stub" contract as packages/ml/text/semantic.py:
the `easyocr` package and its detection/recognition model weights (~64MB,
downloaded from EasyOCR's own CDN on first use) are both optional. Callers
get `None`, never an exception, when either isn't available.
"""

from __future__ import annotations

import io
import logging
import re
import threading

logger = logging.getLogger("uvicorn")

# EasyOCR frequently misreads a hyperlink's "://" as " Il" (colon + two
# slashes rendered as two vertical strokes) and its "."s as bare spaces --
# packages/domain/entities/intelligence_extractor.py's URL regex then never
# matches at all, so a screenshot with an obvious phishing link silently
# contributes zero URL signal. Repair the scheme, then treat remaining
# spaces on that line as the domain dots they almost always are -- a
# transcribed link is reliably alone on its own line, and URLs never
# contain real spaces (only OCR noise does).
_OCR_URL_SCHEME = re.compile(r"(?i)\bhttps?\s*[Il|]{1,2}\s*")


def _repair_ocr_urls(text: str) -> str:
    def fix_scheme(match: re.Match) -> str:
        return "https://" if match.group(0).lower().startswith("https") else "http://"

    lines = []
    for line in text.split("\n"):
        fixed = _OCR_URL_SCHEME.sub(fix_scheme, line)
        if "://" in fixed:
            start = fixed.index("://")
            head, tail = fixed[: start + 3], fixed[start + 3 :]
            fixed = head + tail.replace(" ", ".")
        lines.append(fixed)
    return "\n".join(lines)

_reader = None
_reader_load_attempted = False
_reader_lock = threading.Lock()


def _load_reader():
    global _reader, _reader_load_attempted
    with _reader_lock:
        if _reader_load_attempted:
            return _reader
        try:
            import easyocr
        except Exception as exc:  # noqa: BLE001 -- torch/torchvision ABI mismatches raise RuntimeError, not ImportError
            logger.warning(f"EasyOCR unavailable: {exc}")
            _reader_load_attempted = True  # package/build genuinely broken -- retrying won't help
            return None
        try:
            _reader = easyocr.Reader(["en"], gpu=False, verbose=False)
            _reader_load_attempted = True
        except Exception as exc:  # noqa: BLE001 -- model download/load can fail many transient ways
            # Not latched: a download hiccup or startup-warmup/first-request race on
            # the model cache dir shouldn't disable OCR for the rest of the process's
            # life. Left False so the next call retries.
            logger.warning(f"EasyOCR reader failed to load, will retry next call: {exc}")
            _reader = None
        return _reader


def available() -> bool:
    return _load_reader() is not None


def _extract_sync(data: bytes) -> str | None:
    reader = _load_reader()
    if reader is None:
        return None
    try:
        from PIL import Image
        import numpy as np

        image = Image.open(io.BytesIO(data)).convert("RGB")
        results = reader.readtext(np.array(image), detail=0, paragraph=True)
    except Exception as exc:  # noqa: BLE001 -- a corrupt/unreadable image degrades, not crashes
        logger.warning(f"EasyOCR extraction failed: {exc}")
        return None
    text = "\n".join(line.strip() for line in results if line.strip())
    text = _repair_ocr_urls(text)
    return text or None


async def extract_text(data: bytes) -> str | None:
    """CPU-bound (no network) -- run off the event loop, same reason
    packages/ml/text/__init__.py wraps every HF pipeline call in
    asyncio.to_thread."""
    import asyncio

    return await asyncio.to_thread(_extract_sync, data)
