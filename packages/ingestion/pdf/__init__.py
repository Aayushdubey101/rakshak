"""PDF text extraction.

A PDF from a stranger is hostile input: it can be enormous, have thousands of
pages, or be encrypted. Each of those is a typed rejection, so the investigation
continues with whatever else it has.
"""

from __future__ import annotations

import logging

from packages.ingestion.limits import DEFAULT_LIMITS, IngestionLimits
from packages.shared.schemas.content import (
    IngestionRejection,
    MediaSummary,
    RejectionReason,
)
from packages.shared.schemas.investigation import ContentType

logger = logging.getLogger("uvicorn")


def extract_pdf_text(
    data: bytes, *, uri: str, limits: IngestionLimits = DEFAULT_LIMITS
) -> MediaSummary | IngestionRejection:
    if len(data) > limits.max_media_bytes:
        return IngestionRejection(
            source=uri,
            reason=RejectionReason.TOO_LARGE,
            detail=f"{len(data)} bytes exceeds {limits.max_media_bytes}",
        )
    if not data.startswith(b"%PDF-"):
        return IngestionRejection(
            source=uri, reason=RejectionReason.UNSUPPORTED_MEDIA, detail="not a PDF"
        )

    try:
        import io

        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(data))

        if reader.is_encrypted:
            return IngestionRejection(
                source=uri, reason=RejectionReason.ENCRYPTED, detail="encrypted PDF"
            )

        page_count = len(reader.pages)
        if page_count > limits.max_pdf_pages:
            return IngestionRejection(
                source=uri,
                reason=RejectionReason.TOO_MANY_PAGES,
                detail=f"{page_count} pages exceeds {limits.max_pdf_pages}",
            )

        pages = [page.extract_text() or "" for page in reader.pages]
    except Exception as exc:  # malformed files are common; never propagate
        logger.warning(f"⚠️ PDF extraction failed for {uri}: {exc}")
        return IngestionRejection(
            source=uri, reason=RejectionReason.EXTRACTION_FAILED, detail=str(exc)[:200]
        )

    return MediaSummary(
        uri=uri,
        kind=ContentType.PDF,
        mime_type="application/pdf",
        size_bytes=len(data),
        pages=page_count,
        extracted_text="\n".join(pages).strip()[: limits.max_text_chars],
        extractor="pypdf",
    )
