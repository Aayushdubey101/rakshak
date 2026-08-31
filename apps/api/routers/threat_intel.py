"""Live external threat-intel feed for the Intel page's read-only "what's
circulating right now" section. See packages/threat_intel/feed for the
source and its fail-soft/cached contract.
"""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends

from apps.api.dependencies import require_scope
from packages.shared.security.api_keys import SCOPE_READ_THREAT_INTEL
from packages.threat_intel.feed import recent

router = APIRouter(prefix="/api/v1/threat-intel", tags=["threat-intel"])


@router.get("/feed")
async def feed(_=Depends(require_scope(SCOPE_READ_THREAT_INTEL))) -> dict:
    entries = await recent(limit=20)
    return {"entries": [asdict(entry) for entry in entries]}
