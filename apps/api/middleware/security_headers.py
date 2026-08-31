"""Security response headers (task.md phase 14). This process never
terminates TLS itself (`rakshak_architecture.md`'s deployment diagram puts
CloudFront/WAF -> ALB in front of it, per phase 15) -- HSTS is only sent when
`X-Forwarded-Proto: https` shows the edge already terminated TLS for this
request, so a plain local `http://` dev run never gets a header telling
browsers to demand HTTPS on localhost.
"""

from __future__ import annotations

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        if request.headers.get("x-forwarded-proto", request.url.scheme) == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        content_type = response.headers.get("content-type", "")
        if content_type.startswith("text/html"):
            # /dashboard serves static/index.html, which loads Google Fonts --
            # style-src/font-src carve-outs for exactly those two hosts, not a
            # blanket allow. The JSON API responses don't get a CSP; nothing
            # there renders as a page.
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src https://fonts.gstatic.com"
            )
        return response
