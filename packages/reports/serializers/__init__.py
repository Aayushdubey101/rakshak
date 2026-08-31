"""Renders the one `CanonicalReport` an investigation produces, one way per
channel. None of these compute new evidence -- rule #3 ("every investigation
produces exactly one CanonicalReport; channels only render it differently").

`to_telegram`/`to_whatsapp` moved here verbatim from
`TelegramAdapter.format_report`/`WhatsAppAdapter.format_report` (task.md
phase 5's own comment: "Phase 12 moves this into the serializers wholesale")
so the formatting exists in one place instead of two. The adapters now
delegate to these functions instead of duplicating them.
"""

from __future__ import annotations

from packages.shared.schemas.report import CanonicalReport, Severity

TELEGRAM_MAX_CHARS = 4096
WHATSAPP_MAX_CHARS = 1600

# MarkdownV2 requires every one of these escaped, anywhere they appear.
_MARKDOWN_V2_SPECIALS = r"_*[]()~`>#+-=|{}.!"

_SEVERITY_LABEL = {
    Severity.CRITICAL: "🚨 Almost certainly a scam",
    Severity.HIGH: "⚠️ Very likely a scam",
    Severity.MEDIUM: "⚠️ Suspicious",
    Severity.LOW: "🔍 Mild signals",
    Severity.NONE: "✅ No scam signals found",
}

__all__ = ["escape_markdown_v2", "to_web", "to_telegram", "to_whatsapp"]


def escape_markdown_v2(text: str) -> str:
    return "".join(f"\\{ch}" if ch in _MARKDOWN_V2_SPECIALS else ch for ch in text)


def to_web(report: CanonicalReport) -> dict:
    """Full structured JSON -- web is the only channel with room for every
    field the report carries."""
    return report.model_dump(mode="json")


def to_telegram(report: CanonicalReport) -> str:
    """Concise MarkdownV2, capped at Telegram's message length."""
    lines = [
        f"*{escape_markdown_v2(_SEVERITY_LABEL[report.severity])}*",
        escape_markdown_v2(f"Risk: {report.risk_score}/100"),
    ]
    if report.scam_type and report.verdict.value == "scam":
        lines.append(escape_markdown_v2(f"Type: {report.scam_type.replace('_', ' ')}"))
    if report.red_flags:
        lines.append("")
        lines.extend(f"• {escape_markdown_v2(flag)}" for flag in report.red_flags[:5])
    if report.url_findings:
        lines.append("")
        lines.append(escape_markdown_v2(f"Links checked: {len(report.url_findings)}"))
    if report.is_degraded:
        lines.append("")
        lines.append(escape_markdown_v2("(partial analysis — some checks were unavailable)"))

    return "\n".join(lines)[:TELEGRAM_MAX_CHARS]


def to_whatsapp(report: CanonicalReport) -> str:
    """Plain text, capped at WhatsApp's 1600-character reply limit."""
    lines = [_SEVERITY_LABEL[report.severity], f"Risk: {report.risk_score}/100"]

    if report.scam_type and report.verdict.value == "scam":
        lines.append(f"Type: {report.scam_type.replace('_', ' ')}")
    if report.red_flags:
        lines.append("")
        lines.extend(f"- {flag}" for flag in report.red_flags[:5])
    if report.is_degraded:
        lines.append("")
        lines.append("(partial analysis - some checks were unavailable)")

    return "\n".join(lines)[:WHATSAPP_MAX_CHARS]
