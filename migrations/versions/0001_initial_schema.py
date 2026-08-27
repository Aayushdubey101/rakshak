"""Initial schema — phase 7.

Revision ID: 0001
Revises:
Create Date: 2026-08-09
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

try:
    from pgvector.sqlalchemy import Vector
except ImportError:  # pragma: no cover
    Vector = None

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def _embedding_column():
    if Vector is None:
        return sa.Column("embedding", sa.JSON(), nullable=True)
    return sa.Column("embedding", Vector(1536), nullable=True)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("external_id", sa.String(255), unique=True, nullable=True),
        sa.Column("email", sa.String(255), nullable=True),
        sa.Column("retention_class", sa.String(32), nullable=False, server_default="standard"),
        sa.Column("consent_state", sa.String(32), nullable=False, server_default="granted"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "platform_accounts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("platform", sa.String(32), nullable=False),
        sa.Column("platform_account_id", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_platform_account_lookup", "platform_accounts", ["platform", "platform_account_id"]
    )

    op.create_table(
        "scam_campaigns",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        _embedding_column(),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "investigations",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column(
            "platform_account_id", sa.String(36), sa.ForeignKey("platform_accounts.id"), nullable=True
        ),
        sa.Column("platform", sa.String(32), nullable=False),
        sa.Column("content_type", sa.String(32), nullable=False),
        sa.Column("verdict", sa.String(32), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("severity", sa.String(16), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("scam_type", sa.String(64), nullable=True),
        sa.Column("is_degraded", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("retention_class", sa.String(32), nullable=False, server_default="standard"),
        sa.Column("consent_state", sa.String(32), nullable=False, server_default="granted"),
        sa.Column("left_infrastructure", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("evidence_state", sa.String(16), nullable=False, server_default="ingested"),
        sa.Column("purge_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "messages",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(64), sa.ForeignKey("investigations.id"), nullable=False),
        sa.Column("sender", sa.String(32), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "attachments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(64), sa.ForeignKey("investigations.id"), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("object_key", sa.String(512), nullable=False),
        sa.Column("content_type", sa.String(128), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("extracted_text", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "entities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(64), sa.ForeignKey("investigations.id"), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("normalized_value", sa.String(512), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("source", sa.String(64), nullable=True),
    )

    op.create_table(
        "urls",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(64), sa.ForeignKey("investigations.id"), nullable=False),
        sa.Column("raw", sa.Text(), nullable=False),
        sa.Column("normalized", sa.Text(), nullable=True),
        sa.Column("blocked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("block_reason", sa.String(255), nullable=True),
    )

    op.create_table(
        "domains",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reputation_score", sa.Float(), nullable=True),
    )

    op.create_table(
        "risk_assessments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(64), sa.ForeignKey("investigations.id"), nullable=False),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("label", sa.String(64), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("model_id", sa.String(128), nullable=True),
        sa.Column("weight", sa.Float(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "scam_classifications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(64), sa.ForeignKey("investigations.id"), nullable=False),
        sa.Column("scam_type", sa.String(64), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("method", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "investigation_id",
            sa.String(64),
            sa.ForeignKey("investigations.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "threat_indicators",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("value_hash", sa.String(128), nullable=False),
        sa.Column("campaign_id", sa.String(36), sa.ForeignKey("scam_campaigns.id"), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index("ix_threat_indicator_lookup", "threat_indicators", ["kind", "value_hash"])

    op.create_table(
        "model_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("investigation_id", sa.String(64), sa.ForeignKey("investigations.id"), nullable=False),
        sa.Column("stage", sa.String(32), nullable=False),
        sa.Column("model_id", sa.String(128), nullable=True),
        sa.Column("version", sa.String(32), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target_id", sa.String(64), nullable=False),
        sa.Column("reason", sa.String(255), nullable=True),
        sa.Column("audit_metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("model_runs")
    op.drop_index("ix_threat_indicator_lookup", table_name="threat_indicators")
    op.drop_table("threat_indicators")
    op.drop_table("reports")
    op.drop_table("scam_classifications")
    op.drop_table("risk_assessments")
    op.drop_table("domains")
    op.drop_table("urls")
    op.drop_table("entities")
    op.drop_table("attachments")
    op.drop_table("messages")
    op.drop_table("investigations")
    op.drop_table("scam_campaigns")
    op.drop_index("ix_platform_account_lookup", table_name="platform_accounts")
    op.drop_table("platform_accounts")
    op.drop_table("users")
