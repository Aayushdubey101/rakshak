"""Honeypot isolation — phase 11.

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-09
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "investigations",
        sa.Column("data_origin", sa.String(16), nullable=False, server_default="consumer"),
    )
    op.create_index("ix_investigations_data_origin", "investigations", ["data_origin"])


def downgrade() -> None:
    op.drop_index("ix_investigations_data_origin", table_name="investigations")
    op.drop_column("investigations", "data_origin")
