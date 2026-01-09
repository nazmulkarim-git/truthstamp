from __future__ import annotations

import os
import secrets
import string
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

import asyncpg
from passlib.context import CryptContext
import smtplib
from email.message import EmailMessage


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


async def create_pool() -> asyncpg.Pool:
    dsn = os.getenv("DATABASE_URL", "")
    if not dsn:
        raise RuntimeError("DATABASE_URL is not set")
    return await asyncpg.create_pool(dsn, min_size=1, max_size=5)


async def init_db(pool: asyncpg.Pool) -> None:
    # Creates tables if missing (id UUID is important for admin actions)
    async with pool.acquire() as con:
        await con.execute(
            """
            CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
            """
        )

        await con.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
              id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
              name TEXT,
              email TEXT UNIQUE NOT NULL,
              phone TEXT,
              occupation TEXT,
              company TEXT,
              extras JSONB DEFAULT '{}'::jsonb,
              password_hash TEXT NOT NULL,
              is_active BOOLEAN NOT NULL DEFAULT TRUE,
              is_approved BOOLEAN NOT NULL DEFAULT FALSE,
              must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
              requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
              approved_at TIMESTAMPTZ
            );
            """
        )

        await con.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
              id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
              user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              title TEXT,
              description TEXT,
              status TEXT DEFAULT 'open',
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
            """
        )

        await con.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
              id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
              case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
              filename TEXT,
              sha256 TEXT,
              media_type TEXT,
              bytes BIGINT,
              provenance_state TEXT,
              summary TEXT,
              analysis_json JSONB DEFAULT '{}'::jsonb,
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
            """
        )

        await con.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
              id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
              case_id UUID REFERENCES cases(id) ON DELETE SET NULL,
              evidence_id UUID REFERENCES evidence(id) ON DELETE SET NULL,
              event_type TEXT,
              actor TEXT,
              ip TEXT,
              user_agent TEXT,
              details_json JSONB DEFAULT '{}'::jsonb,
              created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
            """
        )


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def generate_temp_password(length: int = 12) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


async def try_send_email(to_email: str, subject: str, body: str) -> bool:
    """
    Returns True if email was sent, False if SMTP is not configured.
    """
    host = os.getenv("SMTP_HOST", "").strip()
    user = os.getenv("SMTP_USER", "").strip()
    passwd = os.getenv("SMTP_PASS", "").strip()
    from_addr = os.getenv("SMTP_FROM", "TruthStamp <no-reply@truthstamp.local>").strip()
    port = int(os.getenv("SMTP_PORT", "587"))

    if not host or not user or not passwd:
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_email
    msg.set_content(body)

    try:
        with smtplib.SMTP(host, port) as server:
            server.starttls()
            server.login(user, passwd)
            server.send_message(msg)
        return True
    except Exception:
        # don’t crash the API because SMTP failed
        return False


# -----------------------
# Users
# -----------------------

async def get_user_by_email(pool: asyncpg.Pool, email: str) -> Optional[Dict[str, Any]]:
    async with pool.acquire() as con:
        row = await con.fetchrow("SELECT * FROM users WHERE email=$1", email.lower())
    return dict(row) if row else None


async def list_pending_users(pool: asyncpg.Pool, limit: int = 200) -> List[Dict[str, Any]]:
    async with pool.acquire() as con:
        rows = await con.fetch(
            """
            SELECT id, name, email, phone, occupation, company, extras,
                   is_active, is_approved, must_change_password,
                   requested_at, approved_at
            FROM users
            WHERE is_approved=false
            ORDER BY requested_at DESC
            LIMIT $1
            """,
            limit,
        )
    return [dict(r) for r in rows]


async def list_users(pool: asyncpg.Pool, status: str = "all", limit: int = 200) -> List[Dict[str, Any]]:
    where = ""
    if status == "approved":
        where = "WHERE is_approved=true"
    elif status == "pending":
        where = "WHERE is_approved=false"
    elif status == "active":
        where = "WHERE is_active=true"
    elif status == "inactive":
        where = "WHERE is_active=false"

    q = f"""
        SELECT id, name, email, phone, occupation, company, extras,
               is_active, is_approved, must_change_password,
               requested_at, approved_at
        FROM users
        {where}
        ORDER BY requested_at DESC
        LIMIT $1
    """

    async with pool.acquire() as con:
        rows = await con.fetch(q, limit)
    return [dict(r) for r in rows]


async def set_user_active(pool: asyncpg.Pool, user_id: str, is_active: bool) -> None:
    async with pool.acquire() as con:
        await con.execute("UPDATE users SET is_active=$2 WHERE id=$1", user_id, is_active)


async def set_user_approved(pool: asyncpg.Pool, user_id: str, approved: bool) -> None:
    async with pool.acquire() as con:
        await con.execute(
            """
            UPDATE users
            SET is_approved=$2,
                approved_at=CASE WHEN $2=true THEN now() ELSE NULL END
            WHERE id=$1
            """,
            user_id,
            approved,
        )


async def set_user_temp_password(pool: asyncpg.Pool, user_id: str, temp_password: str) -> None:
    ph = hash_password(temp_password)
    async with pool.acquire() as con:
        await con.execute(
            """
            UPDATE users
            SET password_hash=$2,
                must_change_password=true
            WHERE id=$1
            """,
            user_id,
            ph,
        )


# -----------------------
# Overview counts
# -----------------------

async def counts_overview(pool: asyncpg.Pool) -> Dict[str, int]:
    async with pool.acquire() as con:
        users_total = await con.fetchval("SELECT COUNT(*) FROM users")
        users_pending = await con.fetchval("SELECT COUNT(*) FROM users WHERE is_approved=false")
        users_approved = await con.fetchval("SELECT COUNT(*) FROM users WHERE is_approved=true")
        cases_total = await con.fetchval("SELECT COUNT(*) FROM cases")
        evidence_total = await con.fetchval("SELECT COUNT(*) FROM evidence")
        events_total = await con.fetchval("SELECT COUNT(*) FROM events")

    return {
        "users_total": int(users_total or 0),
        "users_pending": int(users_pending or 0),
        "users_approved": int(users_approved or 0),
        "cases_total": int(cases_total or 0),
        "evidence_total": int(evidence_total or 0),
        "events_total": int(events_total or 0),
    }


# -----------------------
# Cases (admin listing)
# -----------------------

async def list_cases(pool: asyncpg.Pool, user_id: Optional[str], limit: int = 200) -> List[Dict[str, Any]]:
    async with pool.acquire() as con:
        if user_id:
            rows = await con.fetch(
                """
                SELECT id, user_id, title, description, status, created_at
                FROM cases
                WHERE user_id=$1
                ORDER BY created_at DESC
                LIMIT $2
                """,
                user_id,
                limit,
            )
        else:
            rows = await con.fetch(
                """
                SELECT id, user_id, title, description, status, created_at
                FROM cases
                ORDER BY created_at DESC
                LIMIT $1
                """,
                limit,
            )
    return [dict(r) for r in rows]
