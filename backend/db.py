from __future__ import annotations

import os
import secrets
import string
import uuid
import requests
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
import json
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

        await con.execute(
            """
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS requested_at TIMESTAMPTZ;
            ALTER TABLE users
            ALTER COLUMN requested_at SET DEFAULT now();
            UPDATE users SET requested_at = now() WHERE requested_at IS NULL;
            ALTER TABLE users
            ALTER COLUMN requested_at SET NOT NULL;
            """
        )

        await con.execute(
            """
            -- If your id is UUID type, set a default UUID generator when possible
            -- This may fail if extension isn't available, but that's okay.
            DO $$
            BEGIN
            BEGIN
                CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
            EXCEPTION WHEN OTHERS THEN
                -- ignore
            END;

            BEGIN
                ALTER TABLE cases ALTER COLUMN id SET DEFAULT uuid_generate_v4();
            EXCEPTION WHEN OTHERS THEN
                -- ignore
            END;
            END $$;
            """
        )


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def generate_temp_password(length: int = 12) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def try_send_email(to_email: str, subject: str, body: str) -> tuple[bool, str | None]:
    """
    Returns (sent, error). Never raises.
    """
    host = os.getenv("SMTP_HOST", "").strip()
    user = os.getenv("SMTP_USER", "").strip()
    passwd = os.getenv("SMTP_PASS", "").strip().replace(" ", "")  # IMPORTANT: remove spaces
    from_addr = os.getenv("SMTP_FROM", "TruthStamp <no-reply@truthstamp.local>").strip()
    port = int(os.getenv("SMTP_PORT", "587"))

    if not host or not user or not passwd:
        return False, "SMTP is not configured (missing SMTP_HOST/SMTP_USER/SMTP_PASS)"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_email
    msg.set_content(body)

    try:
        with smtplib.SMTP(host, port, timeout=20) as server:
            server.ehlo()
            # Gmail on 587 uses STARTTLS
            server.starttls()
            server.ehlo()
            server.login(user, passwd)
            server.send_message(msg)
        return True, None
    except Exception as e:
        # LOG the actual error so you can see it in Render logs
        import traceback
        print("SMTP ERROR:", repr(e))
        print(traceback.format_exc())

    except Exception as e:
        import traceback
        print("SMTP ERROR:", repr(e))
        print(traceback.format_exc())

        # Fallback to Resend (HTTPS) when SMTP is blocked
        sent2, err2 = try_send_email_resend(to_email, subject, body)
        if sent2:
            return True, None
        return False, f"SMTP failed: {e}; Resend failed: {err2}"
    
def try_send_email_http(to_email: str, subject: str, body: str) -> tuple[bool, str | None]:
    api_key = os.getenv("RESEND_API_KEY", "").strip()
    from_addr = os.getenv("SMTP_FROM", "TruthStamp <onboarding@resend.dev>").strip()

    if not api_key:
        return False, "Missing RESEND_API_KEY"

    try:
        r = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "from": from_addr,
                "to": [to_email],
                "subject": subject,
                "text": body,
            },
            timeout=20,
        )
        if r.status_code >= 400:
            return False, f"Resend error {r.status_code}: {r.text}"
        return True, None
    except Exception as e:
        return False, str(e)

def try_send_email_resend(to_email: str, subject: str, body: str) -> tuple[bool, str | None]:
    api_key = os.getenv("RESEND_API_KEY", "").strip()
    from_addr = os.getenv("SMTP_FROM", "TruthStamp <onboarding@resend.dev>").strip()

    if not api_key:
        return False, "Missing RESEND_API_KEY"

    try:
        r = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "from": from_addr,
                "to": [to_email],
                "subject": subject,
                "text": body,
            },
            timeout=20,
        )
        if r.status_code >= 400:
            return False, f"Resend error {r.status_code}: {r.text}"
        return True, None
    except Exception as e:
        return False, str(e)
    
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

async def get_user_by_id(pool: asyncpg.Pool, user_id: str) -> Optional[Dict[str, Any]]:
    async with pool.acquire() as con:
        row = await con.fetchrow("SELECT * FROM users WHERE id=$1", user_id)
    return dict(row) if row else None


async def create_user_request(
    pool: asyncpg.Pool,
    *,
    name: str,
    email: str,
    phone: str | None,
    occupation: str | None,
    company: str | None,
    extras: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    email_l = email.lower().strip()

    # placeholder password (never shown to user)
    placeholder = generate_temp_password()
    phash = hash_password(placeholder)

    extras = extras or {}
    user_id = uuid.uuid4()
    requested_at = datetime.now(timezone.utc)

    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO users (
                id, name, email, phone, occupation, company, extras,
                password_hash, is_active, is_approved, must_change_password,
                requested_at
            )
            VALUES (
                $1,$2,$3,$4,$5,$6,$7::jsonb,
                $8, TRUE, FALSE, TRUE,
                $9
            )
            RETURNING *
            """,
            user_id,
            name.strip() if name else None,
            email_l,
            phone,
            occupation,
            company,
            json.dumps(extras),
            phash,
            requested_at,
        )
    return dict(row)


async def set_user_password(pool: asyncpg.Pool, user_id: str, new_password: str) -> None:
    new_hash = hash_password(new_password)
    async with pool.acquire() as con:
        await con.execute(
            """
            UPDATE users
            SET password_hash=$2,
                must_change_password=FALSE
            WHERE id=$1
            """,
            user_id,
            new_hash,
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

async def create_case(
    pool: asyncpg.Pool,
    *,
    user_id: str,
    title: str,
    description: Optional[str] = None,
) -> Dict[str, Any]:
    case_id = uuid.uuid4()
    created_at = datetime.now(timezone.utc)

    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO cases (id, user_id, title, description, status, created_at)
            VALUES ($1, $2, $3, $4, 'open', $5)
            RETURNING id, user_id, title, description, status, created_at
            """,
            case_id,
            user_id,
            title,
            description,
            created_at,
        )
    return dict(row)


async def get_case(
    pool: asyncpg.Pool,
    *,
    case_id: str,
    user_id: str,
) -> Optional[Dict[str, Any]]:
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            SELECT id, user_id, title, description, status, created_at
            FROM cases
            WHERE id = $1 AND user_id = $2
            """,
            case_id,
            user_id,
        )
    return dict(row) if row else None
