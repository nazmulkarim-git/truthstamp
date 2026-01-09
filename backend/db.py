import asyncpg
import datetime as dt
import hashlib
import json
import os
import secrets
import uuid
from typing import Any, Optional

# -----------------------------------------------------------------------------
# Helpers / config
# -----------------------------------------------------------------------------

def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)

def _is_email(s: str) -> bool:
    return "@" in s

def _to_uuid(val: Any) -> uuid.UUID:
    if isinstance(val, uuid.UUID):
        return val
    if hasattr(val, "hex") and hasattr(val, "int"):
        # asyncpg UUID type behaves very close to uuid.UUID
        return uuid.UUID(str(val))
    return uuid.UUID(str(val))

def hash_password(pw: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + pw).encode("utf-8")).hexdigest()
    return f"{salt}${h}"

def verify_password(pw: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$", 1)
    except ValueError:
        return False
    return hashlib.sha256((salt + pw).encode("utf-8")).hexdigest() == h


# -----------------------------------------------------------------------------
# Pool / DB init
# -----------------------------------------------------------------------------

async def create_pool(dsn: str | None = None) -> asyncpg.Pool:
    """
    Create and return an asyncpg Pool.

    Render provides DATABASE_URL automatically (Postgres connection string).
    """
    dsn = dsn or os.getenv("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL is not set")
    # Keep small pool for Render free tier
    return await asyncpg.create_pool(dsn=dsn, min_size=1, max_size=5, command_timeout=60)


async def init_db(pool: asyncpg.Pool) -> None:
    """
    Creates tables if they don't exist.
    IMPORTANT: This schema matches what you said you see in pgAdmin:
      - users(requested_at, approved_at, etc.)
      - cases(created_at)
      - evidence(created_at, analysis_json)
      - events(details_json, created_at)
    """
    async with pool.acquire() as con:
        await con.execute('CREATE EXTENSION IF NOT EXISTS pgcrypto;')
        await con.execute(
            """
            CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
            """
        )

        await con.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
              id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
              name text NOT NULL,
              email text UNIQUE NOT NULL,
              phone text,
              occupation text,
              company text,
              extras jsonb DEFAULT '{}'::jsonb,
              password_hash text NOT NULL,
              is_active boolean DEFAULT false,
              is_approved boolean DEFAULT false,
              must_change_password boolean DEFAULT true,
              requested_at timestamptz DEFAULT now(),
              approved_at timestamptz
            );
            """
        )

        await con.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
              id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
              user_id uuid REFERENCES users(id) ON DELETE CASCADE,
              title text NOT NULL,
              description text,
              status text DEFAULT 'open',
              created_at timestamptz DEFAULT now()
            );
            """
        )

        await con.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
              id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
              case_id uuid REFERENCES cases(id) ON DELETE CASCADE,
              filename text NOT NULL,
              sha256 text NOT NULL,
              media_type text,
              bytes bigint,
              provenance_state text,
              summary text,
              analysis_json jsonb DEFAULT '{}'::jsonb,
              created_at timestamptz DEFAULT now()
            );
            """
        )

        await con.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
              id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
              case_id uuid REFERENCES cases(id) ON DELETE CASCADE,
              evidence_id uuid REFERENCES evidence(id) ON DELETE SET NULL,
              event_type text NOT NULL,
              actor text,
              ip text,
              user_agent text,
              details_json jsonb DEFAULT '{}'::jsonb,
              created_at timestamptz DEFAULT now()
            );
            """
        )


# -----------------------------------------------------------------------------
# Users
# -----------------------------------------------------------------------------

<<<<<<< HEAD
async def create_user_request(
=======
        # ---- Migrations for older schemas (safe no-ops if columns already exist)
        await con.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS id UUID;")
        await con.execute("UPDATE users SET id = gen_random_uuid() WHERE id IS NULL;")
        await con.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS requested_at TIMESTAMPTZ DEFAULT NOW();")
        await con.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;")
        await con.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE;")
        await con.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_approved BOOLEAN DEFAULT FALSE;")
        await con.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN DEFAULT FALSE;")
        await con.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS extras JSONB DEFAULT '{}'::jsonb;")

        # Add primary key on users(id) if missing
        await con.execute(
            """DO $$ BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'users'::regclass AND contype = 'p'
                ) THEN
                    ALTER TABLE users ADD CONSTRAINT users_pkey PRIMARY KEY (id);
                END IF;
            EXCEPTION WHEN others THEN
                -- ignore (e.g., lacks privileges or already has PK)
            END $$;"""
        )

        await con.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS details_json JSONB DEFAULT '{}'::jsonb;")
        await con.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();")
        await con.execute("ALTER TABLE cases ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();")
        await con.execute("ALTER TABLE evidence ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();")


async def create_access_request(
>>>>>>> 30d16ff (Temp pass)
    pool: asyncpg.Pool,
    *,
    name: str,
    email: str,
    phone: str | None,
    occupation: str | None,
    company: str | None,
    extras: dict | None,
    password_hash: str,
) -> dict:
    email_n = email.strip().lower()
    extras = extras or {}
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO users (name, email, phone, occupation, company, extras, password_hash,
                               is_active, is_approved, must_change_password, requested_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,false,false,true,now())
            ON CONFLICT (email) DO UPDATE SET
              name=EXCLUDED.name,
              phone=EXCLUDED.phone,
              occupation=EXCLUDED.occupation,
              company=EXCLUDED.company,
              extras=EXCLUDED.extras
            RETURNING id, name, email, phone, occupation, company, extras, is_active, is_approved, must_change_password, requested_at, approved_at
            """,
            name,
            email_n,
            phone,
            occupation,
            company,
            json.dumps(extras),
            password_hash,
        )
    return dict(row)

async def get_user_by_email(pool: asyncpg.Pool, email: str) -> Optional[dict]:
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "SELECT * FROM users WHERE email=$1",
            email.strip().lower(),
        )
    return dict(row) if row else None

async def list_users(pool: asyncpg.Pool, status: str = "all", limit: int = 200) -> list[dict]:
    status = (status or "all").lower()
    async with pool.acquire() as con:
        if status == "pending":
            rows = await con.fetch(
                """
                SELECT * FROM users
                WHERE is_approved=false
                ORDER BY requested_at DESC
                LIMIT $1
                """,
                limit,
            )
        elif status == "approved":
            rows = await con.fetch(
                """
                SELECT * FROM users
                WHERE is_approved=true
                ORDER BY approved_at DESC NULLS LAST, requested_at DESC
                LIMIT $1
                """,
                limit,
            )
        else:
            rows = await con.fetch(
                """
                SELECT * FROM users
                ORDER BY requested_at DESC
                LIMIT $1
                """,
                limit,
            )
    return [dict(r) for r in rows]

async def set_user_active(pool: asyncpg.Pool, user_id: Any, active: bool) -> None:
    uid = _to_uuid(user_id)
    async with pool.acquire() as con:
        await con.execute("UPDATE users SET is_active=$2 WHERE id=$1", uid, active)

async def set_user_approved(pool: asyncpg.Pool, user_id: Any, approved: bool) -> None:
    uid = _to_uuid(user_id)
    async with pool.acquire() as con:
        if approved:
            await con.execute(
                "UPDATE users SET is_approved=true, approved_at=now() WHERE id=$1",
                uid,
            )
        else:
            await con.execute(
                "UPDATE users SET is_approved=false, approved_at=NULL WHERE id=$1",
                uid,
            )

async def set_user_password(pool: asyncpg.Pool, user_id: Any, password_hash: str, must_change: bool) -> None:
    uid = _to_uuid(user_id)
    async with pool.acquire() as con:
        await con.execute(
            "UPDATE users SET password_hash=$2, must_change_password=$3 WHERE id=$1",
            uid,
            password_hash,
            must_change,
        )


# -----------------------------------------------------------------------------
# Cases
# -----------------------------------------------------------------------------

async def create_case(pool: asyncpg.Pool, user_id: Any, title: str, description: str | None) -> dict:
    uid = _to_uuid(user_id)
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO cases (user_id, title, description, status, created_at)
            VALUES ($1,$2,$3,'open',now())
            RETURNING *
            """,
            uid,
            title,
            description,
        )
    return dict(row)

async def list_cases(pool: asyncpg.Pool, user_id: Any | None, limit: int = 200) -> list[dict]:
    async with pool.acquire() as con:
        if user_id is None:
            rows = await con.fetch(
                """
                SELECT * FROM cases
                ORDER BY created_at DESC
                LIMIT $1
                """,
                limit,
            )
        else:
            uid = _to_uuid(user_id)
            rows = await con.fetch(
                """
                SELECT * FROM cases
                WHERE user_id=$1
                ORDER BY created_at DESC
                LIMIT $2
                """,
                uid,
                limit,
            )
    return [dict(r) for r in rows]


# -----------------------------------------------------------------------------
# Evidence
# -----------------------------------------------------------------------------

async def create_evidence(
    pool: asyncpg.Pool,
    *,
    case_id: Any,
    filename: str,
    sha256: str,
    media_type: str | None,
    bytes_len: int | None,
    provenance_state: str | None,
    summary: str | None,
    analysis_json: dict | None,
) -> dict:
    cid = _to_uuid(case_id)
    analysis_json = analysis_json or {}
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO evidence (
              case_id, filename, sha256, media_type, bytes, provenance_state, summary, analysis_json, created_at
            )
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
            RETURNING *
            """,
            cid,
            filename,
            sha256,
            media_type,
            bytes_len,
            provenance_state,
            summary,
            json.dumps(analysis_json),
        )
    return dict(row)

async def list_evidence(pool: asyncpg.Pool, case_id: Any, limit: int = 200) -> list[dict]:
    cid = _to_uuid(case_id)
    async with pool.acquire() as con:
        rows = await con.fetch(
            """
            SELECT * FROM evidence
            WHERE case_id=$1
            ORDER BY created_at DESC
            LIMIT $2
            """,
            cid,
            limit,
        )
    return [dict(r) for r in rows]


# -----------------------------------------------------------------------------
# Events (audit log)
# -----------------------------------------------------------------------------

async def add_event(
    pool: asyncpg.Pool,
    *,
    case_id: Any,
    evidence_id: Any | None,
    event_type: str,
    actor: str | None,
    ip: str | None,
    user_agent: str | None,
    details_json: dict | None,
) -> dict:
    cid = _to_uuid(case_id)
    eid = _to_uuid(evidence_id) if evidence_id else None
    details_json = details_json or {}
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO events (case_id, evidence_id, event_type, actor, ip, user_agent, details_json, created_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,now())
            RETURNING *
            """,
            cid,
            eid,
            event_type,
            actor,
            ip,
            user_agent,
            json.dumps(details_json),
        )
    return dict(row)

async def list_events(pool: asyncpg.Pool, case_id: Any | None, limit: int = 200) -> list[dict]:
    async with pool.acquire() as con:
        if case_id is None:
            rows = await con.fetch(
                """
                SELECT * FROM events
                ORDER BY created_at DESC
                LIMIT $1
                """,
                limit,
            )
        else:
            cid = _to_uuid(case_id)
            rows = await con.fetch(
                """
                SELECT * FROM events
                WHERE case_id=$1
                ORDER BY created_at DESC
                LIMIT $2
                """,
                cid,
                limit,
            )
    return [dict(r) for r in rows]
