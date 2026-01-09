"""
TruthStamp asyncpg data-access layer.

Goals:
- Work with Render Postgres (asyncpg) and a simple FastAPI backend.
- Be resilient to UUID types returned by asyncpg (asyncpg.pgproto.UUID).
- Keep schema aligned with what you see in pgAdmin:
    users(id uuid, name, email, phone, occupation, company, extras jsonb,
          password_hash, is_active, is_approved, must_change_password,
          requested_at timestamptz, approved_at timestamptz)
    cases(id uuid, user_id uuid, title, description, status, created_at timestamptz)
    evidence(id uuid, case_id uuid, filename, sha256, media_type, bytes bigint,
             provenance_state, summary, analysis_json jsonb, created_at timestamptz)
    events(id uuid, case_id uuid, evidence_id uuid, event_type, actor, ip, user_agent,
           details_json jsonb, created_at timestamptz)

This file intentionally contains *no* FastAPI routes—only DB helpers.
"""
from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional, Union

import asyncpg

UUIDLike = Union[str, uuid.UUID, Any]  # tolerate asyncpg UUID wrapper


# -----------------------------
# Helpers
# -----------------------------
def _to_uuid(value: UUIDLike) -> uuid.UUID:
    """Coerce asyncpg UUID / str / uuid.UUID into uuid.UUID."""
    if isinstance(value, uuid.UUID):
        return value
    s = str(value).strip()
    return uuid.UUID(s)


def _is_email(value: Any) -> bool:
    s = str(value).strip()
    return "@" in s and "." in s.split("@")[-1]


def _row_to_dict(row: asyncpg.Record) -> Dict[str, Any]:
    d = dict(row)
    # Make JSON-serializable (uuid.UUID + asyncpg UUID wrapper)
    for k, v in list(d.items()):
        if isinstance(v, uuid.UUID):
            d[k] = str(v)
        else:
            if v is not None and v.__class__.__name__ == "UUID":
                try:
                    d[k] = str(v)
                except Exception:
                    pass
    return d


async def _has_column(con: asyncpg.Connection, table: str, column: str) -> bool:
    q = """
    SELECT 1
    FROM information_schema.columns
    WHERE table_name = $1 AND column_name = $2
    LIMIT 1
    """
    return await con.fetchval(q, table, column) is not None


# -----------------------------
# Schema init / migrations
# -----------------------------
async def init_db(pool: asyncpg.Pool) -> None:
    """
    Create tables if missing and apply lightweight, safe migrations.
    This is designed to be idempotent.
    """
    async with pool.acquire() as con:
        await con.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")

        # USERS
        await con.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
              id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
              name text,
              email text UNIQUE NOT NULL,
              phone text,
              occupation text,
              company text,
              extras jsonb DEFAULT '{}'::jsonb,
              password_hash text NOT NULL,
              is_active boolean NOT NULL DEFAULT false,
              is_approved boolean NOT NULL DEFAULT false,
              must_change_password boolean NOT NULL DEFAULT true,
              requested_at timestamptz NOT NULL DEFAULT now(),
              approved_at timestamptz
            );
            """
        )

        # If an older schema exists without id, add it.
        if not await _has_column(con, "users", "id"):
            await con.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS id uuid;")
            await con.execute("UPDATE users SET id = gen_random_uuid() WHERE id IS NULL;")
            try:
                await con.execute("ALTER TABLE users ADD PRIMARY KEY (id);")
            except Exception:
                pass

        try:
            await con.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_email_uq ON users(email);")
        except Exception:
            pass

        # CASES
        await con.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
              id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
              user_id uuid NOT NULL,
              title text NOT NULL,
              description text DEFAULT '',
              status text NOT NULL DEFAULT 'open',
              created_at timestamptz NOT NULL DEFAULT now()
            );
            """
        )
        try:
            await con.execute("CREATE INDEX IF NOT EXISTS cases_user_id_idx ON cases(user_id);")
        except Exception:
            pass

        # EVIDENCE
        await con.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
              id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
              case_id uuid NOT NULL,
              filename text NOT NULL,
              sha256 text NOT NULL,
              media_type text NOT NULL,
              bytes bigint NOT NULL DEFAULT 0,
              provenance_state text NOT NULL DEFAULT 'unknown',
              summary text DEFAULT '',
              analysis_json jsonb DEFAULT '{}'::jsonb,
              created_at timestamptz NOT NULL DEFAULT now()
            );
            """
        )
        try:
            await con.execute("CREATE INDEX IF NOT EXISTS evidence_case_id_idx ON evidence(case_id);")
        except Exception:
            pass

        # EVENTS
        await con.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
              id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
              case_id uuid NOT NULL,
              evidence_id uuid,
              event_type text NOT NULL,
              actor text DEFAULT '',
              ip text DEFAULT '',
              user_agent text DEFAULT '',
              details_json jsonb DEFAULT '{}'::jsonb,
              created_at timestamptz NOT NULL DEFAULT now()
            );
            """
        )
        try:
            await con.execute("CREATE INDEX IF NOT EXISTS events_case_id_idx ON events(case_id);")
        except Exception:
            pass


# -----------------------------
# Users
# -----------------------------
async def get_user_by_email(pool: asyncpg.Pool, email: str) -> Optional[Dict[str, Any]]:
    async with pool.acquire() as con:
        row = await con.fetchrow("SELECT * FROM users WHERE email = $1", email.lower().strip())
        return _row_to_dict(row) if row else None


async def get_user_by_id(pool: asyncpg.Pool, user_id: UUIDLike) -> Optional[Dict[str, Any]]:
    uid = _to_uuid(user_id)
    async with pool.acquire() as con:
        row = await con.fetchrow("SELECT * FROM users WHERE id = $1", uid)
        return _row_to_dict(row) if row else None


async def list_users(pool: asyncpg.Pool, status: str = "all", limit: int = 200) -> List[Dict[str, Any]]:
    """
    status:
      - all
      - pending  (not approved)
      - approved
      - active
      - disabled
    """
    status = (status or "all").lower()
    where = "TRUE"
    if status == "pending":
        where = "is_approved = FALSE"
    elif status == "approved":
        where = "is_approved = TRUE"
    elif status == "active":
        where = "is_active = TRUE"
    elif status == "disabled":
        where = "is_active = FALSE"

    q = f"""
    SELECT *
    FROM users
    WHERE {where}
    ORDER BY requested_at DESC
    LIMIT $1
    """
    async with pool.acquire() as con:
        rows = await con.fetch(q, limit)
        return [_row_to_dict(r) for r in rows]


async def create_user_request(
    pool: asyncpg.Pool,
    *,
    name: str,
    email: str,
    phone: str = "",
    occupation: str = "",
    company: str = "",
    extras: Optional[Dict[str, Any]] = None,
    password_hash: str,
) -> Dict[str, Any]:
    email_n = email.lower().strip()
    extras = extras or {}
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO users (name, email, phone, occupation, company, extras, password_hash,
                               is_active, is_approved, must_change_password)
            VALUES ($1,$2,$3,$4,$5,$6,$7, FALSE, FALSE, TRUE)
            ON CONFLICT (email) DO UPDATE SET
              name = EXCLUDED.name,
              phone = EXCLUDED.phone,
              occupation = EXCLUDED.occupation,
              company = EXCLUDED.company,
              extras = EXCLUDED.extras
            RETURNING *;
            """,
            name,
            email_n,
            phone,
            occupation,
            company,
            json.dumps(extras),
            password_hash,
        )
        return _row_to_dict(row)


async def set_user_active(pool: Pool, user_id_or_email: Any, active: bool) -> None:
    """
    Set a user's active flag.

    Accepts either:
      - user UUID (uuid.UUID / asyncpg UUID / uuid string)
      - email string
    """
    async with pool.acquire() as con:
        if user_id_or_email is None:
            raise ValueError("user_id_or_email is required")

        # Email path
        if isinstance(user_id_or_email, str) and "@" in user_id_or_email:
            await con.execute(
                "UPDATE users SET is_active = $2 WHERE lower(email) = lower($1)",
                user_id_or_email,
                active,
            )
            return

        # UUID path
        if isinstance(user_id_or_email, uuid.UUID):
            user_uuid = user_id_or_email
        else:
            user_uuid = uuid.UUID(str(user_id_or_email))

        await con.execute(
            "UPDATE users SET is_active = $2 WHERE id = $1",
            user_uuid,
            active,
        )


async def set_user_approved(pool: Pool, user_id_or_email: Any, approved: bool) -> None:
    """
    Set a user's approved flag.

    Accepts either:
      - user UUID (uuid.UUID / asyncpg UUID / uuid string)
      - email string
    """
    async with pool.acquire() as con:
        if user_id_or_email is None:
            raise ValueError("user_id_or_email is required")

        # Email path
        if isinstance(user_id_or_email, str) and "@" in user_id_or_email:
            await con.execute(
                "UPDATE users SET is_approved = $2, approved_at = CASE WHEN $2 THEN now() ELSE NULL END WHERE lower(email) = lower($1)",
                user_id_or_email,
                approved,
            )
            return

        # UUID path
        if isinstance(user_id_or_email, uuid.UUID):
            user_uuid = user_id_or_email
        else:
            user_uuid = uuid.UUID(str(user_id_or_email))

        await con.execute(
            "UPDATE users SET is_approved = $2, approved_at = CASE WHEN $2 THEN now() ELSE NULL END WHERE id = $1",
            user_uuid,
            approved,
        )


async def set_user_password_hash(pool: asyncpg.Pool, user_identifier: Any, password_hash: str, must_change: bool) -> None:
    async with pool.acquire() as con:
        if _is_email(user_identifier):
            email = str(user_identifier).lower().strip()
            await con.execute(
                "UPDATE users SET password_hash=$2, must_change_password=$3 WHERE email=$1",
                email,
                password_hash,
                must_change,
            )
        else:
            uid = _to_uuid(user_identifier)
            await con.execute(
                "UPDATE users SET password_hash=$2, must_change_password=$3 WHERE id=$1",
                uid,
                password_hash,
                must_change,
            )


# -----------------------------
# Cases
# -----------------------------
async def create_case(
    pool: asyncpg.Pool,
    *,
    user_id: Any,
    title: str,
    description: str = "",
    status: str = "open",
) -> Dict[str, Any]:
    uid = _to_uuid(user_id)
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO cases (user_id, title, description, status)
            VALUES ($1,$2,$3,$4)
            RETURNING *;
            """,
            uid,
            title,
            description,
            status,
        )
        return _row_to_dict(row)


async def list_cases(pool: asyncpg.Pool, user_id: Optional[Any] = None, limit: int = 200) -> List[Dict[str, Any]]:
    async with pool.acquire() as con:
        if user_id is None:
            rows = await con.fetch(
                "SELECT * FROM cases ORDER BY created_at DESC LIMIT $1",
                limit,
            )
        else:
            uid = _to_uuid(user_id)
            rows = await con.fetch(
                "SELECT * FROM cases WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2",
                uid,
                limit,
            )
        return [_row_to_dict(r) for r in rows]


async def get_case(pool: asyncpg.Pool, case_id: Any) -> Optional[Dict[str, Any]]:
    cid = _to_uuid(case_id)
    async with pool.acquire() as con:
        row = await con.fetchrow("SELECT * FROM cases WHERE id = $1", cid)
        return _row_to_dict(row) if row else None


# -----------------------------
# Evidence
# -----------------------------
async def create_evidence(
    pool: asyncpg.Pool,
    *,
    case_id: Any,
    filename: str,
    sha256: str,
    media_type: str,
    bytes_size: int,
    provenance_state: str,
    summary: str,
    analysis_json: Dict[str, Any],
) -> Dict[str, Any]:
    cid = _to_uuid(case_id)
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO evidence (case_id, filename, sha256, media_type, bytes,
                                 provenance_state, summary, analysis_json)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
            RETURNING *;
            """,
            cid,
            filename,
            sha256,
            media_type,
            int(bytes_size or 0),
            provenance_state,
            summary,
            json.dumps(analysis_json or {}),
        )
        return _row_to_dict(row)


async def list_evidence(pool: asyncpg.Pool, case_id: Any, limit: int = 200) -> List[Dict[str, Any]]:
    cid = _to_uuid(case_id)
    async with pool.acquire() as con:
        rows = await con.fetch(
            "SELECT * FROM evidence WHERE case_id = $1 ORDER BY created_at DESC LIMIT $2",
            cid,
            limit,
        )
        return [_row_to_dict(r) for r in rows]


async def get_evidence(pool: asyncpg.Pool, evidence_id: Any) -> Optional[Dict[str, Any]]:
    eid = _to_uuid(evidence_id)
    async with pool.acquire() as con:
        row = await con.fetchrow("SELECT * FROM evidence WHERE id = $1", eid)
        return _row_to_dict(row) if row else None


# -----------------------------
# Events (chain of custody)
# -----------------------------
async def create_event(
    pool: asyncpg.Pool,
    *,
    case_id: Any,
    evidence_id: Optional[Any],
    event_type: str,
    actor: str,
    ip: str = "",
    user_agent: str = "",
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    cid = _to_uuid(case_id)
    eid = _to_uuid(evidence_id) if evidence_id else None
    details = details or {}
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO events (case_id, evidence_id, event_type, actor, ip, user_agent, details_json)
            VALUES ($1,$2,$3,$4,$5,$6,$7)
            RETURNING *;
            """,
            cid,
            eid,
            event_type,
            actor,
            ip,
            user_agent,
            json.dumps(details),
        )
        return _row_to_dict(row)


async def list_events(
    pool: asyncpg.Pool,
    case_id: Optional[Any] = None,
    limit: int = 200,
) -> List[Dict[str, Any]]:
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
                WHERE case_id = $1
                ORDER BY created_at DESC
                LIMIT $2
                """,
                cid,
                limit,
            )
        return [_row_to_dict(r) for r in rows]


# -----------------------------
# Simple counts for admin dashboard
# -----------------------------
async def count_users(pool: asyncpg.Pool) -> int:
    async with pool.acquire() as con:
        return int(await con.fetchval("SELECT COUNT(*) FROM users"))


async def count_cases(pool: asyncpg.Pool) -> int:
    async with pool.acquire() as con:
        return int(await con.fetchval("SELECT COUNT(*) FROM cases"))


async def count_evidence(pool: asyncpg.Pool) -> int:
    async with pool.acquire() as con:
        return int(await con.fetchval("SELECT COUNT(*) FROM evidence"))


async def count_pending_users(pool: asyncpg.Pool) -> int:
    async with pool.acquire() as con:
        return int(await con.fetchval("SELECT COUNT(*) FROM users WHERE is_approved = FALSE"))
