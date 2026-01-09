from __future__ import annotations

import os
import json
import uuid
import datetime
from typing import Any, Dict, List, Optional

import asyncpg


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


def dsn_from_env() -> str:
    """Return DSN for asyncpg.

    Render and many providers expose DATABASE_URL as either:
      - postgres://user:pass@host:port/db
      - postgresql://user:pass@host:port/db

    asyncpg accepts postgresql://.
    """
    dsn = os.getenv("DATABASE_URL") or os.getenv("TRUTHSTAMP_DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL is not set")
    if dsn.startswith("postgres://"):
        dsn = "postgresql://" + dsn[len("postgres://") :]
    return dsn


async def create_pool() -> asyncpg.Pool:
    pool = await asyncpg.create_pool(dsn_from_env(), min_size=1, max_size=5)
    await init_db(pool)
    return pool


async def init_db(pool: asyncpg.Pool) -> None:
    """Create tables if missing.

    Keeping migrations minimal for YC MVP: schema evolves via forward-compatible columns.
    """
    async with pool.acquire() as con:
        await con.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
              id UUID PRIMARY KEY,
              name TEXT NOT NULL,
              email TEXT NOT NULL UNIQUE,
              phone TEXT,
              occupation TEXT,
              company TEXT,
              extras JSONB,
              password_hash TEXT,
              is_active BOOLEAN NOT NULL DEFAULT FALSE,
              is_approved BOOLEAN NOT NULL DEFAULT FALSE,
              must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
              requested_at TIMESTAMPTZ NOT NULL,
              approved_at TIMESTAMPTZ
            );
            """
        )

        await con.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
              id UUID PRIMARY KEY,
              user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              title TEXT NOT NULL,
              description TEXT,
              status TEXT NOT NULL DEFAULT 'open',
              created_at TIMESTAMPTZ NOT NULL
            );
            """
        )

        await con.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
              id UUID PRIMARY KEY,
              case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
              filename TEXT NOT NULL,
              sha256 TEXT NOT NULL,
              media_type TEXT,
              bytes BIGINT,
              provenance_state TEXT,
              summary TEXT,
              analysis_json JSONB,
              created_at TIMESTAMPTZ NOT NULL
            );
            """
        )

        await con.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
              id UUID PRIMARY KEY,
              case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
              evidence_id UUID REFERENCES evidence(id) ON DELETE SET NULL,
              event_type TEXT NOT NULL,
              actor TEXT,
              ip TEXT,
              user_agent TEXT,
              details_json JSONB,
              created_at TIMESTAMPTZ NOT NULL
            );
            """
        )

        await con.execute("CREATE INDEX IF NOT EXISTS idx_cases_user ON cases(user_id);")
        await con.execute("CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);")
        await con.execute("CREATE INDEX IF NOT EXISTS idx_events_case ON events(case_id);")
        await con.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")


# -----------------------------
# Users
# -----------------------------


async def create_access_request(
    pool: asyncpg.Pool,
    *,
    name: str,
    email: str,
    phone: Optional[str],
    occupation: Optional[str],
    company: Optional[str],
    extras: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    uid = _uuid()
    now = _utcnow()
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO users (id, name, email, phone, occupation, company, extras, requested_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, name, email, phone, occupation, company, is_active, is_approved, must_change_password, requested_at;
            """,
            uuid.UUID(uid),
            name.strip(),
            email.strip().lower(),
            (phone or None),
            (occupation or None),
            (company or None),
            json.dumps(extras or {}),
            now,
        )
    return _row_to_user(row)


async def get_user_by_email(pool: asyncpg.Pool, email: str) -> Optional[Dict[str, Any]]:
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            SELECT id, name, email, phone, occupation, company, extras,
                   password_hash, is_active, is_approved, must_change_password,
                   requested_at, approved_at
            FROM users WHERE email = $1;
            """,
            email.strip().lower(),
        )
    return _row_to_user(row) if row else None


async def get_user_by_id(pool: asyncpg.Pool, user_id: str) -> Optional[Dict[str, Any]]:
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            SELECT id, name, email, phone, occupation, company, extras,
                   password_hash, is_active, is_approved, must_change_password,
                   requested_at, approved_at
            FROM users WHERE id = $1;
            """,
            uuid.UUID(user_id),
        )
    return _row_to_user(row) if row else None


async def list_pending_users(pool: asyncpg.Pool, limit: int = 50) -> List[Dict[str, Any]]:
    async with pool.acquire() as con:
        rows = await con.fetch(
            """
            SELECT id, name, email, phone, occupation, company, extras,
                   is_active, is_approved, must_change_password, requested_at
            FROM users
            WHERE is_approved = FALSE
            ORDER BY requested_at DESC
            LIMIT $1;
            """,
            limit,
        )
    return [_row_to_user(r) for r in rows]


async def approve_user(
    pool: asyncpg.Pool,
    user_id: str,
    *,
    password_hash: str,
    must_change_password: bool = True,
) -> Dict[str, Any]:
    now = _utcnow()
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            UPDATE users
            SET password_hash = $2,
                is_active = TRUE,
                is_approved = TRUE,
                must_change_password = $3,
                approved_at = $4
            WHERE id = $1
            RETURNING id, name, email, phone, occupation, company, extras,
                      is_active, is_approved, must_change_password, requested_at, approved_at;
            """,
            uuid.UUID(user_id),
            password_hash,
            must_change_password,
            now,
        )
    if not row:
        raise KeyError("User not found")
    return _row_to_user(row)


async def set_user_password(pool: asyncpg.Pool, user_id: str, password_hash: str, *, must_change_password: bool = False) -> None:
    async with pool.acquire() as con:
        await con.execute(
            """
            UPDATE users
            SET password_hash = $2,
                must_change_password = $3
            WHERE id = $1;
            """,
            uuid.UUID(user_id),
            password_hash,
            must_change_password,
        )


# -----------------------------
# Cases / Evidence / Events
# -----------------------------


async def create_case(pool: asyncpg.Pool, user_id: str, title: str, description: Optional[str]) -> Dict[str, Any]:
    cid = _uuid()
    now = _utcnow()
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO cases (id, user_id, title, description, created_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, user_id, title, description, status, created_at;
            """,
            uuid.UUID(cid),
            uuid.UUID(user_id),
            title,
            description,
            now,
        )
    return _row_to_case(row)


async def list_cases(pool: asyncpg.Pool, user_id: str | None, limit: int = 50, offset: int = 0):
    async with pool.acquire() as con:
        rows = await con.fetch(
            """
            SELECT id, user_id, title, description, status, created_at
            FROM cases
            WHERE ($1::text IS NULL OR user_id = $1)
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3;
            """,
            (uuid.UUID(user_id) if user_id else None),
            limit,
            offset,
        )
    return [_row_to_case(r) for r in rows]


async def get_case(pool: asyncpg.Pool, user_id: str, case_id: str) -> Optional[Dict[str, Any]]:
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            SELECT id, user_id, title, description, status, created_at
            FROM cases
            WHERE id = $1 AND user_id = $2;
            """,
            (uuid.UUID(case_id) if case_id else None),
            (uuid.UUID(user_id) if user_id else None),
        )
    return _row_to_case(row) if row else None


async def add_evidence(
    pool: asyncpg.Pool,
    *,
    case_id: str,
    filename: str,
    sha256: str,
    media_type: Optional[str],
    nbytes: int,
    provenance_state: Optional[str],
    summary: Optional[str],
    analysis: Dict[str, Any],
) -> Dict[str, Any]:
    eid = _uuid()
    now = _utcnow()
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO evidence (id, case_id, filename, sha256, media_type, bytes, provenance_state, summary, analysis_json, created_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
            RETURNING id, case_id, filename, sha256, media_type, bytes, provenance_state, summary, created_at;
            """,
            uuid.UUID(eid),
            uuid.UUID(case_id),
            filename,
            sha256,
            media_type,
            int(nbytes),
            provenance_state,
            summary,
            json.dumps(analysis),
            now,
        )
    return _row_to_evidence(row)


async def list_evidence(pool: asyncpg.Pool, case_id: str, limit: int = 200) -> List[Dict[str, Any]]:
    async with pool.acquire() as con:
        rows = await con.fetch(
            """
            SELECT id, case_id, filename, sha256, media_type, bytes, provenance_state, summary, created_at
            FROM evidence
            WHERE case_id = $1
            ORDER BY created_at DESC
            LIMIT $2;
            """,
            uuid.UUID(case_id),
            limit,
        )
    return [_row_to_evidence(r) for r in rows]


async def get_evidence(pool: asyncpg.Pool, case_id: str, evidence_id: str) -> Optional[Dict[str, Any]]:
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            SELECT id, case_id, filename, sha256, media_type, bytes, provenance_state, summary, analysis_json, created_at
            FROM evidence
            WHERE case_id = $1 AND id = $2;
            """,
            uuid.UUID(case_id),
            uuid.UUID(evidence_id),
        )
    if not row:
        return None
    d = _row_to_evidence(row)
    try:
        d["analysis"] = row["analysis_json"] if isinstance(row["analysis_json"], dict) else json.loads(row["analysis_json"] or "{}")
    except Exception:
        d["analysis"] = {}
    return d


async def add_event(
    pool: asyncpg.Pool,
    *,
    case_id: str,
    event_type: str,
    evidence_id: Optional[str] = None,
    actor: Optional[str] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    evt_id = _uuid()
    now = _utcnow()
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO events (id, case_id, evidence_id, event_type, actor, ip, user_agent, details_json, created_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            RETURNING id, case_id, evidence_id, event_type, actor, ip, user_agent, details_json, created_at;
            """,
            uuid.UUID(evt_id),
            uuid.UUID(case_id),
            (uuid.UUID(evidence_id) if evidence_id else None),
            event_type,
            actor,
            ip,
            user_agent,
            json.dumps(details or {}),
            now,
        )
    return _row_to_event(row)


async def list_events(pool, case_id: Optional[str] = None, limit: int = 50):
    """
    Return recent audit/custody events.
    Uses events.details_json (jsonb) in DB but returns it as "details" in API.
    """
    # Normalize case_id
    if case_id in (None, "", "None", "none", "null", "NULL"):
        case_uuid = None
    else:
        try:
            case_uuid = uuid.UUID(str(case_id))
        except Exception:
            case_uuid = None

    async with pool.acquire() as con:
        if case_uuid is None:
            rows = await con.fetch(
                """
                SELECT
                  id,
                  case_id,
                  evidence_id,
                  event_type,
                  actor,
                  ip,
                  user_agent,
                  details_json AS details,
                  created_at
                FROM events
                ORDER BY created_at DESC
                LIMIT $1
                """,
                limit,
            )
        else:
            rows = await con.fetch(
                """
                SELECT
                  id,
                  case_id,
                  evidence_id,
                  event_type,
                  actor,
                  ip,
                  user_agent,
                  details_json AS details,
                  created_at
                FROM events
                WHERE case_id = $1
                ORDER BY created_at DESC
                LIMIT $2
                """,
                case_uuid, limit,
            )

    out = []
    for r in rows:
        details = r.get("details") or {}
        # asyncpg returns jsonb as dict already, but guard anyway
        if not isinstance(details, dict):
            details = {"raw": details}

        out.append({
            "id": str(r["id"]) if r.get("id") else None,
            "case_id": str(r["case_id"]) if r.get("case_id") else None,
            "evidence_id": str(r["evidence_id"]) if r.get("evidence_id") else None,
            "event_type": r.get("event_type"),
            "actor": r.get("actor"),
            "ip": r.get("ip"),
            "user_agent": r.get("user_agent"),
            "details": details,
            "created_at": r["created_at"].isoformat() if r.get("created_at") else None,
        })

    return out



# -----------------------------
# Helpers
# -----------------------------


def _row_to_user(row: asyncpg.Record) -> Dict[str, Any]:
    extras = row.get("extras")
    if isinstance(extras, str):
        try:
            extras = json.loads(extras)
        except Exception:
            extras = {}
    return {
        "id": str(row["id"]),
        "name": row.get("name"),
        "email": row.get("email"),
        "phone": row.get("phone"),
        "occupation": row.get("occupation"),
        "company": row.get("company"),
        "extras": extras or {},
        "password_hash": row.get("password_hash"),
        "is_active": row.get("is_active"),
        "is_approved": row.get("is_approved"),
        "must_change_password": row.get("must_change_password"),
        "requested_at": row.get("requested_at").isoformat() if row.get("requested_at") else None,
        "approved_at": row.get("approved_at").isoformat() if row.get("approved_at") else None,
    }


def _row_to_case(row: asyncpg.Record) -> Dict[str, Any]:
    return {
        "id": str(row["id"]),
        "user_id": str(row["user_id"]),
        "title": row.get("title"),
        "description": row.get("description"),
        "status": row.get("status"),
        "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
    }


def _row_to_evidence(row: asyncpg.Record) -> Dict[str, Any]:
    return {
        "id": str(row["id"]),
        "case_id": str(row["case_id"]),
        "filename": row.get("filename"),
        "sha256": row.get("sha256"),
        "media_type": row.get("media_type"),
        "bytes": row.get("bytes"),
        "provenance_state": row.get("provenance_state"),
        "summary": row.get("summary"),
        "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
    }


def _row_to_event(row: asyncpg.Record) -> Dict[str, Any]:
    details = row.get("details_json")
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except Exception:
            details = {}
    return {
        "id": str(row["id"]),
        "case_id": str(row["case_id"]),
        "evidence_id": str(row["evidence_id"]) if row.get("evidence_id") else None,
        "event_type": row.get("event_type"),
        "actor": row.get("actor"),
        "ip": row.get("ip"),
        "user_agent": row.get("user_agent"),
        "details": details or {},
        "created_at": row.get("created_at").isoformat() if row.get("created_at") else None,
    }


async def list_users(pool: asyncpg.Pool, status: str = "all", limit: int = 200) -> List[Dict[str, Any]]:
    """status: all | pending | approved"""
    where = ""
    if status == "pending":
        where = "WHERE is_approved = false"
    elif status == "approved":
        where = "WHERE is_approved = true"
    q = f"""
        SELECT id, name, email, phone, occupation, company, extras, is_active, is_approved, must_change_password, created_at
        FROM users
        {where}
        ORDER BY created_at DESC
        LIMIT $1
    """
    async with pool.acquire() as con:
        rows = await con.fetch(q, limit)
        return [dict(r) for r in rows]


async def set_user_active(pool: asyncpg.Pool, user_id: str, is_active: bool) -> None:
    async with pool.acquire() as con:
        await con.execute("UPDATE users SET is_active=$2 WHERE id=$1", user_id, is_active)


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