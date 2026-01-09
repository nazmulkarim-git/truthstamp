from __future__ import annotations

import os
import json
import uuid
import datetime
from typing import Any, Dict, List, Optional

import asyncpg


# -----------------------------
# Utils
# -----------------------------

def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)

def _uuid() -> uuid.UUID:
    return uuid.uuid4()

def dsn_from_env() -> str:
    dsn = os.getenv("DATABASE_URL") or os.getenv("TRUTHSTAMP_DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL is not set")
    if dsn.startswith("postgres://"):
        dsn = "postgresql://" + dsn[len("postgres://"):]
    return dsn


# -----------------------------
# Connection
# -----------------------------

async def create_pool() -> asyncpg.Pool:
    pool = await asyncpg.create_pool(dsn_from_env(), min_size=1, max_size=5)
    return pool


# -----------------------------
# USERS
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
):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO users
              (name, email, phone, occupation, company, extras, requested_at)
            VALUES
              ($1,$2,$3,$4,$5,$6,$7)
            RETURNING *;
            """,
            name.strip(),
            email.strip().lower(),
            phone,
            occupation,
            company,
            json.dumps(extras or {}),
            _utcnow(),
        )
    return dict(row)


async def list_users(pool, status: Optional[str] = None, limit: int = 500):
    async with pool.acquire() as con:
        if status == "pending":
            q = """
            SELECT * FROM users
            WHERE is_approved = FALSE
            ORDER BY requested_at DESC
            LIMIT $1
            """
            rows = await con.fetch(q, limit)

        elif status == "approved":
            q = """
            SELECT * FROM users
            WHERE is_approved = TRUE
            ORDER BY approved_at DESC NULLS LAST
            LIMIT $1
            """
            rows = await con.fetch(q, limit)

        else:
            q = """
            SELECT * FROM users
            ORDER BY requested_at DESC
            LIMIT $1
            """
            rows = await con.fetch(q, limit)

    return [dict(r) for r in rows]


async def get_user_by_email(pool, email: str):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "SELECT * FROM users WHERE email=$1",
            email.lower(),
        )
    return dict(row) if row else None


async def set_user_active(pool, email: str, active: bool):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            "UPDATE users SET is_active=$2 WHERE email=$1 RETURNING email",
            email.lower(), active
        )
        if not row:
            raise ValueError("User not found")


async def set_user_approved(pool, email: str, approved: bool):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            UPDATE users
            SET is_approved=$2,
                approved_at=NOW()
            WHERE email=$1
            RETURNING email
            """,
            email.lower(), approved
        )
        if not row:
            raise ValueError("User not found")


async def set_user_password(pool, email: str, password_hash: str, must_change_password: bool):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            UPDATE users
            SET password_hash=$2,
                must_change_password=$3
            WHERE email=$1
            RETURNING email
            """,
            email.lower(), password_hash, must_change_password
        )
        if not row:
            raise ValueError("User not found")


# -----------------------------
# CASES
# -----------------------------

async def create_case(pool, user_id: str, title: str, description: Optional[str]):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO cases (user_id, title, description, created_at)
            VALUES ($1,$2,$3,$4)
            RETURNING *;
            """,
            uuid.UUID(user_id),
            title,
            description,
            _utcnow(),
        )
    return dict(row)


async def list_cases(pool, user_id: Optional[str] = None, limit: int = 500):
    async with pool.acquire() as con:
        if not user_id:
            rows = await con.fetch(
                """
                SELECT * FROM cases
                ORDER BY created_at DESC
                LIMIT $1
                """,
                limit,
            )
        else:
            rows = await con.fetch(
                """
                SELECT * FROM cases
                WHERE user_id = $1
                ORDER BY created_at DESC
                LIMIT $2
                """,
                uuid.UUID(user_id), limit,
            )

    return [dict(r) for r in rows]


# -----------------------------
# EVIDENCE
# -----------------------------

async def add_evidence(
    pool,
    *,
    case_id: str,
    filename: str,
    sha256: str,
    media_type: Optional[str],
    nbytes: int,
    provenance_state: Optional[str],
    summary: Optional[str],
    analysis: Dict[str, Any],
):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO evidence
              (case_id, filename, sha256, media_type, bytes, provenance_state,
               summary, analysis_json, created_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            RETURNING *;
            """,
            uuid.UUID(case_id),
            filename,
            sha256,
            media_type,
            int(nbytes),
            provenance_state,
            summary,
            json.dumps(analysis),
            _utcnow(),
        )
    return dict(row)


async def list_evidence(pool, case_id: Optional[str] = None, limit: int = 500):
    async with pool.acquire() as con:
        if not case_id:
            rows = await con.fetch(
                """
                SELECT * FROM evidence
                ORDER BY created_at DESC
                LIMIT $1
                """,
                limit,
            )
        else:
            rows = await con.fetch(
                """
                SELECT * FROM evidence
                WHERE case_id = $1
                ORDER BY created_at DESC
                LIMIT $2
                """,
                uuid.UUID(case_id), limit,
            )

    return [dict(r) for r in rows]


# -----------------------------
# EVENTS (AUDIT LOG)
# -----------------------------

async def add_event(
    pool,
    *,
    case_id: str,
    event_type: str,
    evidence_id: Optional[str] = None,
    actor: Optional[str] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
):
    async with pool.acquire() as con:
        row = await con.fetchrow(
            """
            INSERT INTO events
              (case_id, evidence_id, event_type, actor, ip, user_agent, details_json, created_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
            RETURNING *;
            """,
            uuid.UUID(case_id),
            uuid.UUID(evidence_id) if evidence_id else None,
            event_type,
            actor,
            ip,
            user_agent,
            json.dumps(details or {}),
            _utcnow(),
        )
    return dict(row)


async def list_events(pool, case_id: Optional[str] = None, limit: int = 50):
    async with pool.acquire() as con:
        if not case_id:
            rows = await con.fetch(
                """
                SELECT *, details_json AS details FROM events
                ORDER BY created_at DESC
                LIMIT $1
                """,
                limit,
            )
        else:
            rows = await con.fetch(
                """
                SELECT *, details_json AS details FROM events
                WHERE case_id = $1
                ORDER BY created_at DESC
                LIMIT $2
                """,
                uuid.UUID(case_id), limit,
            )

    out = []
    for r in rows:
        d = dict(r)
        d["details"] = d.get("details_json") or {}
        out.append(d)

    return out


# -----------------------------
# ADMIN DASHBOARD COUNTS
# -----------------------------

async def counts_overview(pool):
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
