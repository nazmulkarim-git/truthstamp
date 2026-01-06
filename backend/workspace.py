from __future__ import annotations

import os
import sqlite3
import json
import uuid
import datetime
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_DB_PATH = os.getenv("TRUTHSTAMP_DB_PATH", "/tmp/truthstamp.db")


def _utc_now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def get_db_path() -> str:
    return os.getenv("TRUTHSTAMP_DB_PATH", DEFAULT_DB_PATH)


def connect() -> sqlite3.Connection:
    con = sqlite3.connect(get_db_path(), check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def init_db() -> None:
    """Create tables if not exist + apply light migrations."""
    con = connect()

    # Users
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )

    # Cases (owned by user)
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
    )

    # Evidence
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS evidence (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            media_type TEXT,
            bytes INTEGER,
            provenance_state TEXT,
            summary TEXT,
            analysis_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(id)
        );
        """
    )

    # Events (chain of custody)
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            case_id TEXT NOT NULL,
            evidence_id TEXT,
            event_type TEXT NOT NULL,
            actor TEXT,
            ip TEXT,
            user_agent TEXT,
            details_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(id),
            FOREIGN KEY(evidence_id) REFERENCES evidence(id)
        );
        """
    )

    # Simple migrations for older DBs: add missing columns safely
    def _col_exists(table: str, col: str) -> bool:
        rows = con.execute(f"PRAGMA table_info({table});").fetchall()
        return any(r[1] == col for r in rows)

    # cases.user_id might be missing in older DB
    if not _col_exists("cases", "user_id"):
        # If the table existed without user_id, add it nullable then backfill to 'public' user.
        con.execute("ALTER TABLE cases ADD COLUMN user_id TEXT;")
        # ensure a default 'public' user
        public = con.execute("SELECT id FROM users WHERE email = ?", ("public@truthstamp",)).fetchone()
        if not public:
            public_id = _new_id("usr")
            con.execute(
                "INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (public_id, "public@truthstamp", "disabled", _utc_now_iso()),
            )
        public_id = con.execute("SELECT id FROM users WHERE email = ?", ("public@truthstamp",)).fetchone()[0]
        con.execute("UPDATE cases SET user_id = COALESCE(user_id, ?)", (public_id,))
        con.commit()

    con.commit()
    con.close()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


# -----------------------------
# Users
# -----------------------------
def create_user(email: str, password_hash: str) -> Dict[str, Any]:
    init_db()
    con = connect()
    user_id = _new_id("usr")
    created_at = _utc_now_iso()
    con.execute(
        "INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (user_id, email.lower().strip(), password_hash, created_at),
    )
    con.commit()
    con.close()
    return {"id": user_id, "email": email.lower().strip(), "created_at": created_at}


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    init_db()
    con = connect()
    row = con.execute(
        "SELECT id, email, password_hash, created_at FROM users WHERE email = ?",
        (email.lower().strip(),),
    ).fetchone()
    con.close()
    return dict(row) if row else None


def get_user(user_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    con = connect()
    row = con.execute(
        "SELECT id, email, created_at FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    con.close()
    return dict(row) if row else None


# -----------------------------
# Cases
# -----------------------------
def create_case(user_id: str, title: str, description: Optional[str] = None) -> Dict[str, Any]:
    init_db()
    con = connect()
    case_id = _new_id("case")
    created_at = _utc_now_iso()
    con.execute(
        "INSERT INTO cases (id, user_id, title, description, created_at) VALUES (?, ?, ?, ?, ?)",
        (case_id, user_id, title, description, created_at),
    )
    con.commit()
    con.close()
    return {"id": case_id, "user_id": user_id, "title": title, "description": description, "created_at": created_at}


def list_cases(user_id: str, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    init_db()
    con = connect()
    rows = con.execute(
        "SELECT id, user_id, title, description, created_at FROM cases WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (user_id, limit, offset),
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def get_case(user_id: str, case_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    con = connect()
    row = con.execute(
        "SELECT id, user_id, title, description, created_at FROM cases WHERE id = ? AND user_id = ?",
        (case_id, user_id),
    ).fetchone()
    con.close()
    return dict(row) if row else None


# -----------------------------
# Evidence
# -----------------------------
def add_evidence(
    case_id: str,
    filename: str,
    sha256: str,
    media_type: Optional[str],
    nbytes: int,
    provenance_state: Optional[str],
    summary: Optional[str],
    analysis: Dict[str, Any],
) -> Dict[str, Any]:
    init_db()
    con = connect()
    evidence_id = _new_id("evd")
    created_at = _utc_now_iso()
    con.execute(
        "INSERT INTO evidence (id, case_id, filename, sha256, media_type, bytes, provenance_state, summary, analysis_json, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (evidence_id, case_id, filename, sha256, media_type, nbytes, provenance_state, summary, json.dumps(analysis), created_at),
    )
    con.commit()
    con.close()
    return {
        "id": evidence_id,
        "case_id": case_id,
        "filename": filename,
        "sha256": sha256,
        "media_type": media_type,
        "bytes": nbytes,
        "provenance_state": provenance_state,
        "summary": summary,
        "created_at": created_at,
    }


def list_evidence(case_id: str, limit: int = 200) -> List[Dict[str, Any]]:
    init_db()
    con = connect()
    rows = con.execute(
        "SELECT id, case_id, filename, sha256, media_type, bytes, provenance_state, summary, created_at "
        "FROM evidence WHERE case_id = ? ORDER BY created_at DESC LIMIT ?",
        (case_id, limit),
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def get_evidence(case_id: str, evidence_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    con = connect()
    row = con.execute(
        "SELECT id, case_id, filename, sha256, media_type, bytes, provenance_state, summary, analysis_json, created_at "
        "FROM evidence WHERE case_id = ? AND id = ?",
        (case_id, evidence_id),
    ).fetchone()
    con.close()
    if not row:
        return None
    d = dict(row)
    try:
        d["analysis"] = json.loads(d.pop("analysis_json") or "{}")
    except Exception:
        d["analysis"] = {}
    return d


# -----------------------------
# Events
# -----------------------------
def add_event(
    case_id: str,
    event_type: str,
    evidence_id: Optional[str] = None,
    actor: Optional[str] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    init_db()
    con = connect()
    event_id = _new_id("evt")
    created_at = _utc_now_iso()
    payload = json.dumps(details or {})
    con.execute(
        "INSERT INTO events (id, case_id, evidence_id, event_type, actor, ip, user_agent, details_json, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (event_id, case_id, evidence_id, event_type, actor, ip, user_agent, payload, created_at),
    )
    con.commit()
    con.close()
    return {"id": event_id, "case_id": case_id, "evidence_id": evidence_id, "event_type": event_type, "created_at": created_at}


def list_events(case_id: str, limit: int = 200) -> List[Dict[str, Any]]:
    init_db()
    con = connect()
    rows = con.execute(
        "SELECT id, case_id, evidence_id, event_type, actor, ip, user_agent, details_json, created_at "
        "FROM events WHERE case_id = ? ORDER BY created_at DESC LIMIT ?",
        (case_id, limit),
    ).fetchall()
    con.close()
    out: List[Dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        try:
            d["details"] = json.loads(d.pop("details_json") or "{}")
        except Exception:
            d["details"] = {}
        out.append(d)
    return out
