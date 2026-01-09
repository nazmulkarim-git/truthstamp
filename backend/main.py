import asyncio
import os
import json
import tempfile
import traceback
import datetime
import pathlib
import hashlib
import hmac
import secrets
from typing import Optional, Any, Dict, List

import jwt
import asyncpg
from asyncpg import Pool
from fastapi import (
    FastAPI,
    UploadFile,
    File,
    HTTPException,
    BackgroundTasks,
    Form,
    Request,
    Depends,
    Header,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from . import db
from . import emailer
from .config import MAX_MB
from .models import (
    AnalysisResult,
    ToolStatus,
    Finding,
    CaseCreate,
    CaseItem,
    EvidenceItem,
    EventItem,
)
from .utils import sha256_file
from .engine import (
    tool_versions,
    detect_media_type,
    extract_exiftool,
    extract_ffprobe,
    extract_c2pa,
    ai_disclosure_from_metadata,
    transformation_hints,
    classify_provenance,
    derived_timeline,
    metadata_consistency,
    metadata_completeness,
)

# -----------------------------
# App / CORS
# -----------------------------

import smtplib
from email.message import EmailMessage

def _smtp_configured() -> bool:
    return bool(os.getenv("SMTP_HOST") and os.getenv("SMTP_USER") and os.getenv("SMTP_PASS"))

def _generate_temp_password(length: int = 12) -> str:
    # URL-safe, includes letters+numbers; trim to length
    return secrets.token_urlsafe(max(8, length))[:length]

async def _send_email(to_email: str, subject: str, body: str) -> None:
    host = os.getenv("SMTP_HOST", "")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER", "")
    password = os.getenv("SMTP_PASS", "")
    from_addr = os.getenv("SMTP_FROM", "TruthStamp <no-reply@truthstamp.local>")

    if not host or not user or not password:
        return

    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    def _send():
        with smtplib.SMTP(host, port, timeout=20) as s:
            s.starttls()
            s.login(user, password)
            s.send_message(msg)

    await asyncio.to_thread(_send)

app = FastAPI()

_origins_raw = os.getenv(
    "CORS_ORIGINS",
    "https://truthstamp-web.onrender.com,http://localhost:3000,http://localhost:10000",
)
origins = [o.strip() for o in _origins_raw.split(",") if o.strip()]
if "*" in origins:
    origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Database
# -----------------------------
@app.on_event("startup")
async def _startup():
    app.state.pool = await db.create_pool()
    await db.init_db(app.state.pool)

@app.on_event("shutdown")
async def _shutdown():
    pool = getattr(app.state, "pool", None)
    if pool:
        await pool.close()

def get_pool() -> Pool:
    pool = getattr(app.state, "pool", None)
    if not pool:
        raise HTTPException(status_code=500, detail="Database not initialized")
    return pool

# -----------------------------
# Admin auth (header x-admin-key)
# -----------------------------
def require_admin(x_admin_key: str = Header(default="", alias="x-admin-key")) -> bool:
    expected = os.getenv("TRUTHSTAMP_ADMIN_API_KEY", "")
    if not expected or x_admin_key != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return True

# -----------------------------
# Schemas
# -----------------------------
class AuthIn(BaseModel):
    email: str
    password: str

class AuthOut(BaseModel):
    token: str
    user: dict

class EnableByEmail(BaseModel):
    email: str
    is_active: bool = True
    is_approved: bool = True

class AccessRequestIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: str
    phone: str | None = Field(default=None, max_length=50)
    occupation: str | None = Field(default=None, max_length=120)
    company: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=500)
    use_case: str | None = Field(default=None, max_length=200)

class ChangePasswordIn(BaseModel):
    old_password: str | None = None
    new_password: str = Field(min_length=8, max_length=200)

class ApproveOut(BaseModel):
    ok: bool
    email_sent: bool

# -----------------------------
# Auth (PBKDF2-HMAC-SHA256 + JWT)
# -----------------------------
JWT_SECRET = os.getenv("TRUTHSTAMP_JWT_SECRET", "dev-change-me")
JWT_ALG = "HS256"
JWT_TTL_HOURS = int(os.getenv("TRUTHSTAMP_JWT_TTL_HOURS", "168"))  # 7 days

# Stored format: pbkdf2_sha256$<iterations>$<salt_hex>$<dk_hex>
PBKDF2_ITERATIONS = int(os.getenv("TRUTHSTAMP_PBKDF2_ITERS", "200000"))

def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"

def _verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iters_s, salt_hex, dk_hex = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iters = int(iters_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(dk_hex)
        got = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
        return hmac.compare_digest(got, expected)
    except Exception:
        return False

def _create_token(user_id: str, email: str) -> str:
    now = datetime.datetime.utcnow()
    exp = now + datetime.timedelta(hours=JWT_TTL_HOURS)
    payload = {"sub": user_id, "email": email, "iat": int(now.timestamp()), "exp": int(exp.timestamp())}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def _decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])

def _sanitize_user(u: dict) -> dict:
    return {
        "id": u.get("id"),
        "name": u.get("name"),
        "email": u.get("email"),
        "phone": u.get("phone"),
        "occupation": u.get("occupation"),
        "company": u.get("company"),
        "extras": u.get("extras") or {},
        "must_change_password": bool(u.get("must_change_password")),
        "is_active": bool(u.get("is_active")),
        "is_approved": bool(u.get("is_approved")),
        "requested_at": u.get("requested_at"),
        "approved_at": u.get("approved_at"),
    }

async def get_current_user_async(request: Request, pool: Pool = Depends(get_pool)) -> dict:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth.split(" ", 1)[1].strip()
    try:
        payload = _decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    u = await db.get_user_by_id(pool, user_id)
    if not u or not u.get("is_active") or not u.get("is_approved"):
        raise HTTPException(status_code=401, detail="User not active")
    return u

async def get_optional_user_async(request: Request, pool: Pool = Depends(get_pool)) -> Optional[dict]:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    try:
        payload = _decode_token(token)
        user_id = payload.get("sub")
        if not user_id:
            return None
        u = await db.get_user_by_id(pool, user_id)
        if not u or not u.get("is_active") or not u.get("is_approved"):
            return None
        return u
    except Exception:
        return None

# -----------------------------
# Health
# -----------------------------
@app.get("/health")
def health():
    return {"ok": True, "service": "truthstamp-api"}
<<<<<<< HEAD

def _too_big(nbytes: int) -> bool:
    return nbytes > MAX_MB * 1024 * 1024

def _cleanup_file(path: Optional[str]) -> None:
    if not path:
        return
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

# -----------------------------
# ADMIN: use direct SQL matching your schemas
#   events.details_json (jsonb)
#   users.requested_at / approved_at
# -----------------------------
async def _admin_counts(pool: Pool) -> dict:
    async with pool.acquire() as con:
        users_total = await con.fetchval("SELECT COUNT(*) FROM users")
        users_pending = await con.fetchval("SELECT COUNT(*) FROM users WHERE is_approved = FALSE")
        cases_total = await con.fetchval("SELECT COUNT(*) FROM cases")
        evidence_total = await con.fetchval("SELECT COUNT(*) FROM evidence")
        events_total = await con.fetchval("SELECT COUNT(*) FROM events")
    return {
        "users_total": int(users_total or 0),
        "users_pending": int(users_pending or 0),
        "cases_total": int(cases_total or 0),
        "evidence_total": int(evidence_total or 0),
        "events_total": int(events_total or 0),
    }

async def _admin_recent_events(pool: Pool, limit: int = 50) -> list[dict]:
    async with pool.acquire() as con:
        rows = await con.fetch(
            """
            SELECT id, case_id, evidence_id, event_type, actor, ip, user_agent, details_json, created_at
            FROM events
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
        )
    out = []
    for r in rows:
        out.append(
            {
                "id": str(r["id"]),
                "case_id": str(r["case_id"]) if r["case_id"] else None,
                "evidence_id": str(r["evidence_id"]) if r["evidence_id"] else None,
                "event_type": r["event_type"],
                "actor": r["actor"],
                "ip": r["ip"],
                "user_agent": r["user_agent"],
                "details": r["details_json"] or {},
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
        )
    return out

async def _admin_list_users(pool: Pool, status: str = "all", limit: int = 500) -> list[dict]:
    where = ""
    params: list[Any] = [limit]
    if status == "pending":
        where = "WHERE is_approved = FALSE"
    elif status == "approved":
        where = "WHERE is_approved = TRUE"
    elif status == "disabled":
        where = "WHERE is_active = FALSE"

    q = f"""
        SELECT name, email, phone, occupation, company, extras,
               is_active, is_approved, must_change_password,
               requested_at, approved_at
        FROM users
        {where}
        ORDER BY requested_at DESC NULLS LAST
        LIMIT $1
    """
    async with pool.acquire() as con:
        rows = await con.fetch(q, *params)

    out = []
    for r in rows:
        out.append(
            {
                "name": r["name"],
                "email": r["email"],
                "phone": r["phone"],
                "occupation": r["occupation"],
                "company": r["company"],
                "extras": r["extras"] or {},
                "is_active": bool(r["is_active"]),
                "is_approved": bool(r["is_approved"]),
                "must_change_password": bool(r["must_change_password"]),
                "requested_at": r["requested_at"].isoformat() if r["requested_at"] else None,
                "approved_at": r["approved_at"].isoformat() if r["approved_at"] else None,
            }
        )
    return out

async def _admin_list_cases(pool: Pool, limit: int = 500) -> list[dict]:
    async with pool.acquire() as con:
        rows = await con.fetch(
            """
            SELECT id, user_id, title, description, status, created_at
            FROM cases
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
        )
    out = []
    for r in rows:
        out.append(
            {
                "id": str(r["id"]),
                "user_id": str(r["user_id"]) if r["user_id"] else None,
                "title": r["title"],
                "description": r["description"],
                "status": r["status"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
        )
    return out

async def _admin_set_user_flags_by_email(pool: Pool, email: str, is_active: bool, is_approved: bool) -> bool:
    email_norm = (email or "").strip().lower()
    if not email_norm or "@" not in email_norm:
        raise HTTPException(status_code=422, detail="Invalid email")
    async with pool.acquire() as con:
        res = await con.execute(
            """
            UPDATE users
            SET is_active = $2,
                is_approved = $3,
                approved_at = CASE WHEN $3 = TRUE THEN COALESCE(approved_at, NOW()) ELSE approved_at END
            WHERE email = $1
            """,
            email_norm,
            is_active,
            is_approved,
        )
    # asyncpg returns like: "UPDATE 1"
    return res.endswith("1")

@app.get("/admin/overview")
async def admin_overview(
    ok: bool = Depends(require_admin),
    pool: Pool = Depends(get_pool),
):
    counts = await _admin_counts(pool)
    recent_events = await _admin_recent_events(pool, limit=50)
    return {"counts": counts, "recent_events": recent_events}

@app.get("/admin/users")
async def admin_users(
    status: str = "all",
    ok: bool = Depends(require_admin),
    pool: Pool = Depends(get_pool),
):
    users = await _admin_list_users(pool, status=status, limit=500)
    return {"users": users}

@app.get("/admin/cases")
async def admin_cases(
    ok: bool = Depends(require_admin),
    pool: Pool = Depends(get_pool),
):
    cases = await _admin_list_cases(pool, limit=500)
    return {"cases": cases}

@app.post("/admin/users/enable-by-email")
async def admin_enable_user_by_email(
    req: EnableByEmail,
    pool: Pool = Depends(get_pool),
    _: None = Depends(require_admin),
):
    user = await db.get_user_by_email(pool, req.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await db.set_user_active(pool, user["id"], req.is_active)
    await db.set_user_approved(pool, user["id"], req.is_approved)

    return {"ok": True}

@app.get("/admin/pending-users")
async def admin_pending_users(
    ok: bool = Depends(require_admin),
    pool: Pool = Depends(get_pool),
):
    users = await _admin_list_users(pool, status="pending", limit=200)
    return users

=======

def _too_big(nbytes: int) -> bool:
    return nbytes > MAX_MB * 1024 * 1024

def _cleanup_file(path: Optional[str]) -> None:
    if not path:
        return
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass

# -----------------------------
# ADMIN: use direct SQL matching your schemas
#   events.details_json (jsonb)
#   users.requested_at / approved_at
# -----------------------------
async def _admin_counts(pool: Pool) -> dict:
    async with pool.acquire() as con:
        users_total = await con.fetchval("SELECT COUNT(*) FROM users")
        users_pending = await con.fetchval("SELECT COUNT(*) FROM users WHERE is_approved = FALSE")
        cases_total = await con.fetchval("SELECT COUNT(*) FROM cases")
        evidence_total = await con.fetchval("SELECT COUNT(*) FROM evidence")
        events_total = await con.fetchval("SELECT COUNT(*) FROM events")
    return {
        "users_total": int(users_total or 0),
        "users_pending": int(users_pending or 0),
        "cases_total": int(cases_total or 0),
        "evidence_total": int(evidence_total or 0),
        "events_total": int(events_total or 0),
    }

async def _admin_recent_events(pool: Pool, limit: int = 50) -> list[dict]:
    async with pool.acquire() as con:
        rows = await con.fetch(
            """
            SELECT id, case_id, evidence_id, event_type, actor, ip, user_agent, details_json, created_at
            FROM events
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
        )
    out = []
    for r in rows:
        out.append(
            {
                "id": str(r["id"]),
                "case_id": str(r["case_id"]) if r["case_id"] else None,
                "evidence_id": str(r["evidence_id"]) if r["evidence_id"] else None,
                "event_type": r["event_type"],
                "actor": r["actor"],
                "ip": r["ip"],
                "user_agent": r["user_agent"],
                "details": r["details_json"] or {},
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
        )
    return out

async def _admin_list_users(pool: Pool, status: str = "all", limit: int = 500) -> list[dict]:
    where = ""
    params: list[Any] = [limit]
    if status == "pending":
        where = "WHERE is_approved = FALSE"
    elif status == "approved":
        where = "WHERE is_approved = TRUE"
    elif status == "disabled":
        where = "WHERE is_active = FALSE"

    q = f"""
        SELECT name, email, phone, occupation, company, extras,
               is_active, is_approved, must_change_password,
               requested_at, approved_at
        FROM users
        {where}
        ORDER BY requested_at DESC NULLS LAST
        LIMIT $1
    """
    async with pool.acquire() as con:
        rows = await con.fetch(q, *params)

    out = []
    for r in rows:
        out.append(
            {
                "name": r["name"],
                "email": r["email"],
                "phone": r["phone"],
                "occupation": r["occupation"],
                "company": r["company"],
                "extras": r["extras"] or {},
                "is_active": bool(r["is_active"]),
                "is_approved": bool(r["is_approved"]),
                "must_change_password": bool(r["must_change_password"]),
                "requested_at": r["requested_at"].isoformat() if r["requested_at"] else None,
                "approved_at": r["approved_at"].isoformat() if r["approved_at"] else None,
            }
        )
    return out

async def _admin_list_cases(pool: Pool, limit: int = 500) -> list[dict]:
    async with pool.acquire() as con:
        rows = await con.fetch(
            """
            SELECT id, user_id, title, description, status, created_at
            FROM cases
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
        )
    out = []
    for r in rows:
        out.append(
            {
                "id": str(r["id"]),
                "user_id": str(r["user_id"]) if r["user_id"] else None,
                "title": r["title"],
                "description": r["description"],
                "status": r["status"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
        )
    return out


async def _admin_set_user_flags_by_email(pool, email: str, is_active: bool | None, is_approved: bool | None, *, issue_temp_password: bool = False):
    # Normalize
    email_norm = (email or "").strip().lower()
    if not email_norm:
        raise HTTPException(status_code=400, detail="Email is required")

    # Update flags
    sets = []
    args = [email_norm]
    if is_active is not None:
        sets.append(f"is_active=${len(args)+1}")
        args.append(bool(is_active))
    if is_approved is not None:
        sets.append(f"is_approved=${len(args)+1}")
        args.append(bool(is_approved))
        # stamp approved_at if approving
        if bool(is_approved):
            sets.append("approved_at=NOW()")
    if not sets:
        # nothing to update, but still allow issuing temp password
        pass
    else:
        q = "UPDATE users SET " + ", ".join(sets) + " WHERE email=$1 RETURNING email"
        async with pool.acquire() as con:
            row = await con.fetchrow(q, *args)
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

    user = await db.get_user_by_email(pool, email_norm)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    temp_password: str | None = None

    # Issue temp password when approving (or when explicitly asked)
    if issue_temp_password and (is_approved is None or bool(is_approved)):
        temp_password = _generate_temp_password()
        password_hash = _hash_password(temp_password)
        # Ensure user has id; if missing, init_db migration should have created it
        await db.set_user_password(pool, str(user["id"]), password_hash, must_change_password=True)

        # Email it if SMTP is configured; otherwise return in response so admin can copy-paste
        subject = "Your TruthStamp temporary password"
        body = (
            "Your account has been approved.

"
            f"Login email: {email_norm}
"
            f"Temporary password: {temp_password}

"
            "After logging in, you will be prompted to change your password immediately.

"
            "— TruthStamp"
        )
        await _send_email(email_norm, subject, body)

    # Return the updated user (sanitized) and temp password (if generated and SMTP not configured)
    sanitized = _sanitize_user(user)
    return {"user": sanitized, "temp_password": (temp_password if not _smtp_configured() else None)}


@app.get("/admin/overview")
async def admin_overview(
    ok: bool = Depends(require_admin),
    pool: Pool = Depends(get_pool),
):
    counts = await _admin_counts(pool)
    recent_events = await _admin_recent_events(pool, limit=50)
    return {"counts": counts, "recent_events": recent_events}

@app.get("/admin/users")
async def admin_users(
    status: str = "all",
    ok: bool = Depends(require_admin),
    pool: Pool = Depends(get_pool),
):
    users = await _admin_list_users(pool, status=status, limit=500)
    return {"users": users}

@app.get("/admin/cases")
async def admin_cases(
    ok: bool = Depends(require_admin),
    pool: Pool = Depends(get_pool),
):
    cases = await _admin_list_cases(pool, limit=500)
    return {"cases": cases}

@app.post("/admin/users/enable-by-email")
async def admin_enable_user_by_email(
    req: EnableByEmail,
    ok: bool = Depends(require_admin),
    pool: Pool = Depends(get_pool),
):
    updated = await _admin_set_user_flags_by_email(pool, req.email, req.is_active, req.is_approved)
    if not updated:
        raise HTTPException(status_code=404, detail="User not found")
    return {"ok": True, "email": (req.email or "").strip().lower()}

@app.get("/admin/pending-users")
async def admin_pending_users(
    ok: bool = Depends(require_admin),
    pool: Pool = Depends(get_pool),
):
    users = await _admin_list_users(pool, status="pending", limit=200)
    return users

>>>>>>> 30d16ff (Temp pass)
@app.post("/admin/approve-user/{email}", response_model=ApproveOut)
async def admin_approve_user(
    email: str,
    ok: bool = Depends(require_admin),
    pool: Pool = Depends(get_pool),
):
    # Approve by email (safer than UUID when UI is buggy)
    temp_password = secrets.token_urlsafe(9)
    ph = _hash_password(temp_password)

    # Set flags + password + must_change_password
    email_norm = (email or "").strip().lower()
    async with pool.acquire() as con:
        updated = await con.execute(
            """
            UPDATE users
            SET is_approved = TRUE,
                is_active = TRUE,
                must_change_password = TRUE,
                password_hash = $2,
                approved_at = COALESCE(approved_at, NOW())
            WHERE email = $1
            """,
            email_norm,
            ph,
        )
    if not updated.endswith("1"):
        raise HTTPException(status_code=404, detail="User not found")

    email_sent = False
    if emailer.smtp_configured():
        try:
            web_url = os.getenv("TRUTHSTAMP_WEB_URL", "https://truthstamp-web.onrender.com")
            subject = "Your TruthStamp temporary password"
            text = (
                f"Hi,\n\n"
                "Your TruthStamp account has been approved.\n\n"
                f"Login: {web_url}/login\n"
                f"Email: {email_norm}\n"
                f"Temporary password: {temp_password}\n\n"
                "After you log in, go to Profile → Change password to set your own password.\n\n"
                "— TruthStamp"
            )
            emailer.send_email(email_norm, subject, text)
            email_sent = True
        except Exception as e:
            print("EMAIL_SEND_ERROR:", repr(e))

    if not email_sent:
        print("TEMP_PASSWORD_FOR", email_norm, ":", temp_password)

    return {"ok": True, "email_sent": email_sent}

# -----------------------------
# Invite-only registration endpoints
# -----------------------------
async def _register_access_request(payload: AccessRequestIn, pool: Pool):
    email = (payload.email or "").strip().lower()
    if not email or "@" not in email:
        raise HTTPException(status_code=422, detail="Invalid email")

    existing = await db.get_user_by_email(pool, email)
    if existing:
        if existing.get("is_approved"):
            raise HTTPException(status_code=409, detail="Email already approved. Please log in.")
        raise HTTPException(status_code=409, detail="Request already submitted. Please wait for approval.")

    extras = {"notes": payload.notes, "use_case": payload.use_case}
    u = await db.create_access_request(
        pool,
        name=payload.name,
        email=email,
        phone=payload.phone,
        occupation=payload.occupation,
        company=payload.company,
        extras=extras,
    )
    return {"ok": True, "status": "pending", "user": {"id": u["id"], "email": u["email"]}}

@app.post("/auth/request-access")
async def request_access(payload: AccessRequestIn, pool: Pool = Depends(get_pool)):
    return await _register_access_request(payload, pool)

@app.post("/auth/login", response_model=AuthOut)
async def login(payload: AuthIn, pool: Pool = Depends(get_pool)):
    email = (payload.email or "").strip().lower()
    u = await db.get_user_by_email(pool, email)
    if not u or not u.get("is_approved") or not u.get("is_active"):
        raise HTTPException(status_code=401, detail="Account not approved yet")
    if not u.get("password_hash") or not _verify_password(payload.password, u.get("password_hash") or ""):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = _create_token(u["id"], u["email"])
    return {"token": token, "user": _sanitize_user(u)}

@app.get("/auth/me")
async def me(user=Depends(get_current_user_async)):
    return _sanitize_user(user)

@app.post("/auth/change-password")
async def change_password(
    payload: ChangePasswordIn,
    user=Depends(get_current_user_async),
    pool: Pool = Depends(get_pool),
):
    if not user.get("must_change_password"):
        if not payload.old_password:
            raise HTTPException(status_code=400, detail="old_password required")
        if not _verify_password(payload.old_password, user.get("password_hash") or ""):
            raise HTTPException(status_code=401, detail="Invalid current password")

    ph = _hash_password(payload.new_password)
    await db.set_user_password(pool, user["id"], ph, must_change_password=False)
    return {"ok": True}

# -----------------------------
# Analysis core
# -----------------------------
def _analyze_to_model(
    in_path: str,
    filename: Optional[str],
    role: Optional[str],
    use_case: Optional[str],
    bytes_len: int,
) -> AnalysisResult:
    sha = sha256_file(in_path)
    media_type = detect_media_type(in_path)
    tools = tool_versions() or {}

    meta = extract_exiftool(in_path) if media_type in {"image", "video", "unknown"} else {}
    ff = extract_ffprobe(in_path) if media_type in {"video", "unknown"} else {}
    c2pa = extract_c2pa(in_path)

    meta_d = meta if isinstance(meta, dict) else {}
    ff_d = ff if isinstance(ff, dict) else {}

    ai = ai_disclosure_from_metadata(meta_d)
    trans = transformation_hints(meta_d, ff_d)
    tl = derived_timeline(meta_d)
    cons = metadata_consistency(meta_d)
    prov_state, prov_summary = classify_provenance(c2pa, meta_d)

    make = meta_d.get("EXIF:Make") or meta_d.get("Make")
    model = meta_d.get("EXIF:Model") or meta_d.get("Model")
    sw = meta_d.get("EXIF:Software") or meta_d.get("XMP:CreatorTool") or meta_d.get("Software")

    extra: List[str] = []
    if make or model:
        extra.append(f"Device metadata suggests capture on: {(make or '').strip()} {(model or '').strip()}".strip())
    if sw:
        extra.append(f"Software/creator tool tag: {sw}")
    if isinstance(ai, dict) and ai.get("declared") == "POSSIBLE":
        extra.append(f"AI-related markers present in metadata: {', '.join((ai.get('signals') or [])[:6])}")
    if isinstance(trans, dict) and trans.get("screenshot_likelihood") == "HIGH":
        extra.append("Workflow hints suggest possible screenshot/screen capture.")

    summary = prov_summary + (" " + " ".join(extra) if extra else "")

    tool_list = [
        ToolStatus(
            name=k,
            available=v.get("available", False) if isinstance(v, dict) else False,
            version=v.get("version") if isinstance(v, dict) else None,
            notes=v.get("notes") if isinstance(v, dict) else None,
        )
        for k, v in tools.items()
    ]

    findings = [
        Finding(
            key="provenance_state",
            value=prov_state,
            confidence="PROVABLE" if prov_state != "UNVERIFIABLE_NO_PROVENANCE" else "INFERRED",
        ),
        Finding(
            key="device_make_model",
            value=(f"{make or ''} {model or ''}".strip() or None),
            confidence="INFERRED" if (make or model) else "UNKNOWN",
            notes=None if (make or model) else "No camera Make/Model metadata found.",
        ),
    ]

    return AnalysisResult(
        filename=filename or "upload",
        role=role,
        use_case=use_case,
        media_type=media_type,
        sha256=sha,
        bytes=bytes_len,
        provenance_state=prov_state,
        summary=summary,
        tools=tool_list,
        c2pa=c2pa,
        metadata=meta_d,
        ffprobe=ff_d,
        ai_disclosure=ai,
        transformations=trans,
        derived_timeline=tl,
        metadata_consistency=cons,
        metadata_completeness=metadata_completeness(meta_d),
        what_this_report_is=[
            "Cryptographic provenance verification when present (C2PA)",
            "Structured technical observations (metadata, encoding, workflow hints)",
            "Clear separation of provable facts, derived observations, and unknowns",
        ],
        what_this_report_is_not=[
            "A probability score of being fake",
            "A determination of authenticity or intent",
            "A detector of specific deepfake models",
        ],
        decision_context={
            "purpose": "Support financial, legal, or editorial decision-making without guessing.",
            "principle": "Separates provable facts, technical observations, and unknowns.",
        },
        what_would_make_verifiable=[
            "Capture from a C2PA-enabled camera/app",
            "Preserve the original file without re-export or platform recompression",
            "Seal media at capture inside a trusted app or device workflow",
        ],
        report_integrity={
            "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            "tools": {t.name: {"available": t.available, "version": t.version} for t in tool_list},
        },
        findings=findings,
    )

# -----------------------------
# Cases (login required)
# -----------------------------
@app.post("/cases", response_model=CaseItem)
async def create_case(
    payload: CaseCreate,
    request: Request,
    user=Depends(get_current_user_async),
    pool: Pool = Depends(get_pool),
):
    c = await db.create_case(pool, user["id"], payload.title, payload.description)
    await db.add_event(
        pool,
        case_id=c["id"],
        event_type="case.created",
        actor=user["email"],
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        details={"title": payload.title},
    )
    return c

@app.get("/cases", response_model=list[CaseItem])
async def list_cases(
    limit: int = 50,
    offset: int = 0,
    user=Depends(get_current_user_async),
    pool: Pool = Depends(get_pool),
):
    return await db.list_cases(pool, user["id"], limit=limit, offset=offset)

@app.get("/cases/{case_id}", response_model=CaseItem)
async def get_case(case_id: str, user=Depends(get_current_user_async), pool: Pool = Depends(get_pool)):
    c = await db.get_case(pool, user["id"], case_id)
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")
    return c

@app.get("/cases/{case_id}/evidence", response_model=list[EvidenceItem])
async def list_case_evidence(case_id: str, limit: int = 200, user=Depends(get_current_user_async), pool: Pool = Depends(get_pool)):
    if not await db.get_case(pool, user["id"], case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    return await db.list_evidence(pool, case_id, limit=limit)

@app.get("/cases/{case_id}/events", response_model=list[EventItem])
async def list_case_events(case_id: str, limit: int = 200, user=Depends(get_current_user_async), pool: Pool = Depends(get_pool)):
    if not await db.get_case(pool, user["id"], case_id):
        raise HTTPException(status_code=404, detail="Case not found")
    return await db.list_events(pool, case_id, limit=limit)

# -----------------------------
# Analysis (public) & PDF report (login required)
# -----------------------------
@app.post("/analyze", response_model=AnalysisResult)
async def analyze(
    request: Request,
    user: Optional[dict] = Depends(get_optional_user_async),
    file: UploadFile = File(...),
    role: str | None = Form(default=None),
    use_case: str | None = Form(default=None),
    case_id: str | None = Form(default=None),
    pool: Pool = Depends(get_pool),
):
    contents = await file.read()
    if _too_big(len(contents)):
        raise HTTPException(status_code=413, detail=f"File too large. Max {MAX_MB} MB.")

    # Guests can do quick scan, but can't attach to cases.
    if not user:
        case_id = None

    if case_id and user and not await db.get_case(pool, user["id"], case_id):
        raise HTTPException(status_code=404, detail="Case not found")

    with tempfile.TemporaryDirectory() as td:
        in_path = os.path.join(td, file.filename or "upload.bin")
        with open(in_path, "wb") as f:
            f.write(contents)

        res = _analyze_to_model(in_path, file.filename, role, use_case, bytes_len=len(contents))

        if case_id and user:
            evd = await db.add_evidence(
                pool,
                case_id=case_id,
                filename=file.filename or "upload",
                sha256=res.sha256,
                media_type=res.media_type,
                nbytes=len(contents),
                provenance_state=res.provenance_state,
                summary=res.summary,
                analysis=res.model_dump(),
            )
            await db.add_event(
                pool,
                case_id=case_id,
                event_type="evidence.analyzed",
                evidence_id=evd["id"],
                actor=user["email"],
                ip=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                details={"filename": file.filename, "sha256": res.sha256},
            )

        return res

@app.post("/report")
async def report(
    request: Request,
    background_tasks: BackgroundTasks,
    user=Depends(get_current_user_async),
    file: UploadFile = File(...),
    role: str | None = Form(default=None),
    use_case: str | None = Form(default=None),
    case_id: str | None = Form(default=None),
    pool: Pool = Depends(get_pool),
):
    tmp_in: Optional[str] = None
    tmp_pdf: Optional[str] = None

    try:
        contents = await file.read()
        if _too_big(len(contents)):
            raise HTTPException(status_code=413, detail=f"File too large. Max {MAX_MB} MB.")

        if case_id and not await db.get_case(pool, user["id"], case_id):
            raise HTTPException(status_code=404, detail="Case not found")

        suffix = os.path.splitext(file.filename or "")[-1] or ".bin"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as f:
            tmp_in = f.name
            f.write(contents)

        analysis_model = _analyze_to_model(tmp_in, file.filename, role, use_case, bytes_len=len(contents))

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as pf:
            tmp_pdf = pf.name

        try:
            from .report import build_pdf_report
        except Exception as ie:
            print("REPORT_IMPORT_ERROR:", repr(ie))
            raise HTTPException(status_code=500, detail="Report generator not available")

        payload = analysis_model.model_dump()
        build_pdf_report(payload, tmp_pdf)

        if case_id:
            evd = await db.add_evidence(
                pool,
                case_id=case_id,
                filename=file.filename or "upload",
                sha256=analysis_model.sha256,
                media_type=analysis_model.media_type,
                nbytes=len(contents),
                provenance_state=analysis_model.provenance_state,
                summary=analysis_model.summary,
                analysis=analysis_model.model_dump(),
            )
            await db.add_event(
                pool,
                case_id=case_id,
                event_type="report.generated",
                evidence_id=evd["id"],
                actor=user["email"],
                ip=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                details={"filename": file.filename, "sha256": analysis_model.sha256},
            )

        background_tasks.add_task(_cleanup_file, tmp_in)
        background_tasks.add_task(_cleanup_file, tmp_pdf)
        return FileResponse(tmp_pdf, media_type="application/pdf", filename="truthstamp-report.pdf")

    except HTTPException:
        background_tasks.add_task(_cleanup_file, tmp_in)
        background_tasks.add_task(_cleanup_file, tmp_pdf)
        raise

    except Exception as e:
        print("REPORT_GENERATION_ERROR:", repr(e))
        print(traceback.format_exc())
        background_tasks.add_task(_cleanup_file, tmp_in)
        background_tasks.add_task(_cleanup_file, tmp_pdf)
        raise HTTPException(status_code=500, detail="Report generation failed. See API logs.")

# -----------------------------
# Pilot leads (optional)
# -----------------------------
class LeadIn(BaseModel):
    email: str
    role: str | None = None
    use_case: str | None = None
    notes: str | None = None

@app.post("/lead")
async def lead(payload: LeadIn):
    try:
        line = {
            "email": (payload.email or "").strip().lower(),
            "role": payload.role,
            "use_case": payload.use_case,
            "notes": payload.notes,
            "received_at": datetime.datetime.utcnow().isoformat() + "Z",
        }
        out_dir = pathlib.Path("/tmp/truthstamp")
        out_dir.mkdir(parents=True, exist_ok=True)
        with (out_dir / "leads.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(line) + "\n")
        return {"ok": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
