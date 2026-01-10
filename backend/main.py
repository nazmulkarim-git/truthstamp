from __future__ import annotations
import os
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
import tempfile
from fastapi import FastAPI, Depends, HTTPException, Request, UploadFile, File, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from backend import db, engine
from backend.utils import sha256_file
import jwt

ADMIN_HEADER = "x-admin-key"

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
JWT_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "168"))  # 7 days default

bearer = HTTPBearer(auto_error=False)


def make_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=JWT_EXPIRE_HOURS)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


async def require_user(
    pool,
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
):
    if not creds or not creds.credentials:
        raise HTTPException(status_code=401, detail="Missing token")

    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = await db.get_user_by_id(pool, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="User disabled")

    if not user.get("is_approved", False):
        # frontend clears token on 401; we prefer 403 so it can show a message if you want
        raise HTTPException(status_code=403, detail="User not approved yet")

    return user

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def require_admin(request: Request) -> None:
    expected = os.getenv("TRUTHSTAMP_ADMIN_API_KEY", "")
    got = request.headers.get(ADMIN_HEADER, "")
    if not expected or got != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")


class EnableByEmail(BaseModel):
    email: EmailStr
    is_active: Optional[bool] = None
    is_approved: Optional[bool] = None


class SendTempPasswordReq(BaseModel):
    email: EmailStr

class RegisterReq(BaseModel):
    name: str
    email: EmailStr
    phone: Optional[str] = None
    occupation: Optional[str] = None
    company: Optional[str] = None
    use_case: Optional[str] = None
    role: Optional[str] = None
    notes: Optional[str] = None


class LoginReq(BaseModel):
    email: EmailStr
    password: str


class ChangePasswordReq(BaseModel):
    old_password: Optional[str] = None
    new_password: str


app = FastAPI(title="TruthStamp API", version="1.0.0")


# CORS
cors_origins = os.getenv("CORS_ORIGINS", "")
origins = [o.strip() for o in cors_origins.split(",") if o.strip()] or ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def _startup():
    app.state.pool = await db.create_pool()
    await db.init_db(app.state.pool)


@app.on_event("shutdown")
async def _shutdown():
    pool = getattr(app.state, "pool", None)
    if pool:
        await pool.close()


async def get_pool():
    pool = getattr(app.state, "pool", None)
    if not pool:
        raise HTTPException(status_code=500, detail="DB pool not initialized")
    return pool


@app.get("/health")
async def health():
    return {"ok": True}


# -----------------------
# Admin endpoints
# -----------------------

@app.get("/admin/overview")
async def admin_overview(request: Request, pool=Depends(get_pool)):
    require_admin(request)
    counts = await db.counts_overview(pool)
    return {"ok": True, "counts": counts}


@app.get("/admin/pending-users")
async def admin_pending_users(request: Request, pool=Depends(get_pool)):
    require_admin(request)
    return await db.list_pending_users(pool, limit=500)


@app.get("/admin/users")
async def admin_users(request: Request, status: str = "all", pool=Depends(get_pool)):
    require_admin(request)
    return await db.list_users(pool, status=status, limit=500)


@app.get("/admin/cases")
async def admin_cases(request: Request, pool=Depends(get_pool)):
    require_admin(request)
    return await db.list_cases(pool, user_id=None, limit=500)


@app.post("/admin/users/enable-by-email")
async def admin_enable_user_by_email(
    request: Request,
    req: EnableByEmail,
    pool=Depends(get_pool),
):
    require_admin(request)

    user = await db.get_user_by_email(pool, req.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update flags if provided
    if req.is_active is not None:
        await db.set_user_active(pool, user["id"], bool(req.is_active))

    if req.is_approved is not None:
        await db.set_user_approved(pool, user["id"], bool(req.is_approved))

    return {"ok": True}


@app.post("/admin/users/send-temp-password")
async def admin_send_temp_password(
    request: Request,
    req: SendTempPasswordReq,
    pool=Depends(get_pool),
):
    """
    Generates a temporary password, sets must_change_password=true,
    updates password_hash, and emails it (if SMTP configured).

    If SMTP is not configured, returns temp_password in response
    (so you can manually send it).
    """
    require_admin(request)

    user = await db.get_user_by_email(pool, req.email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    temp_password = db.generate_temp_password()
    await db.set_user_temp_password(pool, user_id=user["id"], temp_password=temp_password)

    # Try email (optional)
    sent = await db.try_send_email(
        to_email=req.email,
        subject="TruthStamp: Your temporary password",
        body=(
            "Your TruthStamp account has a temporary password.\n\n"
            f"Email: {req.email}\n"
            f"Temporary password: {temp_password}\n\n"
            "Please log in and change your password immediately.\n"
        ),
    )

    # If SMTP isn’t configured, we return it so you can manually send
    if not sent:
        return {"ok": True, "temp_password": temp_password}

    return {"ok": True}


# -----------------------
# (Optional) Auth endpoints
# -----------------------
# Keep your existing auth routes if you already have them in your project.
# This file focuses on fixing deploy + admin + temp password workflow.

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    # Save upload to a temp file (engine functions expect a filesystem path)
    suffix = ""
    if file.filename:
        _, ext = os.path.splitext(file.filename)
        suffix = ext or ""

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp_path = tmp.name
            content = await file.read()
            tmp.write(content)

        size_bytes = os.path.getsize(tmp_path)
        sha256 = sha256_file(tmp_path)

        media_type = engine.detect_media_type(tmp_path)
        metadata = engine.extract_exiftool(tmp_path)
        ffprobe = engine.extract_ffprobe(tmp_path) if media_type.startswith("video/") else {}
        c2pa = engine.extract_c2pa(tmp_path)

        ai_disclosure = engine.ai_disclosure_from_metadata(metadata)
        transformations = engine.transformation_hints(metadata, ffprobe)
        provenance_state, summary = engine.classify_provenance(c2pa, metadata)

        findings = []

        # Helpful “findings” based on what the engine reports
        if isinstance(c2pa, dict) and c2pa.get("_status") == "missing_c2patool":
            findings.append({
                "title": "C2PA verifier not available on server",
                "severity": "LOW",
                "detail": "The API server does not have c2patool installed, so cryptographic provenance cannot be verified."
            })

        if isinstance(metadata, dict) and metadata.get("_status") == "missing_exiftool":
            findings.append({
                "title": "EXIF extractor not available on server",
                "severity": "LOW",
                "detail": "The API server does not have exiftool installed, so metadata signals may be incomplete."
            })

        return {
            "filename": file.filename or "upload",
            "media_type": media_type,
            "sha256": sha256,
            "bytes": size_bytes,
            "provenance_state": provenance_state,
            "summary": summary,
            "ai_disclosure": ai_disclosure,
            "transformations": transformations,
            "findings": findings,
            "c2pa": c2pa,
            "metadata": metadata,
            "ffprobe": ffprobe,
        }

    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
            

@app.post("/auth/register")
async def auth_register(req: RegisterReq, pool=Depends(get_pool)):
    # prevent duplicates
    existing = await db.get_user_by_email(pool, req.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    extras = {
        "use_case": req.use_case,
        "role": req.role,
        "notes": req.notes,
    }

    _ = await db.create_user_request(
        pool,
        name=req.name,
        email=req.email,
        phone=req.phone,
        occupation=req.occupation,
        company=req.company,
        extras=extras,
    )

    # frontend just needs ok: true
    return {"ok": True}


@app.post("/auth/login")
async def auth_login(req: LoginReq, pool=Depends(get_pool)):
    user = await db.get_user_by_email(pool, req.email)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="User disabled")

    if not user.get("is_approved", False):
        raise HTTPException(status_code=403, detail="Not approved yet")

    if not db.verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = make_token(str(user["id"]))
    # match frontend expectation: {token, user}
    return {
        "token": token,
        "user": {
            "id": str(user["id"]),
            "email": user["email"],
            "name": user.get("name"),
            "must_change_password": bool(user.get("must_change_password")),
            "is_approved": bool(user.get("is_approved")),
            "is_active": bool(user.get("is_active")),
        },
    }


@app.get("/auth/me")
async def auth_me(pool=Depends(get_pool), creds: HTTPAuthorizationCredentials | None = Depends(bearer)):
    user = await require_user(pool, creds)
    return {
        "id": str(user["id"]),
        "email": user["email"],
        "name": user.get("name"),
        "must_change_password": bool(user.get("must_change_password")),
        "is_approved": bool(user.get("is_approved")),
        "is_active": bool(user.get("is_active")),
    }

@app.post("/auth/change-password")
async def auth_change_password(
    req: ChangePasswordReq,
    pool=Depends(get_pool),
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
):
    user = await require_user(pool, creds)

    # If user is not in "must change" mode, require old password
    if not user.get("must_change_password", False):
        if not req.old_password:
            raise HTTPException(status_code=400, detail="Old password required")
        if not db.verify_password(req.old_password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")

    await db.set_user_password(pool, str(user["id"]), req.new_password)
    return {"ok": True}