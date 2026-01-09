from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from backend import db


ADMIN_HEADER = "x-admin-key"


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
