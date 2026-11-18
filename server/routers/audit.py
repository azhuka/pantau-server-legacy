"""Audit logs and application dashboard logs router."""

import os
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

try:
    from config import settings
    from models import Server, User
    from core.database import get_db
    from core.security import get_current_user, require_user, filter_servers_for_user
    from core.templates import tpl
    from services.audit_service import (
        AUDIT_ACTION_LABELS,
        AUDIT_CATEGORIES,
        _audit_rows,
        tail_lines,
    )
except ImportError:
    from server.config import settings
    from server.models import Server, User
    from server.core.database import get_db
    from server.core.security import get_current_user, require_user, filter_servers_for_user
    from server.core.templates import tpl
    from server.services.audit_service import (
        AUDIT_ACTION_LABELS,
        AUDIT_CATEGORIES,
        _audit_rows,
        tail_lines,
    )

router = APIRouter(tags=["Audit & Logs"])


@router.get("/logs", response_class=HTMLResponse)
def logs_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if not (user.is_master_admin() or (user.allowed_server_ids is None and user.has_perm("can_audit"))):
        return RedirectResponse("/", status_code=303)
    return tpl(request, "logs.html", {"user": user, "log_file": settings.LOG_FILE})


@router.get("/api/logs/dashboard")
@router.get("/api/system/logs")
def api_logs_dashboard(
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
    lines: int = 300,
):
    if not (user.is_master_admin() or (user.allowed_server_ids is None and user.has_perm("can_audit"))):
        raise HTTPException(
            status_code=403,
            detail="Akses ditolak: Hanya Master Admin atau Operator Utama Global yang dapat mengakses log sistem host.",
        )
    lines = max(10, min(lines, 2000))
    path = settings.LOG_FILE
    last_lines = tail_lines(path, lines)
    return {
        "path": path,
        "exists": os.path.exists(path),
        "count": min(lines, len(last_lines)),
        "lines": last_lines,
    }


@router.get("/api/audit")
def api_audit(
    q: str = "",
    action: str = "",
    user: str = "",
    period: str = "24h",
    server: str = "",
    status: str = "",
    limit: int = 500,
    user_actor: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    """Endpoint JSON audit untuk SPA."""
    if not (user_actor.is_master_admin() or user_actor.has_perm("can_audit")):
        raise HTTPException(status_code=403, detail="Akses ditolak: izin audit trail diperlukan")

    user_clean = user.strip()
    period_clean = period.strip().lower()
    server_id = int(server.strip()) if server.strip().isdigit() else None
    status_clean = status.strip().upper()

    user_allowed_sids = user_actor.get_allowed_server_ids() if user_actor.allowed_server_ids is not None else None

    rows = _audit_rows(
        db,
        limit=min(limit, 1000),
        q=q,
        action=action,
        user_filter=user_clean,
        period=period_clean,
        server_id=server_id,
        status_filter=status_clean,
        allowed_server_ids=user_allowed_sids,
    )
    if not user_actor.is_master_admin():
        master_admin_names = {u.username for u in db.query(User).filter(User.role == "master_admin").all()}
        for r in rows:
            if r.get("user") in master_admin_names:
                r["user"] = "Sistem"
            target_str = str(r.get("target") or "")
            for m in master_admin_names:
                if m in target_str:
                    target_str = target_str.replace(m, "Sistem")
            if "master_admin" in target_str:
                target_str = target_str.replace("master_admin", "sistem")
            r["target"] = target_str

        if user_clean in master_admin_names:
            rows = []

        available_users = [
            u.username
            for u in db.query(User).filter(~User.role.in_(["master_admin", "admin"])).order_by(User.username).all()
        ]
    else:
        master_admin_names = set()
        available_users = [u.username for u in db.query(User).order_by(User.username).all()]

    if user_clean and user_clean not in available_users and (
        user_actor.is_master_admin() or user_clean not in master_admin_names
    ):
        available_users.append(user_clean)
        available_users.sort()

    if user_actor.allowed_server_ids is not None:
        allowed_ids = set(user_actor.get_allowed_server_ids())
        rows = [r for r in rows if r.get("server_id") is not None and r.get("server_id") in allowed_ids]

    for r in rows:
        if hasattr(r.get("created_at"), "strftime"):
            r["time_str"] = r["created_at"].strftime("%Y-%m-%d %H:%M:%S")
        elif "created_at" in r:
            r["time_str"] = str(r["created_at"])

    return {
        "rows": rows,
        "users": available_users,
    }


@router.get("/audit", response_class=HTMLResponse)
def audit_page(
    request: Request,
    db: Session = Depends(get_db),
    q: str = "",
    action: str = "",
    user: str = "",
    period: str = "",
    server: str = "",
    status: str = "",
    start_date: str = "",
    end_date: str = "",
):
    user_actor = get_current_user(request, db)
    if not user_actor:
        return RedirectResponse("/login", status_code=303)
    if not (user_actor.is_master_admin() or user_actor.has_perm("can_audit")):
        return RedirectResponse("/", status_code=303)

    user_clean = user.strip()
    period_clean = period.strip().lower()
    server_id = int(server.strip()) if server.strip().isdigit() else None
    status_clean = status.strip().upper()
    start_date_clean = start_date.strip()
    end_date_clean = end_date.strip()

    user_allowed_sids = user_actor.get_allowed_server_ids() if user_actor.allowed_server_ids is not None else None

    rows = _audit_rows(
        db,
        limit=500,
        q=q,
        action=action,
        user_filter=user_clean,
        period=period_clean,
        server_id=server_id,
        status_filter=status_clean,
        start_date=start_date_clean,
        end_date=end_date_clean,
        allowed_server_ids=user_allowed_sids,
    )
    if not user_actor.is_master_admin():
        master_admin_names = {u.username for u in db.query(User).filter(User.role == "master_admin").all()}
        for r in rows:
            if r.get("user") in master_admin_names:
                r["user"] = "Sistem"
            target_str = str(r.get("target") or "")
            for m in master_admin_names:
                if m in target_str:
                    target_str = target_str.replace(m, "Sistem")
            if "master_admin" in target_str:
                target_str = target_str.replace("master_admin", "sistem")
            r["target"] = target_str

        if user_clean in master_admin_names:
            rows = []

        available_users = [
            u.username
            for u in db.query(User).filter(~User.role.in_(["master_admin", "admin"])).order_by(User.username).all()
        ]
    else:
        available_users = [u.username for u in db.query(User).order_by(User.username).all()]

    if user_clean and user_clean not in available_users and (
        user_actor.is_master_admin() or user_clean not in master_admin_names
    ):
        available_users.append(user_clean)
        available_users.sort()

    if user_actor.allowed_server_ids is not None:
        allowed_ids = set(user_actor.get_allowed_server_ids())
        rows = [r for r in rows if r.get("server_id") is not None and r.get("server_id") in allowed_ids]

    all_servers = filter_servers_for_user(db.query(Server), user_actor).order_by(Server.hostname).all()

    st_cls = {
        "SUCCESS": "up",
        "FAILED": "danger",
        "PENDING": "muted",
        "EXECUTING": "warn",
    }
    st_label = {
        "SUCCESS": "BERHASIL",
        "FAILED": "GAGAL",
        "PENDING": "MENUNGGU",
        "EXECUTING": "PROSES",
    }

    return tpl(
        request,
        "audit.html",
        {
            "user": user_actor,
            "rows": rows,
            "q": q,
            "action": action,
            "period": period_clean,
            "selected_user": user_clean,
            "selected_server": server_id,
            "selected_status": status_clean,
            "start_date": start_date_clean,
            "end_date": end_date_clean,
            "all_servers": all_servers,
            "available_users": available_users,
            "categories": AUDIT_CATEGORIES,
            "actions": sorted(AUDIT_ACTION_LABELS.items()),
            "st_cls": st_cls,
            "st_label": st_label,
        },
    )


# ---------------------------------------------------------------------------
# IN-APP ACTIVITY CONSOLE & LIVE EVENT STREAM (ADR-0030)
# ---------------------------------------------------------------------------
from fastapi.responses import StreamingResponse

try:
    from services.activity_stream import subscribe_activities, get_recent_activities
except ImportError:
    from server.services.activity_stream import subscribe_activities, get_recent_activities


@router.get("/api/activity/stream")
async def api_activity_stream(user: User = Depends(require_user)):
    """SSE endpoint untuk langganan event telemetri operasional real-time."""
    return StreamingResponse(
        subscribe_activities(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/api/activity/recent")
def api_activity_recent(limit: int = 50, user: User = Depends(require_user)):
    """Mengambil 50 aktivitas terbaru dari in-memory ring buffer untuk bootstrap drawer."""
    limit = max(5, min(limit, 100))
    return {"activities": get_recent_activities(limit)}
