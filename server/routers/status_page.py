"""
Public Status Page Router (ADR-0038).
Menyediakan endpoint mandiri tanpa autentikasi (Zero-Trust Isolation)
untuk halaman status publik dan ringkasan ketersediaan 90 hari.
"""

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

try:
    from core.database import get_db
    from core.templates import render_template
    from services.status_page_service import (
        get_public_status_summary,
        status_limiter,
    )
except ImportError:
    from server.core.database import get_db
    from server.core.templates import render_template
    from server.services.status_page_service import (
        get_public_status_summary,
        status_limiter,
    )

router = APIRouter(tags=["Status Page"])


def _resolve_client_ip(request: Request) -> str:
    """Mendeteksi IP client dengan memperhatikan header proksi terpercaya."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",")]
        if parts:
            return parts[0]
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "127.0.0.1"


@router.get("/status", response_class=HTMLResponse)
async def public_status_page(request: Request, db: Session = Depends(get_db)):
    """Menyajikan antarmuka web Public Status Page mandiri tanpa login."""
    response = render_template(request, "status_page.html")
    # Strict Isolated CSP: Tidak mengizinkan external CDN atau skrip pihak ketiga
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "font-src 'self' data:; connect-src 'self';"
    )
    response.headers["Cache-Control"] = "public, max-age=60"
    return response


@router.get("/api/status-page/summary")
async def public_status_summary(
    request: Request,
    if_none_match: str | None = Header(None),
    refresh: int = 0,
    db: Session = Depends(get_db),
):
    """
    Mengembalikan data ketersediaan (uptime) 90 hari, status global,
    dan pengumuman insiden aktif dalam format JSON yang telah disanitasi mutlak (Masked).
    """
    client_ip = _resolve_client_ip(request)
    if not status_limiter.allow(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Batas laju permintaan terlampaui. Silakan coba kembali dalam beberapa detik.",
            headers={"Retry-After": "60"},
        )

    force = bool(refresh)
    data, raw_json, etag = get_public_status_summary(db=db, force_refresh=force)

    # Verifikasi ETag untuk efisiensi HTTP 304 Not Modified
    if if_none_match and if_none_match.strip() == etag:
        return Response(
            status_code=status.HTTP_304_NOT_MODIFIED,
            headers={
                "ETag": etag,
                "Cache-Control": "public, max-age=15, stale-while-revalidate=30",
            },
        )

    return Response(
        content=raw_json,
        media_type="application/json; charset=utf-8",
        headers={
            "ETag": etag,
            "Cache-Control": "public, max-age=15, stale-while-revalidate=30",
        },
    )
