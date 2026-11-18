"""
In-App Activity Console & Live Event Stream Service (ADR-0030).
Menyediakan ring buffer telemetri in-memory, sensor kredensial otomatis (redaction),
serta pemancar Server-Sent Events (SSE) non-blocking untuk observabilitas runtime real-time.
"""

import asyncio
import json
import re
import secrets
from collections import deque
from datetime import datetime
from typing import AsyncGenerator, Dict, List, Optional, Set

# Ring buffer in-memory berkapasitas 100 entri terbaru
MAX_RING_BUFFER = 100
_ring_buffer: deque = deque(maxlen=MAX_RING_BUFFER)
_subscribers: Set[asyncio.Queue] = set()
_lock: Optional[asyncio.Lock] = None

# Pola penyensoran kredensial sensitif otomatis (Redaction Filter ADR-0030)
REDACT_PATTERNS = [
    (re.compile(r"(password|pwd|secret|token|api_key|auth_key|bearer)\s*[:=]\s*([^\s,;]+)", re.IGNORECASE), r"\1=[REDACTED]"),
    (re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----", re.DOTALL), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"pantau_session=[a-zA-Z0-9_\.-]+"), "pantau_session=[REDACTED]"),
]


def _get_lock() -> asyncio.Lock:
    global _lock
    if _lock is None:
        _lock = asyncio.Lock()
    return _lock


def _redact_text(text: str) -> str:
    if not text or not isinstance(text, str):
        return ""
    cleaned = text
    for pattern, repl in REDACT_PATTERNS:
        cleaned = pattern.sub(repl, cleaned)
    return cleaned


def broadcast_activity(
    level: str,
    module: str,
    host: str,
    message: str,
    details: str = "",
) -> None:
    """Siarkan peristiwa runtime ke seluruh subscriber SSE aktif dan simpan dalam ring buffer."""
    now = datetime.utcnow()
    item = {
        "id": secrets.token_hex(6),
        "time": now.strftime("%H:%M:%S"),
        "timestamp": now.isoformat(),
        "level": (level or "INFO").upper(),
        "module": (module or "SYSTEM").upper(),
        "host": host or "pusat",
        "message": _redact_text(message),
        "details": _redact_text(details),
    }

    _ring_buffer.append(item)

    # Sebarkan ke antrian subscriber secara non-blocking
    dead_queues = []
    for q in _subscribers:
        try:
            if q.qsize() >= 50:
                try:
                    q.get_nowait()
                except Exception:
                    pass
            q.put_nowait(item)
        except Exception:
            dead_queues.append(q)

    for dq in dead_queues:
        _subscribers.discard(dq)


def get_recent_activities(limit: int = 50) -> List[Dict]:
    """Ambil riwayat aktivitas terbaru dari ring buffer."""
    items = list(_ring_buffer)
    return items[-limit:]


async def subscribe_activities() -> AsyncGenerator[str, None]:
    """Generator Server-Sent Events (SSE) untuk browser client."""
    q: asyncio.Queue = asyncio.Queue(maxsize=60)
    lock = _get_lock()
    async with lock:
        _subscribers.add(q)

    try:
        # Kirim event koneksi awal (Handshake)
        handshake = {
            "type": "init",
            "connected_at": datetime.utcnow().strftime("%H:%M:%S"),
            "recent": get_recent_activities(30),
        }
        yield f"event: init\ndata: {json.dumps(handshake, ensure_ascii=False)}\n\n"

        while True:
            try:
                # Tunggu event baru dengan timeout heartbeat tiap 15 detik
                item = await asyncio.wait_for(q.get(), timeout=15.0)
                yield f"event: activity\ndata: {json.dumps(item, ensure_ascii=False)}\n\n"
            except asyncio.TimeoutError:
                # Kirim heartbeat ping agar koneksi tetap hidup melalui proxy / load balancer
                yield ": ping\n\n"
    except (asyncio.CancelledError, GeneratorExit):
        pass
    finally:
        async with lock:
            _subscribers.discard(q)
