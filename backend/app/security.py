import os
import time
import logging
import threading
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

logger = logging.getLogger("uniguard.security")

# Maximum upload limit: 50 Megabytes to prevent DoS / Memory exhaustion
MAX_UPLOAD_SIZE_BYTES = 50 * 1024 * 1024

# Allowed capture extensions
ALLOWED_EXTENSIONS: Set[str] = {".pcap", ".pcapng", ".cap"}

# Magic byte signatures for PCAP and PCAPNG
PCAP_MAGIC_SIGNATURES: Set[bytes] = {
    b"\xd4\xc3\xb2\xa1",  # Standard PCAP (microsecond)
    b"\xa1\xb2\xc3\xd4",  # Byte-swapped PCAP
    b"\x4d\x3c\xb2\xa1",  # Nanosecond PCAP
    b"\xa1\xb2\x3c\x4d",  # Byte-swapped Nanosecond PCAP
    b"\x0a\x0d\x0d\x0a",  # PCAPNG Section Header Block
}

# Default allowed development/demo origins
DEFAULT_CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]


def get_cors_origins() -> List[str]:
    """Retrieves configured CORS origins from ALLOWED_ORIGINS or CORS_ORIGINS, defaulting to local hosts."""
    custom = os.getenv("ALLOWED_ORIGINS", "").strip() or os.getenv("CORS_ORIGINS", "").strip()
    if custom:
        origins = [orig.strip() for orig in custom.split(",") if orig.strip()]
        # Preserve default dev origins alongside custom domains if specified
        for dev_orig in DEFAULT_CORS_ORIGINS:
            if dev_orig not in origins:
                origins.append(dev_orig)
        return origins
    return DEFAULT_CORS_ORIGINS



def validate_pcap_magic_bytes(header: bytes) -> bool:
    """
    Validates that the first 4 bytes match a recognized PCAP or PCAPNG file format magic number.
    Rejects arbitrary text, scripts, or non-capture binaries.
    """
    if len(header) < 4:
        return False
    return header[:4] in PCAP_MAGIC_SIGNATURES


def sanitize_safe_filename(filename: str) -> str:
    """
    Sanitizes user-provided filename to prevent directory traversal attacks (e.g. '../../etc/passwd').
    Ensures filename is strictly a plain basename without path separators or traversal sequences.
    """
    if not filename or not filename.strip():
        raise ValueError("Filename cannot be empty")

    raw = filename.strip()
    # Reject any directory traversal tokens or path separators
    if ".." in raw or "/" in raw or "\\" in raw or raw.startswith("."):
        raise ValueError("Path traversal sequences and hidden files are strictly prohibited")

    base = Path(raw).name.strip()
    suffix = Path(base).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Unsupported file extension '{suffix}'. Allowed: {', '.join(ALLOWED_EXTENSIONS)}")

    return base



class InMemoryRateLimiter:
    """
    Thread-safe, sliding-window in-memory rate limiter for demo and single-instance deployments.
    Tracks request timestamps per client IP and endpoint category.
    """
    def __init__(self, cleanup_interval_seconds: float = 300.0):
        self._lock = threading.Lock()
        self._buckets: Dict[str, List[float]] = {}
        self._last_cleanup = time.time()
        self._cleanup_interval = cleanup_interval_seconds

    def check(self, client_ip: str, category: str, max_requests: int, window_seconds: int = 60) -> Tuple[bool, int]:
        """
        Checks if the client is within rate limits.
        Returns: (is_allowed: bool, retry_after_seconds: int)
        """
        now = time.time()
        key = f"{client_ip}:{category}"

        with self._lock:
            # Periodic cleanup of stale entries
            if now - self._last_cleanup > self._cleanup_interval:
                self._cleanup(now)

            timestamps = self._buckets.get(key, [])
            cutoff = now - window_seconds
            valid_timestamps = [ts for ts in timestamps if ts > cutoff]

            if len(valid_timestamps) >= max_requests:
                earliest = valid_timestamps[0]
                retry_after = max(1, int(earliest + window_seconds - now))
                self._buckets[key] = valid_timestamps
                return False, retry_after

            valid_timestamps.append(now)
            self._buckets[key] = valid_timestamps
            return True, 0

    def _cleanup(self, now: float):
        """Removes expired timestamp buckets."""
        expired_keys = []
        for key, timestamps in self._buckets.items():
            valid = [ts for ts in timestamps if now - ts < 300]
            if not valid:
                expired_keys.append(key)
            else:
                self._buckets[key] = valid
        for k in expired_keys:
            del self._buckets[k]
        self._last_cleanup = now


# Global singleton instance
rate_limiter = InMemoryRateLimiter()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Injects standard defensive HTTP security headers to protect against clickjacking,
    MIME sniffing, and untrusted cross-origin framing.
    """
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=()"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response
