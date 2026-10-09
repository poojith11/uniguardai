import pytest
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
from app.security import (
    validate_pcap_magic_bytes,
    sanitize_safe_filename,
    InMemoryRateLimiter,
    MAX_UPLOAD_SIZE_BYTES,
)

client = TestClient(app)


def test_security_headers_present():
    """Verify defensive HTTP security headers are injected in responses."""
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert response.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
    assert "payment=()" in response.headers.get("permissions-policy", "")


def test_pcap_magic_byte_validator():
    """Verify PCAP magic byte validator accepts valid headers and rejects invalid bytes."""
    valid_pcap = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20
    valid_pcapng = b"\x0a\x0d\x0d\x0a" + b"\x00" * 20
    invalid_text = b"THIS IS NOT A PCAP FILE"
    empty = b""

    assert validate_pcap_magic_bytes(valid_pcap) is True
    assert validate_pcap_magic_bytes(valid_pcapng) is True
    assert validate_pcap_magic_bytes(invalid_text) is False
    assert validate_pcap_magic_bytes(empty) is False


def test_filename_sanitizer_and_path_traversal_prevention():
    """Verify sanitize_safe_filename rejects path traversal attempts and invalid extensions."""
    assert sanitize_safe_filename("sample.pcap") == "sample.pcap"
    assert sanitize_safe_filename("capture_2026.pcapng") == "capture_2026.pcapng"

    with pytest.raises(ValueError, match="Path traversal"):
        sanitize_safe_filename("nested/path/sample.pcapng")

    with pytest.raises(ValueError, match="Path traversal"):
        sanitize_safe_filename("../../../etc/passwd.pcap")

    with pytest.raises(ValueError, match="Unsupported file extension"):
        sanitize_safe_filename("malicious_script.sh")

    with pytest.raises(ValueError, match="empty"):
        sanitize_safe_filename("")



def test_upload_empty_file_rejected():
    """Verify uploading an empty file returns HTTP 400."""
    response = client.post(
        "/api/analyze/pcap",
        files={"file": ("empty.pcap", b"", "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "empty" in response.json().get("detail", "").lower()


def test_upload_invalid_magic_bytes_rejected():
    """Verify uploading a file with non-PCAP content returns HTTP 400."""
    fake_content = b"Plain text content that is not a valid network capture file"
    response = client.post(
        "/api/analyze/pcap",
        files={"file": ("fake.pcap", fake_content, "application/octet-stream")},
    )
    assert response.status_code == 400
    assert "header" in response.json().get("detail", "").lower() or "signature" in response.json().get("detail", "").lower()


def test_sample_pcap_path_traversal_blocked():
    """Verify attempting directory traversal on sample-pcap returns HTTP 400 or 404."""
    response = client.post("/api/analyze/sample-pcap?filename=../../../../etc/passwd.pcap")
    assert response.status_code in (400, 404)


def test_query_parameter_bounds_validation():
    """Verify invalid max_flows values outside [1, 5000] are rejected with HTTP 422."""
    response_neg = client.post("/api/analyze/sample-pcap?filename=UCAP172.31.69.25_Wed21.pcap&max_flows=0")
    assert response_neg.status_code == 422

    response_high = client.post("/api/analyze/sample-pcap?filename=UCAP172.31.69.25_Wed21.pcap&max_flows=99999")
    assert response_high.status_code == 422


def test_in_memory_rate_limiter_unit():
    """Unit test for InMemoryRateLimiter sliding window and retry calculation."""
    limiter = InMemoryRateLimiter()
    ip = "192.0.2.1"
    category = "test_endpoint"

    # Allow up to 3 requests in 10s window
    for _ in range(3):
        allowed, retry = limiter.check(ip, category, max_requests=3, window_seconds=10)
        assert allowed is True
        assert retry == 0

    # 4th request must be rate-limited
    allowed, retry = limiter.check(ip, category, max_requests=3, window_seconds=10)
    assert allowed is False
    assert retry > 0
