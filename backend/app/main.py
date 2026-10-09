import os
import tempfile
import logging
from pathlib import Path
from datetime import datetime, timezone
from fastapi import FastAPI, UploadFile, File, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional

from app.db import check_supabase_connection
from app.traffic.models import PCAPAnalysisResult
from app.traffic.analyze_pcap import analyze_pcap_file
from app.ml.inference_service import MLInferenceEngine, get_available_sample_pcaps
from app.security import (
    SecurityHeadersMiddleware,
    get_cors_origins,
    validate_pcap_magic_bytes,
    sanitize_safe_filename,
    rate_limiter,
    MAX_UPLOAD_SIZE_BYTES,
)

logger = logging.getLogger("uniguard.api")

app = FastAPI(
    title="UNIGUARD AI - Passive Threat Intelligence API",
    description="Hardened Backend API for SIH26145 Passive Unidirectional Threat Detection Platform",
    version="0.2.0",
)

# 1. Add Defensive Security Headers Middleware
app.add_middleware(SecurityHeadersMiddleware)

# 2. Add Restricted CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)


def enforce_rate_limit(request: Request, category: str, max_requests: int = 30, window_seconds: int = 60):
    """Enforces in-memory IP-based rate limiting on sensitive and computationally heavy endpoints."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    allowed, retry_after = rate_limiter.check(client_ip, category, max_requests, window_seconds)
    if not allowed:
        logger.warning(f"Rate limit exceeded for IP {client_ip} on category '{category}'. Retry after {retry_after}s.")
        raise HTTPException(
            status_code=429,
            detail=f"Too many requests. Rate limit exceeded for {category}. Please retry in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    timestamp: str
    diode_channel: str
    database: Dict[str, Any]
    active_ml_model: str


@app.get("/")
def root():
    return {
        "message": "UNIGUARD AI Engine Online",
        "docs": "/docs",
        "health": "/api/health",
        "db_status": "/api/db/status",
        "pcap_extractor": "/api/traffic/extract-pcap",
        "pcap_analyzer": "/api/analyze/pcap",
        "model_info": "/api/ml/model-info",
        "security_profile": "SIH26145 Hardened Local & Demo Deployment",
    }


@app.get("/api/health", response_model=HealthResponse)
def get_health():
    """System health check endpoint with database connection telemetry and active ML model status."""
    db_status = check_supabase_connection()
    return HealthResponse(
        status="healthy",
        service="uniguard-ai-backend",
        version="0.2.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
        diode_channel="passive-unidirectional-standby",
        database=db_status,
        active_ml_model="Phase 3I True 4-Class Multi-Capture Detector (HistGradientBoosting + IsolationForest)",
    )



@app.get("/api/db/status")
def get_db_status():
    """Explicit database connection status check."""
    return check_supabase_connection()


@app.get("/api/ml/model-info")
def get_model_info():
    """Returns active Phase 3I ML model metadata, architecture specifications, and evaluation metrics."""
    try:
        engine = MLInferenceEngine.get_instance()
        clf_name = engine.metadata.get("supervised_algorithm", "HistGradientBoostingClassifier")
        return {
            "model_metadata": engine.metadata,
            "training_manifest": engine.manifest,
            "status": "loaded",
            "supported_classes": ["BENIGN", "DDOS", "RECON_SCAN", "C2_BEACONING"],
            "unsupported_classes": ["EXFILTRATION"],
            "feature_count": 27,
            "architecture": {
                "tier_1": f"Supervised {clf_name} (Class-Balanced)",
                "tier_2": "Unsupervised Isolation Forest Anomaly Detector (Contamination 0.02)",
                "feature_pipeline": "Deterministic Unidirectional 5-Tuple 27-Feature Extractor",
            },
        }
    except Exception as e:
        logger.error(f"Failed to load model metadata: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to load active ML model specifications.")


@app.get("/api/ml/samples")
def list_sample_pcaps():
    """Lists available authentic sample PCAP captures in backend storage."""
    return {"samples": get_available_sample_pcaps()}


@app.post("/api/analyze/pcap")
async def analyze_uploaded_pcap(
    request: Request,
    file: UploadFile = File(...),
    max_flows: int = Query(500, ge=1, le=5000, description="Max flows to evaluate (1 - 5000)"),
):
    """
    End-to-End Real ML PCAP Threat Analysis Endpoint.
    Hardened with rate limiting, file size verification, magic byte validation, and path sanitization.
    """
    enforce_rate_limit(request, "pcap_analysis", max_requests=25, window_seconds=60)

    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")

    try:
        safe_filename = sanitize_safe_filename(file.filename)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

    content = await file.read()
    file_size = len(content)

    if file_size == 0:
        raise HTTPException(status_code=400, detail="Uploaded capture file is empty (0 bytes).")

    if file_size > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Uploaded file size ({file_size / 1024 / 1024:.2f} MB) exceeds maximum allowed limit (50 MB).",
        )

    # Magic byte format validation
    if not validate_pcap_magic_bytes(content[:4]):
        raise HTTPException(
            status_code=400,
            detail="Invalid PCAP header signature. File is not a valid libpcap or pcapng network capture format.",
        )

    suffix = Path(safe_filename).suffix.lower()
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        logger.info(f"Analyzing uploaded capture '{safe_filename}' ({file_size} bytes, max_flows={max_flows})")
        engine = MLInferenceEngine.get_instance()
        result = engine.analyze_pcap(tmp_path, max_flows=max_flows)
        result["pcap_filename"] = safe_filename
        return result
    except Exception as e:
        logger.error(f"PCAP analysis failure for '{safe_filename}': {str(e)}")
        raise HTTPException(status_code=422, detail=f"PCAP analysis execution failed: {str(e)}")
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


@app.post("/api/analyze/sample-pcap")
def analyze_sample_pcap(
    request: Request,
    filename: str = Query(..., description="Filename of authentic sample PCAP in data/raw"),
    max_flows: int = Query(500, ge=1, le=5000, description="Max flows to evaluate (1 - 5000)"),
):
    """Runs end-to-end ML analysis on an authentic sample PCAP with path traversal protection."""
    enforce_rate_limit(request, "pcap_analysis", max_requests=30, window_seconds=60)

    try:
        safe_filename = sanitize_safe_filename(filename)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

    raw_dir = Path(__file__).parent.parent / "data" / "raw"
    pcap_path = (raw_dir / safe_filename).resolve()

    # Enforce path confinement strictly within raw_dir
    if not pcap_path.is_relative_to(raw_dir.resolve()) or not pcap_path.exists():
        raise HTTPException(status_code=404, detail=f"Sample PCAP capture not found: '{safe_filename}'")

    try:
        engine = MLInferenceEngine.get_instance()
        return engine.analyze_pcap(pcap_path, max_flows=max_flows)
    except Exception as e:
        logger.error(f"Sample analysis failure for '{safe_filename}': {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to analyze sample capture: {str(e)}")


@app.post("/api/traffic/extract-pcap", response_model=PCAPAnalysisResult)
async def extract_pcap_features(
    request: Request,
    file: UploadFile = File(...),
):
    """
    Passive Unidirectional Feature Extractor Endpoint (Phase 2).
    Extracts 27 canonical flow features without ML inference.
    """
    enforce_rate_limit(request, "feature_extraction", max_requests=25, window_seconds=60)

    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")

    try:
        safe_filename = sanitize_safe_filename(file.filename)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

    content = await file.read()
    file_size = len(content)

    if file_size == 0:
        raise HTTPException(status_code=400, detail="Uploaded capture file is empty.")

    if file_size > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="Uploaded file exceeds 50 MB limit.")

    if not validate_pcap_magic_bytes(content[:4]):
        raise HTTPException(status_code=400, detail="Invalid PCAP file header format.")

    suffix = Path(safe_filename).suffix.lower()
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        result = analyze_pcap_file(tmp_path)
        result.pcap_filename = safe_filename
        return result
    except Exception as e:
        logger.error(f"Feature extraction failed for '{safe_filename}': {str(e)}")
        raise HTTPException(status_code=422, detail=f"Feature extraction failed: {str(e)}")
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


@app.post("/api/stream/sample-pcap")
def stream_sample_pcap(
    request: Request,
    filename: str = Query(..., description="Filename of sample PCAP in data/raw"),
    max_packets: int = Query(200, ge=1, le=10000, description="Max packets to stream (1 - 10000)"),
):
    """
    SIH26145 Incremental Streaming Engine Endpoint.
    Processes packets in sliding chunks with bounded latency and path sanitization.
    """
    enforce_rate_limit(request, "streaming", max_requests=30, window_seconds=60)

    try:
        safe_filename = sanitize_safe_filename(filename)
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

    raw_dir = Path(__file__).parent.parent / "data" / "raw"
    pcap_path = (raw_dir / safe_filename).resolve()

    if not pcap_path.is_relative_to(raw_dir.resolve()) or not pcap_path.exists():
        raise HTTPException(status_code=404, detail=f"Sample PCAP capture not found: '{safe_filename}'")

    try:
        from app.traffic.streaming_engine import StreamingPipeline
        pipeline = StreamingPipeline()
        alerts = list(pipeline.stream_pcap(pcap_path, max_packets=max_packets))
        return {
            "pcap_filename": safe_filename,
            "packets_streamed": max_packets,
            "alerts_emitted": len(alerts),
            "alerts": alerts,
        }
    except Exception as e:
        logger.error(f"Streaming analysis failure on '{safe_filename}': {str(e)}")
        raise HTTPException(status_code=500, detail=f"Streaming analysis failed: {str(e)}")


@app.post("/api/analyze/dns-metadata")
def analyze_dns_query(
    request: Request,
    query_name: str = Query(..., max_length=255, description="Observed DNS query name"),
):
    """Metadata-only DNS DGA and Tunneling Analyzer without payload decryption."""
    enforce_rate_limit(request, "metadata_analysis", max_requests=60, window_seconds=60)
    from app.traffic.dns_analyzer import extract_dns_metadata
    return extract_dns_metadata(query_name)


@app.post("/api/analyze/tls-metadata")
def analyze_tls_session(
    request: Request,
    packet_sizes: List[int] = Query(..., description="Sequence of observed packet sizes in bytes"),
    sni: Optional[str] = Query(None, max_length=255, description="Observed SNI domain"),
    ciphers_count: int = Query(5, ge=0, le=1000, description="Count of cipher suites in ClientHello"),
):
    """Metadata-only TLS Encrypted Session Analyzer without payload decryption."""
    enforce_rate_limit(request, "metadata_analysis", max_requests=60, window_seconds=60)
    if len(packet_sizes) > 1000:
        raise HTTPException(status_code=400, detail="Packet size list length cannot exceed 1,000 elements.")
    from app.traffic.tls_analyzer import analyze_tls_metadata
    return analyze_tls_metadata(packet_sizes=packet_sizes, sni=sni, ciphers_count=ciphers_count)


