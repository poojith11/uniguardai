from typing import Optional, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class AlertEvidence(BaseModel):
    """Structured supporting forensic evidence for a security alert."""
    primary_signal: str = Field(..., description="Primary rule or ML feature triggering the alert")
    feature_attributions: Dict[str, Any] = Field(default_factory=dict, description="Key feature values contributing to detection")
    rule_indicators: Dict[str, Any] = Field(default_factory=dict, description="Specific threshold or heuristic signals triggered")


class SecurityAlert(BaseModel):
    """
    Standardized SIH26145 Canonical Alert Schema.
    Shared across backend ML engine, streaming pipeline, forensic evidence ledger, and UI.
    """
    alert_id: str = Field(..., description="Unique deterministic alert identifier")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="ISO-8601 UTC timestamp")
    flow_id: str = Field(..., description="Unidirectional 5-tuple flow identifier")
    
    # 5-Tuple Context
    src_ip: str = Field(..., description="Source IP address")
    dst_ip: str = Field(..., description="Destination IP address")
    src_port: Optional[int] = Field(None, description="Source Layer-4 port")
    dst_port: Optional[int] = Field(None, description="Destination Layer-4 port")
    protocol: str = Field(..., description="Protocol (TCP, UDP, ICMP, DNS, TLS, etc.)")
    
    # Threat Classification
    threat_class: str = Field(..., description="Threat class: BENIGN, DDOS, C2_BEACONING, RECON_SCAN, EXFILTRATION_RISK")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Normalized model confidence or heuristic probability score [0.0 - 1.0]")
    severity: str = Field(..., description="Severity level: LOW, MEDIUM, HIGH, CRITICAL, BENIGN")
    anomaly_score: float = Field(0.0, description="Tier 2 Isolation Forest anomaly decision score (< 0 represents outlier)")
    is_anomaly: bool = Field(False, description="Whether Tier 2 Isolation Forest flagged this flow as an anomaly outlier")
    
    # Supporting Evidence
    evidence: AlertEvidence = Field(..., description="Supporting quantitative features and rule indicators")
    sha256_hash: Optional[str] = Field(None, description="Cryptographic SHA-256 integrity hash of alert block")
