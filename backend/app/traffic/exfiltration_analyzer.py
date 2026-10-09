from typing import Dict, Any
from pydantic import BaseModel, Field
from app.traffic.models import FlowFeatures


class ExfiltrationRiskSignal(BaseModel):
    """Metadata-only heuristic indicators for potential data exfiltration."""
    is_exfiltration_risk: bool = Field(False, description="Whether flow exhibits suspicious volumetric outbound exfiltration traits")
    confidence: float = Field(0.0, description="Heuristic risk score [0.0 - 1.0]")
    byte_count: int = Field(0, description="Total byte volume transferred")
    bytes_per_second: float = Field(0.0, description="Outbound transfer rate")
    duration_seconds: float = Field(0.0, description="Flow duration in seconds")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Supporting quantitative features")


def evaluate_exfiltration_risk(features: FlowFeatures) -> ExfiltrationRiskSignal:
    """
    Evaluates metadata-only heuristic indicators for data exfiltration without payload inspection.
    Exfiltration patterns: High outbound volume to non-standard external destination with sustained throughput.
    """
    bytes_total = features.byte_count
    duration = features.duration_seconds
    bps = features.bytes_per_second
    dst_port = features.dst_port

    # Non-standard port with high outbound data volume
    is_large_transfer = bytes_total > 500_000 and duration > 5.0
    is_non_standard_egress = dst_port not in (80, 443, 8080) if dst_port else False

    confidence = 0.0
    if is_large_transfer and is_non_standard_egress:
        confidence = 0.85
    elif is_large_transfer:
        confidence = 0.65
    elif bytes_total > 200_000 and bps > 50_000:
        confidence = 0.50

    is_risk = confidence >= 0.60

    evidence = {
        "byte_count": bytes_total,
        "duration_seconds": round(duration, 2),
        "bytes_per_second": round(bps, 2),
        "dst_port": dst_port,
        "is_large_transfer": is_large_transfer,
        "is_non_standard_egress": is_non_standard_egress,
    }

    return ExfiltrationRiskSignal(
        is_exfiltration_risk=is_risk,
        confidence=confidence,
        byte_count=bytes_total,
        bytes_per_second=round(bps, 2),
        duration_seconds=round(duration, 2),
        evidence=evidence,
    )
