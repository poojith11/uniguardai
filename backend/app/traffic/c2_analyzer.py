from typing import Dict, Any, List
from pydantic import BaseModel, Field
from app.traffic.models import FlowFeatures


class C2BeaconingSignal(BaseModel):
    """C2 Periodic Beaconing Temporal Indicators."""
    is_c2_signal: bool = Field(False, description="Whether flow exhibits C2 periodic beaconing characteristics")
    confidence: float = Field(0.0, description="C2 heuristic confidence score [0.0 - 1.0]")
    mean_iat_seconds: float = Field(0.0, description="Mean packet inter-arrival time")
    iat_jitter_seconds: float = Field(0.0, description="Inter-arrival timing jitter (low indicates strict timer)")
    burstiness_ratio: float = Field(0.0, description="Flow burstiness ratio")
    is_periodic_interval: bool = Field(False, description="Whether inter-arrival times are strictly periodic")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Supporting quantitative features")


def evaluate_c2_signal(features: FlowFeatures) -> C2BeaconingSignal:
    """
    Evaluates temporal periodicity, low inter-arrival jitter, and repeated connection patterns.
    C2 beaconing channels (e.g. Cobalt Strike, Ares, Neris) communicate on fixed timer intervals with low jitter.
    """
    iat_mean = features.mean_iat_seconds
    iat_jitter = features.iat_jitter_seconds
    burstiness = features.burstiness_ratio
    pkt_count = features.packet_count
    duration = features.duration_seconds

    # Suspicious indicator: Regular interval with minimal jitter and low packet count per burst
    is_periodic = (pkt_count >= 4 and iat_jitter < 0.15 and iat_mean > 0.05)
    is_heartbeat = (duration > 5.0 and pkt_count < 30 and burstiness < 0.35)

    confidence = 0.0
    if is_periodic:
        confidence = max(confidence, 0.85)
    if is_heartbeat:
        confidence = max(confidence, 0.75)

    is_c2 = confidence >= 0.70

    evidence = {
        "mean_iat_seconds": round(iat_mean, 4),
        "iat_jitter_seconds": round(iat_jitter, 4),
        "burstiness_ratio": round(burstiness, 4),
        "packet_count": pkt_count,
        "duration_seconds": round(duration, 2),
        "is_periodic_interval": is_periodic,
        "is_heartbeat": is_heartbeat,
    }

    return C2BeaconingSignal(
        is_c2_signal=is_c2,
        confidence=confidence,
        mean_iat_seconds=round(iat_mean, 4),
        iat_jitter_seconds=round(iat_jitter, 4),
        burstiness_ratio=round(burstiness, 4),
        is_periodic_interval=is_periodic,
        evidence=evidence,
    )
