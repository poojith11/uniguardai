from typing import Dict, Any, List
from pydantic import BaseModel, Field
from app.traffic.models import FlowFeatures


class DDoSStatisticalSignal(BaseModel):
    """Statistical DDoS Volumetric & Protocol Indicators."""
    is_ddos_signal: bool = Field(False, description="Whether statistical heuristics flag DDoS attack activity")
    confidence: float = Field(0.0, description="DDoS heuristic confidence score [0.0 - 1.0]")
    pps: float = Field(0.0, description="Packets per second rate")
    bps: float = Field(0.0, description="Bytes per second rate")
    syn_ratio: float = Field(0.0, description="TCP SYN flag ratio")
    is_syn_flood: bool = Field(False, description="Whether flow exhibits TCP SYN flood characteristics")
    is_volumetric_flood: bool = Field(False, description="Whether flow exceeds volumetric flood thresholds")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Supporting quantitative features")


def evaluate_ddos_signal(features: FlowFeatures) -> DDoSStatisticalSignal:
    """
    Evaluates volumetric and protocol-level DDoS signals without payload inspection.
    Detects SYN floods, UDP amplification, and high-rate volumetric floods.
    """
    pps = features.packets_per_second
    bps = features.bytes_per_second
    syn_ratio = features.syn_ratio
    pkt_count = features.packet_count

    is_syn_flood = (syn_ratio > 0.85 and pkt_count >= 10 and features.ack_ratio < 0.15)
    is_volumetric = (pps > 1500.0 or (bps > 500_000.0 and pkt_count > 50))
    is_loic_http_flood = (features.dst_port in (80, 8080, 443) and pps > 20.0 and features.packet_count > 15)

    confidence = 0.0
    if is_syn_flood:
        confidence = max(confidence, 0.95)
    if is_volumetric:
        confidence = max(confidence, 0.85)
    if is_loic_http_flood:
        confidence = max(confidence, 0.75)

    is_ddos = confidence >= 0.70

    evidence = {
        "packets_per_second": round(pps, 2),
        "bytes_per_second": round(bps, 2),
        "syn_ratio": round(syn_ratio, 4),
        "packet_count": pkt_count,
        "is_syn_flood": is_syn_flood,
        "is_volumetric_flood": is_volumetric,
        "is_loic_http_flood": is_loic_http_flood,
    }

    return DDoSStatisticalSignal(
        is_ddos_signal=is_ddos,
        confidence=confidence,
        pps=round(pps, 2),
        bps=round(bps, 2),
        syn_ratio=round(syn_ratio, 4),
        is_syn_flood=is_syn_flood,
        is_volumetric_flood=is_volumetric,
        evidence=evidence,
    )
