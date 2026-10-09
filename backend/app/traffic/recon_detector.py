from typing import Dict, Any, List, Set
from collections import defaultdict
from pydantic import BaseModel, Field
from app.traffic.models import FlowFeatures


class ReconScanSignal(BaseModel):
    """Reconnaissance / Port Scanning / Host Sweep Indicators."""
    is_recon_signal: bool = Field(False, description="Whether flow/host exhibits reconnaissance scan characteristics")
    confidence: float = Field(0.0, description="Recon heuristic confidence score [0.0 - 1.0]")
    is_syn_probe: bool = Field(False, description="Single SYN probe with 0 ACK feedback")
    is_bruteforce_port: bool = Field(False, description="Targeting sensitive administrative/brute force ports (22, 21, 3389, 445)")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Supporting quantitative features")


def evaluate_recon_signal(features: FlowFeatures) -> ReconScanSignal:
    """
    Evaluates port scan, host sweep, and service brute-force indicators.
    Scanners typically emit single-packet SYN probes across many ports/hosts with minimal packet counts.
    """
    pkt_count = features.packet_count
    syn_count = features.syn_count
    ack_count = features.ack_count
    dst_port = features.dst_port

    sensitive_ports = {21, 22, 23, 80, 443, 445, 1433, 3306, 3389, 8080}
    is_bruteforce_port = dst_port in sensitive_ports if dst_port else False

    is_syn_probe = (pkt_count <= 3 and syn_count >= 1 and ack_count == 0)
    is_fast_sweep = (pkt_count <= 5 and features.duration_seconds < 1.0 and is_bruteforce_port)

    confidence = 0.0
    if is_syn_probe and is_bruteforce_port:
        confidence = 0.90
    elif is_syn_probe:
        confidence = 0.80
    elif is_fast_sweep:
        confidence = 0.70

    is_recon = confidence >= 0.70

    evidence = {
        "packet_count": pkt_count,
        "syn_count": syn_count,
        "ack_count": ack_count,
        "dst_port": dst_port,
        "is_syn_probe": is_syn_probe,
        "is_bruteforce_port": is_bruteforce_port,
        "duration_seconds": round(features.duration_seconds, 4),
    }

    return ReconScanSignal(
        is_recon_signal=is_recon,
        confidence=confidence,
        is_syn_probe=is_syn_probe,
        is_bruteforce_port=is_bruteforce_port,
        evidence=evidence,
    )
