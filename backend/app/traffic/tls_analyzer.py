from typing import Optional, List, Dict, Any
import numpy as np
from pydantic import BaseModel, Field


class TLSSessionMetadata(BaseModel):
    """Metadata extracted exclusively from unencrypted TLS/QUIC handshakes without payload decryption."""
    sni: Optional[str] = Field(None, description="Server Name Indication from unencrypted ClientHello")
    tls_version: Optional[str] = Field(None, description="Observed TLS version (e.g. TLSv1.2, TLSv1.3)")
    cipher_suites_offered_count: int = Field(0, description="Count of cipher suites offered by client")
    extensions_count: int = Field(0, description="Count of TLS extensions in ClientHello")
    packet_size_variance: float = Field(0.0, description="Statistical variance of initial packet sizes")
    initial_packet_sizes: List[int] = Field(default_factory=list, description="Sequence of initial packet sizes")
    is_malware_session_suspect: bool = Field(False, description="Whether encrypted session matches malware fingerprint patterns")
    malware_risk_score: float = Field(0.0, description="Calculated encrypted malware risk score [0.0 - 1.0]")


def analyze_tls_metadata(
    packet_sizes: List[int],
    sni: Optional[str] = None,
    tls_version: Optional[str] = None,
    ciphers_count: int = 0,
    exts_count: int = 0,
) -> TLSSessionMetadata:
    """
    Extracts and evaluates metadata-only behavioral fingerprint of an encrypted session without payload decryption.
    Analyzes packet-size sequences, client cipher offering profiles, and SNI domain attributes.
    """
    if packet_sizes:
        var = float(np.var(packet_sizes))
        first_few = packet_sizes[:6]
    else:
        var = 0.0
        first_few = []

    risk_score = 0.0

    # Suspicious indicator 1: Low cipher count (< 4) in modern TLS ClientHello
    if 0 < ciphers_count < 4:
        risk_score += 0.35

    # Suspicious indicator 2: No SNI or direct raw IP SNI in HTTPS session
    if sni and sni.replace(".", "").isdigit():
        risk_score += 0.40
    elif not sni and ciphers_count > 0:
        risk_score += 0.20

    # Suspicious indicator 3: Low packet size variance in early flow (fixed size C2 beacon exchanges)
    if len(first_few) >= 4 and var < 150.0:
        risk_score += 0.30

    risk_score = min(1.0, round(risk_score, 4))
    is_suspect = risk_score >= 0.50

    return TLSSessionMetadata(
        sni=sni,
        tls_version=tls_version or "TLSv1.3",
        cipher_suites_offered_count=ciphers_count,
        extensions_count=exts_count,
        packet_size_variance=round(var, 2),
        initial_packet_sizes=first_few,
        is_malware_session_suspect=is_suspect,
        malware_risk_score=risk_score,
    )
