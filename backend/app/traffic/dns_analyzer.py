import math
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class DNSMetadataFeatures(BaseModel):
    """Metadata-only extracted features from unencrypted DNS packet queries."""
    query_name: str = Field(..., description="Observed DNS query name (e.g. evil-botnet.dga.net)")
    query_length: int = Field(0, description="Length of query string in characters")
    shannon_entropy: float = Field(0.0, description="Shannon character entropy of domain name")
    subdomain_depth: int = Field(0, description="Number of dot-separated subdomain labels")
    digit_ratio: float = Field(0.0, description="Ratio of numerical digits to total characters")
    vowel_ratio: float = Field(0.0, description="Ratio of vowels to total letters")
    dga_risk_score: float = Field(0.0, description="Calculated DGA anomaly risk score [0.0 - 1.0]")
    is_dga_suspect: bool = Field(False, description="Whether query matches DGA algorithm characteristics")
    is_tunneling_suspect: bool = Field(False, description="Whether query exhibits DNS tunneling characteristics")


def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy of character frequency in a string."""
    if not text:
        return 0.0
    text_clean = text.lower().replace(".", "").replace("-", "")
    if not text_clean:
        return 0.0
    length = len(text_clean)
    counts = {}
    for c in text_clean:
        counts[c] = counts.get(c, 0) + 1
    entropy = -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values())
    return round(entropy, 4)


def extract_dns_metadata(query_name: str) -> DNSMetadataFeatures:
    """
    Extracts deterministic numerical metadata from a DNS query name without payload decryption.
    Analyzes DGA characteristics (random character sequences) and DNS tunneling (high-length, high-entropy subdomain exfiltration).
    """
    q = query_name.strip().rstrip(".").lower()
    q_len = len(q)
    entropy = calculate_shannon_entropy(q)
    labels = q.split(".")
    subdomain_depth = len(labels)

    # Calculate digit and vowel ratios
    num_digits = sum(1 for c in q if c.isdigit())
    digit_ratio = round(num_digits / max(1, q_len), 4)

    letters = [c for c in q if c.isalpha()]
    vowels = sum(1 for c in letters if c in "aeiou")
    vowel_ratio = round(vowels / max(1, len(letters)), 4)

    # Heuristic DGA scoring: High entropy (> 3.5), high digit ratio (> 0.25), or low vowel ratio (< 0.15)
    dga_score = 0.0
    if entropy > 3.8:
        dga_score += 0.4
    elif entropy > 3.3:
        dga_score += 0.2

    if digit_ratio > 0.30:
        dga_score += 0.3
    elif digit_ratio > 0.15:
        dga_score += 0.15

    if vowel_ratio < 0.18 and len(letters) > 6:
        dga_score += 0.3

    dga_score = min(1.0, round(dga_score, 4))
    is_dga = dga_score >= 0.60

    # Heuristic DNS Tunneling: Extraordinarily long query (> 45 chars) with high subdomain depth (> 3) and high entropy
    is_tunneling = q_len > 45 and subdomain_depth >= 3 and entropy > 3.6

    return DNSMetadataFeatures(
        query_name=query_name,
        query_length=q_len,
        shannon_entropy=entropy,
        subdomain_depth=subdomain_depth,
        digit_ratio=digit_ratio,
        vowel_ratio=vowel_ratio,
        dga_risk_score=dga_score,
        is_dga_suspect=is_dga,
        is_tunneling_suspect=is_tunneling,
    )
