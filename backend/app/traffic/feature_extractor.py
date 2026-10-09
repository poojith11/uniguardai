import math
from typing import List, Dict
import numpy as np

from .models import TrafficFlow, FlowFeatures


def calculate_entropy(values: List[int]) -> float:
    """
    Computes standard Shannon Entropy in bits for a discrete distribution of values.
    H(X) = - sum(p_i * log2(p_i))
    """
    if not values:
        return 0.0

    total_count = len(values)
    frequency: Dict[int, int] = {}
    for val in values:
        frequency[val] = frequency.get(val, 0) + 1

    entropy = 0.0
    for count in frequency.values():
        p = count / total_count
        if p > 0:
            entropy -= p * math.log2(p)

    return float(round(entropy, 4))


def extract_flow_features(flow: TrafficFlow) -> FlowFeatures:
    """
    Extracts deterministic numerical feature vector from a unidirectional TrafficFlow.
    Zero hallucinated/fake values — strictly grounded in observed packet data.
    """
    packets = flow.packets
    packet_count = len(packets)

    if packet_count == 0:
        raise ValueError(f"Cannot extract features from empty flow '{flow.flow_id}'")

    timestamps = [p.timestamp for p in packets]
    lengths = [p.length for p in packets]

    start_time = float(timestamps[0])
    end_time = float(timestamps[-1])
    duration = max(0.0, end_time - start_time)
    byte_count = sum(lengths)

    # Rates
    if duration > 0.0:
        pps = round(packet_count / duration, 4)
        bps = round(byte_count / duration, 4)
    else:
        pps = float(packet_count)
        bps = float(byte_count)

    # Packet size distribution
    mean_len = float(np.mean(lengths))
    std_len = float(np.std(lengths)) if packet_count > 1 else 0.0
    min_len = int(min(lengths))
    max_len = int(max(lengths))
    size_entropy = calculate_entropy(lengths)

    # Inter-Arrival Times (IAT)
    if packet_count > 1:
        iats = [max(0.0, timestamps[i + 1] - timestamps[i]) for i in range(packet_count - 1)]
        mean_iat = float(np.mean(iats))
        std_iat = float(np.std(iats)) if len(iats) > 1 else 0.0
        min_iat = float(min(iats))
        max_iat = float(max(iats))

        # Jitter: Mean absolute difference between consecutive IATs
        if len(iats) >= 2:
            iat_diffs = [abs(iats[i + 1] - iats[i]) for i in range(len(iats) - 1)]
            iat_jitter = float(np.mean(iat_diffs))
        else:
            iat_jitter = 0.0

        # Burstiness: Coefficient of Variation (std / mean)
        burstiness = float(round(std_iat / mean_iat, 4)) if mean_iat > 0.0 else 0.0
    else:
        mean_iat = 0.0
        std_iat = 0.0
        min_iat = 0.0
        max_iat = 0.0
        iat_jitter = 0.0
        burstiness = 0.0

    # TCP Control Flag Statistics
    syn_count = 0
    ack_count = 0
    fin_count = 0
    rst_count = 0
    psh_count = 0
    urg_count = 0

    for p in packets:
        if p.tcp_flags is not None:
            if p.tcp_flags.syn:
                syn_count += 1
            if p.tcp_flags.ack:
                ack_count += 1
            if p.tcp_flags.fin:
                fin_count += 1
            if p.tcp_flags.rst:
                rst_count += 1
            if p.tcp_flags.psh:
                psh_count += 1
            if p.tcp_flags.urg:
                urg_count += 1

    syn_ratio = round(syn_count / packet_count, 4)
    ack_ratio = round(ack_count / packet_count, 4)
    rst_ratio = round(rst_count / packet_count, 4)

    # Port Categorization
    dst_port = flow.key.dst_port
    src_port = flow.key.src_port
    is_well_known_dst = bool(dst_port is not None and 0 < dst_port <= 1024)
    is_ephemeral_src = bool(src_port is not None and src_port >= 1024)

    return FlowFeatures(
        flow_id=flow.flow_id,
        src_ip=flow.key.src_ip,
        dst_ip=flow.key.dst_ip,
        src_port=flow.key.src_port,
        dst_port=flow.key.dst_port,
        protocol=flow.key.protocol,
        start_time=round(start_time, 6),
        end_time=round(end_time, 6),
        duration_seconds=round(duration, 6),
        packet_count=packet_count,
        byte_count=byte_count,
        packets_per_second=pps,
        bytes_per_second=bps,
        mean_packet_size=round(mean_len, 2),
        std_packet_size=round(std_len, 2),
        min_packet_size=min_len,
        max_packet_size=max_len,
        packet_size_entropy=size_entropy,
        mean_iat_seconds=round(mean_iat, 6),
        std_iat_seconds=round(std_iat, 6),
        min_iat_seconds=round(min_iat, 6),
        max_iat_seconds=round(max_iat, 6),
        iat_jitter_seconds=round(iat_jitter, 6),
        burstiness_ratio=burstiness,
        syn_count=syn_count,
        ack_count=ack_count,
        fin_count=fin_count,
        rst_count=rst_count,
        psh_count=psh_count,
        urg_count=urg_count,
        syn_ratio=syn_ratio,
        ack_ratio=ack_ratio,
        rst_ratio=rst_ratio,
        is_well_known_dst_port=is_well_known_dst,
        is_ephemeral_src_port=is_ephemeral_src,
    )


def extract_features_from_flows(flows: List[TrafficFlow]) -> List[FlowFeatures]:
    """Batch extraction of features for all flows."""
    return [extract_flow_features(flow) for flow in flows]
