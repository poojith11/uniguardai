import hashlib
from typing import List, Dict, Iterable, Optional
from .models import TrafficPacket, TrafficFlow, FlowKey


def build_flow_id(key: FlowKey, start_ts: float) -> str:
    """Generates a deterministic unique identifier for a unidirectional flow instance."""
    raw = f"{key.to_string()}:{start_ts:.6f}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def aggregate_unidirectional_flows(
    packets: Iterable[TrafficPacket],
    idle_timeout_seconds: Optional[float] = None
) -> List[TrafficFlow]:
    """
    Groups packets into unidirectional flows based strictly on the forward 5-tuple:
    (src_ip, dst_ip, src_port, dst_port, protocol).

    In compliance with SIH26145 Passive Threat Intelligence (unidirectional data diode model),
    the flow is strictly one-way without pairing reverse packets.
    """
    active_flows: Dict[str, TrafficFlow] = {}
    completed_flows: List[TrafficFlow] = []

    for pkt in sorted(packets, key=lambda p: p.timestamp):
        key = FlowKey(
            src_ip=pkt.src_ip,
            dst_ip=pkt.dst_ip,
            src_port=pkt.src_port,
            dst_port=pkt.dst_port,
            protocol=pkt.protocol,
        )
        flow_key_str = key.to_string()

        # Check if an existing active flow should be closed due to idle timeout
        if flow_key_str in active_flows:
            current_flow = active_flows[flow_key_str]
            if idle_timeout_seconds is not None and (pkt.timestamp - current_flow.end_time) > idle_timeout_seconds:
                completed_flows.append(current_flow)
                # Start new flow
                new_flow = TrafficFlow(
                    flow_id=build_flow_id(key, pkt.timestamp),
                    key=key,
                    start_time=pkt.timestamp,
                    end_time=pkt.timestamp,
                    duration=0.0,
                    packet_count=1,
                    byte_count=pkt.length,
                    packets=[pkt],
                )
                active_flows[flow_key_str] = new_flow
            else:
                # Append to existing flow
                current_flow.packets.append(pkt)
                current_flow.end_time = pkt.timestamp
                current_flow.duration = max(0.0, pkt.timestamp - current_flow.start_time)
                current_flow.packet_count += 1
                current_flow.byte_count += pkt.length
        else:
            # First packet for this unidirectional 5-tuple
            new_flow = TrafficFlow(
                flow_id=build_flow_id(key, pkt.timestamp),
                key=key,
                start_time=pkt.timestamp,
                end_time=pkt.timestamp,
                duration=0.0,
                packet_count=1,
                byte_count=pkt.length,
                packets=[pkt],
            )
            active_flows[flow_key_str] = new_flow

    # Collect remaining active flows
    completed_flows.extend(active_flows.values())

    # Sort completed flows chronologically by start time
    completed_flows.sort(key=lambda f: f.start_time)
    return completed_flows
