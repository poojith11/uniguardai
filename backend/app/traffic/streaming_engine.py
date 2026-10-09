from pathlib import Path
from typing import Iterator, Dict, Any, List, Optional
import time
import hashlib
from datetime import datetime, timezone

from app.traffic.pcap_parser import read_pcap_packets
from app.traffic.models import TrafficPacket, TrafficFlow, FlowKey, FlowFeatures
from app.traffic.feature_extractor import extract_flow_features
from app.traffic.alert_schema import SecurityAlert, AlertEvidence
from app.ml.inference_service import MLInferenceEngine
from app.traffic.ddos_detector import evaluate_ddos_signal
from app.traffic.c2_analyzer import evaluate_c2_signal
from app.traffic.recon_detector import evaluate_recon_signal
from app.traffic.exfiltration_analyzer import evaluate_exfiltration_risk


class StreamingPipeline:
    """
    Incremental Streaming Engine for Unidirectional Passive Traffic.
    Processes packets in bounded sliding windows / chunks without loading entire PCAP into memory.
    Emits standardized SecurityAlerts and flow updates with bounded latency.
    """
    def __init__(self, idle_timeout_seconds: float = 60.0, chunk_size: int = 100):
        self.idle_timeout_seconds = idle_timeout_seconds
        self.chunk_size = chunk_size
        self.active_flows: Dict[str, TrafficFlow] = {}
        self.flow_index: int = 0
        self.engine = MLInferenceEngine.get_instance()

    def process_packet(self, packet: TrafficPacket) -> Optional[SecurityAlert]:
        """Ingests a single passive packet and incrementally updates flow state."""
        key = FlowKey(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
        )
        flow_str_key = key.to_string()

        # Check if flow already exists and within idle timeout
        flow = self.active_flows.get(flow_str_key)
        if flow and (packet.timestamp - flow.end_time) <= self.idle_timeout_seconds:
            flow.packets.append(packet)
            flow.end_time = packet.timestamp
            flow.duration = flow.end_time - flow.start_time
            flow.packet_count += 1
            flow.byte_count += packet.length
        else:
            self.flow_index += 1
            flow_id = f"flow_{self.flow_index:07d}"
            flow = TrafficFlow(
                flow_id=flow_id,
                key=key,
                start_time=packet.timestamp,
                end_time=packet.timestamp,
                duration=0.0,
                packet_count=1,
                byte_count=packet.length,
                packets=[packet],
            )
            self.active_flows[flow_str_key] = flow

        # When flow reaches significant checkpoint (e.g. 5 packets or end of burst), run incremental inference
        if flow.packet_count in (1, 5, 20, 50, 100) or flow.packet_count % 100 == 0:
            return self._evaluate_flow_alert(flow)

        return None

    def _evaluate_flow_alert(self, flow: TrafficFlow) -> SecurityAlert:
        """Runs two-tier ML inference and specialized signal evaluation on current flow state."""
        features: FlowFeatures = extract_flow_features(flow)
        ml_result = self.engine.predict_flow(features)

        pred_class = ml_result["predicted_class"]
        severity = ml_result["severity"]
        is_threat = ml_result["is_threat"]
        anom_score = ml_result["anomaly_score"]
        is_anomaly = ml_result["is_anomaly"]
        probs = ml_result.get("probabilities", {})

        confidence = probs.get(pred_class, 0.95 if is_threat else 0.99)

        # Cross-evaluate specialized heuristic signals
        ddos_sig = evaluate_ddos_signal(features)
        c2_sig = evaluate_c2_signal(features)
        recon_sig = evaluate_recon_signal(features)
        exfil_sig = evaluate_exfiltration_risk(features)

        primary_signal = f"Phase 3I ML Classifier ({pred_class})"
        evidence_dict = {
            "predicted_class": pred_class,
            "packets": flow.packet_count,
            "bytes": flow.byte_count,
            "duration_sec": round(flow.duration, 4),
            "pps": round(features.packets_per_second, 2),
            "syn_ratio": round(features.syn_ratio, 4),
            "iat_jitter": round(features.iat_jitter_seconds, 4),
        }

        rule_indicators = {
            "ddos_signal": ddos_sig.is_ddos_signal,
            "c2_periodic_signal": c2_sig.is_c2_signal,
            "recon_scan_signal": recon_sig.is_recon_signal,
            "exfiltration_risk": exfil_sig.is_exfiltration_risk,
        }

        # Generate deterministic alert hash
        raw_hash_input = f"{flow.flow_id}:{pred_class}:{confidence}:{anom_score}:{flow.start_time}"
        alert_hash = hashlib.sha256(raw_hash_input.encode("utf-8")).hexdigest()

        return SecurityAlert(
            alert_id=f"alert_{alert_hash[:12]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            flow_id=flow.flow_id,
            src_ip=flow.key.src_ip,
            dst_ip=flow.key.dst_ip,
            src_port=flow.key.src_port,
            dst_port=flow.key.dst_port,
            protocol=flow.key.protocol,
            threat_class=pred_class,
            confidence=round(confidence, 4),
            severity=severity,
            anomaly_score=anom_score,
            is_anomaly=is_anomaly,
            evidence=AlertEvidence(
                primary_signal=primary_signal,
                feature_attributions=evidence_dict,
                rule_indicators=rule_indicators,
            ),
            sha256_hash=alert_hash,
        )

    def stream_pcap(self, pcap_path: Path, max_packets: Optional[int] = None) -> Iterator[Dict[str, Any]]:
        """
        Incrementally streams packets from a PCAP file in bounded chunks.
        Yields real-time flow telemetry and security alerts without loading entire file into memory.
        """
        packet_count = 0
        t0 = time.perf_counter()

        for pkt in read_pcap_packets(pcap_path):
            packet_count += 1
            alert = self.process_packet(pkt)

            if alert:
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                yield {
                    "packet_index": packet_count,
                    "elapsed_ms": round(elapsed_ms, 2),
                    "alert": alert.model_dump(),
                }

            if max_packets and packet_count >= max_packets:
                break
