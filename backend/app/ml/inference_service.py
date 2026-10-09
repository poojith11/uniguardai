import time
from pathlib import Path
from typing import Dict, Any, List, Optional
import json
import numpy as np
import joblib

from app.traffic.pcap_parser import read_pcap_packets
from app.traffic.flow_aggregator import aggregate_unidirectional_flows
from app.traffic.feature_extractor import extract_flow_features
from app.traffic.models import FlowFeatures
from app.ml.dataset_schema import ALL_PREDICTIVE_FEATURES, ThreatClass


class MLInferenceEngine:
    _instance = None

    def __init__(self, model_version: str = "phase3i_multiclass"):
        self.model_version = model_version
        self.base_dir = Path(__file__).parent / "models"
        self.model_dir = self.base_dir / model_version
        
        # Fallback to phase3g if phase3i not found
        if not self.model_dir.exists():
            self.model_dir = self.base_dir / "phase3g_attack_robust"

        self._load_artifacts()

    def _load_artifacts(self):
        if not self.model_dir.exists():
            raise FileNotFoundError(f"Model artifacts directory not found at: {self.model_dir}")

        suffix = "phase3i" if "phase3i" in self.model_dir.name else "phase3g"

        self.iso_forest = joblib.load(self.model_dir / f"isolation_forest_{suffix}.joblib")
        self.supervised_clf = joblib.load(self.model_dir / f"supervised_classifier_{suffix}.joblib")
        self.preprocessor = joblib.load(self.model_dir / f"preprocessor_{suffix}.joblib")
        self.label_encoder = joblib.load(self.model_dir / f"label_encoder_{suffix}.joblib")

        meta_path = self.model_dir / f"model_metadata_{suffix}.json"
        if meta_path.exists():
            with open(meta_path, "r") as f:
                self.metadata = json.load(f)
        else:
            self.metadata = {}

        manifest_path = self.model_dir / "training_manifest.json"
        if manifest_path.exists():
            with open(manifest_path, "r") as f:
                self.manifest = json.load(f)
        else:
            self.manifest = {}

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def predict_flow(self, flow_features: FlowFeatures) -> Dict[str, Any]:
        """Runs two-tier ML inference on a single flow feature vector."""
        # 1. Extract authoritative 27 canonical features
        raw_vector = np.array([[getattr(flow_features, feat) for feat in ALL_PREDICTIVE_FEATURES]], dtype=float)

        # 2. Scale using preprocessor fitted strictly on training data
        scaled_vector = self.preprocessor.scaler.transform(raw_vector)

        # 3. Tier 1: Multi-Class Supervised Classification
        pred_idx = self.supervised_clf.predict(scaled_vector)[0]
        pred_label = self.label_encoder.inverse_transform([pred_idx])[0]

        probabilities = {}
        if hasattr(self.supervised_clf, "predict_proba"):
            probs = self.supervised_clf.predict_proba(scaled_vector)[0]
            for cls_idx, p in zip(self.supervised_clf.classes_, probs):
                name = self.label_encoder.inverse_transform([cls_idx])[0]
                probabilities[name] = round(float(p), 4)

        # 4. Tier 2: Unsupervised Anomaly Detection (Isolation Forest)
        anomaly_score = float(self.iso_forest.decision_function(scaled_vector)[0])
        iso_pred = int(self.iso_forest.predict(scaled_vector)[0])
        is_anomaly = iso_pred == -1

        is_threat = pred_label != ThreatClass.BENIGN.value

        # Determine threat severity
        severity = "BENIGN"
        if pred_label == ThreatClass.C2_BEACONING.value:
            severity = "CRITICAL"
        elif pred_label == ThreatClass.DDOS.value:
            severity = "HIGH"
        elif pred_label == ThreatClass.RECON_SCAN.value:
            severity = "MEDIUM"
        elif is_anomaly:
            severity = "LOW"

        return {
            "flow_id": flow_features.flow_id,
            "src_ip": flow_features.src_ip,
            "dst_ip": flow_features.dst_ip,
            "src_port": flow_features.src_port,
            "dst_port": flow_features.dst_port,
            "protocol": flow_features.protocol,
            "packet_count": flow_features.packet_count,
            "byte_count": flow_features.byte_count,
            "duration_seconds": round(flow_features.duration_seconds, 4),
            "predicted_class": pred_label,
            "is_threat": is_threat,
            "severity": severity,
            "anomaly_score": round(anomaly_score, 4),
            "is_anomaly": is_anomaly,
            "probabilities": probabilities,
            "features": {feat: round(float(getattr(flow_features, feat)), 4) for feat in ALL_PREDICTIVE_FEATURES[:8]},
        }

    def analyze_pcap(self, pcap_path: Path, max_flows: int = 500) -> Dict[str, Any]:
        """Analyzes a PCAP file end-to-end: parse -> aggregate -> extract -> infer."""
        t0 = time.perf_counter()
        packets = list(read_pcap_packets(pcap_path))
        t_parse = time.perf_counter() - t0

        t0_agg = time.perf_counter()
        flows = aggregate_unidirectional_flows(packets, idle_timeout_seconds=60.0)
        t_agg = time.perf_counter() - t0_agg

        t0_infer = time.perf_counter()
        results = []
        threat_breakdown = {"BENIGN": 0, "C2_BEACONING": 0, "DDOS": 0, "RECON_SCAN": 0}
        anomaly_count = 0

        for f in flows[:max_flows]:
            feat = extract_flow_features(f)
            pred = self.predict_flow(feat)
            results.append(pred)

            cls_name = pred["predicted_class"]
            threat_breakdown[cls_name] = threat_breakdown.get(cls_name, 0) + 1
            if pred["is_anomaly"]:
                anomaly_count += 1

        t_infer = time.perf_counter() - t0_infer

        threat_flows = len(results) - threat_breakdown.get("BENIGN", 0)

        return {
            "pcap_filename": pcap_path.name,
            "file_size_bytes": pcap_path.stat().st_size if pcap_path.exists() else 0,
            "total_packets": len(packets),
            "total_flows": len(flows),
            "evaluated_flows": len(results),
            "benign_flows": threat_breakdown.get("BENIGN", 0),
            "threat_flows": threat_flows,
            "anomaly_flows": anomaly_count,
            "threat_breakdown": threat_breakdown,
            "flows": results,
            "timing_ms": {
                "parse_time_ms": round(t_parse * 1000, 2),
                "aggregation_time_ms": round(t_agg * 1000, 2),
                "inference_time_ms": round(t_infer * 1000, 2),
                "total_time_ms": round((t_parse + t_agg + t_infer) * 1000, 2),
            },
        }


def get_available_sample_pcaps() -> List[Dict[str, Any]]:
    raw_dir = Path(__file__).parent.parent.parent / "data" / "raw"
    samples = []
    if raw_dir.exists():
        for p in sorted(raw_dir.glob("*.pcap")):
            samples.append({
                "filename": p.name,
                "size_mb": round(p.stat().st_size / 1024 / 1024, 2),
                "path": str(p),
            })
    return samples
