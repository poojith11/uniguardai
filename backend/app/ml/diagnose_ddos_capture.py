from pathlib import Path
import json
import numpy as np
import pandas as pd
import joblib
from collections import Counter

from app.traffic.pcap_parser import read_pcap_packets
from app.traffic.flow_aggregator import aggregate_unidirectional_flows
from app.traffic.feature_extractor import extract_flow_features
from app.ml.dataset_schema import ALL_PREDICTIVE_FEATURES, ThreatClass
from app.ml.inference_service import MLInferenceEngine


def run_ddos_diagnostic():
    pcap_path = Path("backend/data/raw/UCAP172.31.69.25_Wed21.pcap")
    if not pcap_path.exists():
        print(f"Error: PCAP not found at {pcap_path}")
        return

    print("=" * 80)
    print(f"DDOS ROOT-CAUSE DIAGNOSTIC: {pcap_path.name}")
    print("=" * 80)

    # 1. Parse and extract all flows
    packets = list(read_pcap_packets(pcap_path))
    flows = aggregate_unidirectional_flows(packets, idle_timeout_seconds=60.0)
    feats = [extract_flow_features(f) for f in flows]

    print(f"Total Packets: {len(packets):,}")
    print(f"Total Flows:   {len(flows):,}")

    # 2. Inspect Ingress vs Internal Flows
    ext_flows = [f for f in feats if not f.src_ip.startswith("172.31.")]
    internal_flows = [f for f in feats if f.src_ip.startswith("172.31.")]

    print(f"Internal Enterprise Flows: {len(internal_flows):,}")
    print(f"External Ingress Flows:    {len(ext_flows):,}")

    # 3. Target ports for External Flows
    ext_ports = Counter(f.dst_port for f in ext_flows)
    print("\nExternal Ingress Destination Ports:")
    for p, cnt in ext_ports.most_common(10):
        print(f"  Port {p}: {cnt} flows")

    # 4. Run Phase 3G Inference on the first 300 flows (matching UI max_flows=300)
    engine = MLInferenceEngine.get_instance()
    ui_analysis = engine.analyze_pcap(pcap_path, max_flows=300)

    print("\n--- UI / INFERENCE ENDPOINT RESULTS (max_flows=300) ---")
    print(f"Evaluated Flows:   {ui_analysis['evaluated_flows']}")
    print(f"Benign Flows:      {ui_analysis['benign_flows']}")
    print(f"Threat Flows:      {ui_analysis['threat_flows']}")
    print(f"Anomaly Flows:     {ui_analysis['anomaly_flows']}")
    print("Threat Breakdown:")
    for k, v in ui_analysis["threat_breakdown"].items():
        print(f"  {k:15s}: {v}")

    # 5. Check Random Forest Class Probabilities for External Flows
    print("\n--- DETAILED PROBABILITY DISTRIBUTION FOR FIRST 10 THREAT FLOWS ---")
    threat_samples = [f for f in ui_analysis["flows"] if f["is_threat"]][:10]
    for i, t in enumerate(threat_samples):
        print(f"\nFlow {i+1}: {t['src_ip']}:{t['src_port']} -> {t['dst_ip']}:{t['dst_port']} ({t['protocol']})")
        print(f"  Packets: {t['packet_count']}, Bytes: {t['byte_count']}, Duration: {t['duration_seconds']}s")
        print(f"  Predicted: {t['predicted_class']}, Anomaly Score: {t['anomaly_score']}")
        print(f"  Probabilities: {t['probabilities']}")

    # 6. Check what training samples existed for DDOS in Phase 3G training
    model_dir = Path("backend/app/ml/models/phase3g_attack_robust")
    with open(model_dir / "training_manifest.json") as f:
        manifest = json.load(f)

    with open(model_dir / "model_metadata_phase3g.json") as f:
        metadata = json.load(f)

    print("\n--- PHASE 3G TRAINING DATA AUDIT ---")
    print("Training Captures:", manifest.get("training_captures"))
    print("Validation Captures:", manifest.get("validation_captures"))
    print("Unseen Test Captures:", manifest.get("unseen_test_captures"))
    print("RF Classes in Model:", engine.supervised_clf.classes_)
    print("Encoder Classes:", engine.label_encoder.classes_)

    # 7. Check Class Distribution during Phase 3G Training
    raw_train_captures = [
        ("capEC2AMAZ-O4EL3NG-172.31.69.28.pcap", "Wed14_Server28"),
        ("UCAP172.31.69.27_Wed14.pcap", "Wed14_Subnet27"),
        ("UCAP172.31.69.25_Fri16.pcap", "Fri16_WebServer25"),
        ("ctu13_scenario1_neris.pcap", "CTU13_Neris"),
    ]
    print("\nAuditing actual training flows from Phase 3G training script:")
    for fn, cid in raw_train_captures:
        p = Path("backend/data/raw") / fn
        if p.exists():
            pkts = list(read_pcap_packets(p))
            fl = aggregate_unidirectional_flows(pkts, idle_timeout_seconds=60.0)
            print(f"  Capture [{cid:18s}]: {len(pkts):,} pkts, {len(fl):,} flows")


if __name__ == "__main__":
    run_ddos_diagnostic()
