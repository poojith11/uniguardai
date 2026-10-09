import time
from pathlib import Path
from typing import Dict, Any, List, Tuple
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score, precision_score, recall_score

from app.traffic.pcap_parser import read_pcap_packets
from app.traffic.flow_aggregator import aggregate_unidirectional_flows
from app.traffic.feature_extractor import extract_flow_features
from app.ml.dataset_schema import ALL_PREDICTIVE_FEATURES, ThreatClass
from app.ml.model_registry import load_model_pipeline


# Ground-truth IP mappings for CSE-CIC-IDS2018 Wednesday-14-02-2018 + Local Test Fixture
ATTACKER_IPS = {
    # Official CSE-CIC-IDS2018 Wednesday-14-02-2018 Attackers
    "18.218.115.60": ThreatClass.RECON_SCAN.value,  # FTP-BruteForce attacker
    "18.219.9.1": ThreatClass.RECON_SCAN.value,     # SSH-Bruteforce attacker
    # Local Test Fixture RFC-5737 Attackers
    "192.0.2.25": ThreatClass.C2_BEACONING.value,
    "192.0.2.44": ThreatClass.RECON_SCAN.value,
}
VICTIM_SERVER_IP = "172.31.69.28"


def map_real_pcap_ground_truth(flow) -> str:
    """
    Assigns ground truth based on official CSE-CIC-IDS2018 network topology.
    Distinguishes verified labeled flows from unknown background noise.
    """
    src = flow.src_ip
    dst = flow.dst_ip

    # 1. Direct attacker flows
    if src in ATTACKER_IPS:
        return ATTACKER_IPS[src]

    # 2. Legitimate enterprise subnet traffic (Benign)
    if src.startswith("172.31.") and dst == VICTIM_SERVER_IP:
        return ThreatClass.BENIGN.value
    if src == VICTIM_SERVER_IP and dst.startswith("172.31."):
        return ThreatClass.BENIGN.value

    # 3. Local Test Fixture Benign Traffic
    if src == "192.0.2.10":
        return ThreatClass.BENIGN.value

    # 4. Ambient noise or unverified external traffic
    return "UNKNOWN_EXCLUDED"


def evaluate_real_pcap_pipeline(pcap_path: Path, models_dir: Path = None) -> Dict[str, Any]:
    """
    Executes end-to-end real-world evaluation:
    REAL PCAP -> Phase 2 Parser -> Phase 2 Flow Aggregator -> 27 Features -> Phase 3B Models (No Retraining).
    """
    m_dir = models_dir or (Path(__file__).parent / "models")
    pipeline = load_model_pipeline(m_dir)

    print("=" * 80)
    print("UNIGUARD AI (SIH26145) — Real-World PCAP Evaluation (Phase 3C)")
    print(f"Target PCAP: {pcap_path.name} ({pcap_path.stat().st_size / 1024 / 1024:.2f} MB)")
    print("=" * 80)

    # 1. Process Packets via Phase 2 Parser
    print("\n[1/6] Ingesting and parsing packets via UNIGUARD Phase 2 Parser...")
    t0_parse = time.perf_counter()
    packets = list(read_pcap_packets(pcap_path))
    parse_duration = max(time.perf_counter() - t0_parse, 1e-6)
    print(f"      Total packets parsed: {len(packets):,} ({len(packets)/parse_duration:,.0f} pkts/sec)")

    # 2. Unidirectional 5-Tuple Flow Aggregation
    print("\n[2/6] Aggregating packets into unidirectional 5-tuple flows...")
    t0_agg = time.perf_counter()
    flows = aggregate_unidirectional_flows(packets, idle_timeout_seconds=60.0)
    agg_duration = max(time.perf_counter() - t0_agg, 1e-6)
    print(f"      Total unidirectional flows generated: {len(flows):,} ({len(flows)/agg_duration:,.0f} flows/sec)")

    # 3. Extract 27 Canonical Predictive Features
    print("\n[3/6] Extracting 27 canonical features per flow via Phase 2 Feature Extractor...")
    features_list = [extract_flow_features(f) for f in flows]

    records = []
    supported_records = []
    excluded_count = 0

    for flow_feat in features_list:
        gt_label = map_real_pcap_ground_truth(flow_feat)
        rec = {
            "flow_id": flow_feat.flow_id,
            "src_ip": flow_feat.src_ip,
            "dst_ip": flow_feat.dst_ip,
            "src_port": flow_feat.src_port,
            "dst_port": flow_feat.dst_port,
            "protocol": flow_feat.protocol,
            "start_time": flow_feat.start_time,
            "end_time": flow_feat.end_time,
            "ground_truth": gt_label,
            **{feat: getattr(flow_feat, feat) for feat in ALL_PREDICTIVE_FEATURES},
        }
        records.append(rec)
        if gt_label != "UNKNOWN_EXCLUDED":
            supported_records.append(rec)
        else:
            excluded_count += 1

    full_df = pd.DataFrame(records)
    eval_df = pd.DataFrame(supported_records)

    target_df = eval_df if not eval_df.empty else full_df
    print(f"      Total flows evaluated:                  {len(target_df):,}")
    print(f"      Excluded ambiguous flows:               {excluded_count:,}")
    if not eval_df.empty:
        print(f"      Ground truth breakdown:\n{eval_df['ground_truth'].value_counts().to_string()}")

    # 4. Feature Matrix Preparation (Zero Retraining / Existing Scaler)
    print("\n[4/6] Transforming features via existing Phase 3B preprocessor (No Retraining)...")
    X_eval_raw = target_df[ALL_PREDICTIVE_FEATURES].to_numpy(dtype=float)
    X_eval_scaled = pipeline["preprocessor"].scaler.transform(X_eval_raw)

    # 5. Model Inference & Latency Benchmarks
    print("\n[5/6] Running inference with existing Phase 3B models...")
    latencies = []
    y_preds_idx = []
    anom_scores = []

    for row in X_eval_scaled:
        row_2d = row.reshape(1, -1)
        t_start = time.perf_counter()
        pred_idx = pipeline["supervised_model"].predict(row_2d)[0]
        anom_score = pipeline["anomaly_model"].decision_function(row_2d)[0]
        t_elapsed = (time.perf_counter() - t_start) * 1000.0  # ms
        latencies.append(t_elapsed)
        y_preds_idx.append(pred_idx)
        anom_scores.append(anom_score)

    y_preds_lbl = pipeline["label_encoder"].inverse_transform(y_preds_idx)
    target_df["predicted_label"] = y_preds_lbl
    target_df["anomaly_score"] = anom_scores

    latencies_arr = np.array(latencies)
    mean_lat = float(np.mean(latencies_arr))
    med_lat = float(np.median(latencies_arr))
    p95_lat = float(np.percentile(latencies_arr, 95))
    throughput_fps = float(1000.0 / mean_lat) if mean_lat > 0 else 0.0

    print(f"      Mean Latency:   {mean_lat:.4f} ms/flow")
    print(f"      Median Latency: {med_lat:.4f} ms/flow")
    print(f"      P95 Latency:    {p95_lat:.4f} ms/flow")
    print(f"      Throughput:     {throughput_fps:,.0f} flows/second")

    # 6. Quantitative Evaluation & Metrics
    print("\n[6/6] Computing Real-World Classification & Generalization Metrics...")
    if not eval_df.empty and "ground_truth" in eval_df.columns:
        y_true = eval_df["ground_truth"]
        y_pred = eval_df["predicted_label"]

        acc = float(accuracy_score(y_true, y_pred))
        macro_p = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
        macro_r = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
        macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
        weighted_f1 = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

        classes_present = sorted(list(set(y_true.unique()).union(set(y_pred.unique()))))
        cm = confusion_matrix(y_true, y_pred, labels=classes_present)
        clf_rep = classification_report(y_true, y_pred, labels=classes_present, output_dict=True, zero_division=0)

        benign_mask = y_true == ThreatClass.BENIGN.value
        threat_mask = ~benign_mask

        fp_mask = benign_mask & (y_pred != ThreatClass.BENIGN.value)
        fn_mask = threat_mask & (y_pred == ThreatClass.BENIGN.value)

        fp_count = int(fp_mask.sum())
        fn_count = int(fn_mask.sum())
        benign_total = int(benign_mask.sum())
        threat_total = int(threat_mask.sum())

        fp_rate = (fp_count / benign_total) * 100.0 if benign_total > 0 else 0.0
        fn_rate = (fn_count / threat_total) * 100.0 if threat_total > 0 else 0.0

        anom_preds = eval_df["anomaly_score"] < 0
        iso_fpr_benign = float(np.mean(anom_preds[benign_mask])) if benign_total > 0 else 0.0
        iso_recall_threat = float(np.mean(anom_preds[threat_mask])) if threat_total > 0 else 0.0
    else:
        acc = macro_p = macro_r = macro_f1 = weighted_f1 = 0.0
        fp_count = fn_count = 0
        fp_rate = fn_rate = iso_fpr_benign = iso_recall_threat = 0.0
        cm = []
        classes_present = []
        clf_rep = {}

    return {
        "pcap_filename": pcap_path.name,
        "pcap_size_bytes": pcap_path.stat().st_size,
        "packets_parsed": len(packets),
        "flows_extracted": len(flows),
        "flows_evaluated": len(target_df),
        "flows_excluded": excluded_count,
        "accuracy": acc,
        "macro_precision": macro_p,
        "macro_recall": macro_r,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "false_positive_count": fp_count,
        "false_positive_rate": fp_rate,
        "false_negative_count": fn_count,
        "false_negative_rate": fn_rate,
        "isolation_forest_fpr_benign": iso_fpr_benign,
        "isolation_forest_threat_recall": iso_recall_threat,
        "mean_latency_ms": mean_lat,
        "median_latency_ms": med_lat,
        "p95_latency_ms": p95_lat,
        "throughput_flows_per_sec": throughput_fps,
        "confusion_matrix": cm.tolist() if isinstance(cm, np.ndarray) else cm,
        "classes_present": classes_present,
        "classification_report": clf_rep,
    }


if __name__ == "__main__":
    pcap = Path(__file__).parent.parent.parent / "data" / "raw" / "capEC2AMAZ-O4EL3NG-172.31.69.28.pcap"
    if pcap.exists():
        evaluate_real_pcap_pipeline(pcap)
    else:
        print(f"Target PCAP does not exist at: {pcap}")
