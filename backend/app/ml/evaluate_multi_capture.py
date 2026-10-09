import time
from pathlib import Path
from typing import Dict, Any, List, Tuple
import json
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score, precision_score, recall_score

from app.traffic.pcap_parser import read_pcap_packets
from app.traffic.flow_aggregator import aggregate_unidirectional_flows
from app.traffic.feature_extractor import extract_flow_features
from app.ml.dataset_schema import ALL_PREDICTIVE_FEATURES, ThreatClass
from app.ml.model_registry import load_model_pipeline


# Multi-Capture Ground Truth Mapping for CSE-CIC-IDS2018
def map_multi_capture_ground_truth(flow, capture_id: str) -> str:
    src = flow.src_ip
    dst = flow.dst_ip

    # 1. Botnet Ares Client (Friday 02-03-2018)
    if "Fri02" in capture_id:
        if src.startswith("172.31.67.") and flow.dst_port in (80, 443, 8080) and flow.packet_count >= 3:
            return ThreatClass.C2_BEACONING.value
        if (src.startswith("172.31.") and dst.startswith("172.31.")) or src == "172.31.0.2":
            return ThreatClass.BENIGN.value

    # 2. DoS-Hulk / DoS-SlowHTTPTest (Friday 16-02-2018)
    if "Fri16" in capture_id:
        if src.startswith("18.218.") or src.startswith("18.219.") or src.startswith("13.58."):
            return ThreatClass.DDOS.value
        if (src.startswith("172.31.") and dst.startswith("172.31.")) or src == "172.31.0.2":
            return ThreatClass.BENIGN.value

    # 3. DDOS-LOIC-HTTP / HOIC (Wednesday 21-02-2018)
    if "Wed21" in capture_id:
        if src.startswith("18.218.") or src.startswith("18.219.") or src.startswith("13.58."):
            return ThreatClass.DDOS.value
        if (src.startswith("172.31.") and dst.startswith("172.31.")) or src == "172.31.0.2":
            return ThreatClass.BENIGN.value

    # General Internal Enterprise Benign
    if (src.startswith("172.31.") and dst.startswith("172.31.")) or src == "172.31.0.2":
        return ThreatClass.BENIGN.value

    return "UNKNOWN_EXCLUDED"


def extract_test_capture(pcap_path: Path, capture_id: str) -> Tuple[pd.DataFrame, Dict[str, float]]:
    t0_parse = time.perf_counter()
    packets = list(read_pcap_packets(pcap_path))
    t_parse = time.perf_counter() - t0_parse

    t0_agg = time.perf_counter()
    flows = aggregate_unidirectional_flows(packets, idle_timeout_seconds=60.0)
    t_agg = time.perf_counter() - t0_agg

    t0_feat = time.perf_counter()
    features_list = [extract_flow_features(f) for f in flows]
    t_feat = time.perf_counter() - t0_feat

    records = []
    for flow_feat in features_list:
        gt = map_multi_capture_ground_truth(flow_feat, capture_id)
        if gt != "UNKNOWN_EXCLUDED":
            rec = {
                "flow_id": flow_feat.flow_id,
                "capture_id": capture_id,
                "src_ip": flow_feat.src_ip,
                "dst_ip": flow_feat.dst_ip,
                "src_port": flow_feat.src_port,
                "dst_port": flow_feat.dst_port,
                "protocol": flow_feat.protocol,
                "start_time": flow_feat.start_time,
                "end_time": flow_feat.end_time,
                "ground_truth": gt,
                **{feat: getattr(flow_feat, feat) for feat in ALL_PREDICTIVE_FEATURES},
            }
            records.append(rec)

    df = pd.DataFrame(records)
    timings = {
        "packet_count": len(packets),
        "flow_count": len(flows),
        "eval_flow_count": len(df),
        "parse_time_sec": t_parse,
        "agg_time_sec": t_agg,
        "feat_time_sec": t_feat,
    }
    return df, timings


def run_multi_capture_evaluation():
    print("=" * 85)
    print("UNIGUARD AI (SIH26145) — Phase 3E Expanded Multi-Capture Real-World Validation")
    print("Zero Retraining / Evaluated Across 4 Independent Unseen Physical PCAPs")
    print("=" * 85)

    raw_dir = Path(__file__).parent.parent.parent / "data" / "raw"
    real_models_dir = Path(__file__).parent / "models" / "real_world"
    synth_models_dir = Path(__file__).parent / "models"

    # Load Phase 3D Real-World Model Pipeline
    iso_forest_3d = joblib.load(real_models_dir / "isolation_forest_real.joblib")
    rf_clf_3d = joblib.load(real_models_dir / "supervised_classifier_real.joblib")
    preprocessor_3d = joblib.load(real_models_dir / "preprocessor_real.joblib")
    label_encoder_3d = joblib.load(real_models_dir / "label_encoder_real.joblib")

    # Load Phase 3B Synthetic Model Pipeline for Comparison
    pipe_3b = load_model_pipeline(synth_models_dir)

    test_captures = [
        ("UCAP172.31.69.25_Wed21.pcap", "Wed21_WebServer25", "Wednesday 21-02-2018 DDOS Victim Web Server (5.10 MB)"),
        ("UCAP172.31.69.25_Fri16.pcap", "Fri16_WebServer25", "Friday 16-02-2018 DoS-Hulk Victim Web Server (0.78 MB)"),
        ("capWIN-172.31.67.62_Wed21.pcap", "Wed21_Client62", "Wednesday 21-02-2018 Client Subnet (3.76 MB)"),
        ("capWIN-172.31.67.95_Fri02.pcap", "Fri02_Client95", "Friday 02-03-2018 Botnet Client Subnet (0.49 MB)"),
    ]

    capture_dfs = []
    capture_metrics_list = []
    total_packets = 0
    total_flows = 0

    print("\n[1/5] Extracting features across 4 independent unseen real captures...")
    for filename, cap_id, desc in test_captures:
        pcap_path = raw_dir / filename
        df_cap, timings = extract_test_capture(pcap_path, cap_id)
        total_packets += timings["packet_count"]
        total_flows += timings["flow_count"]
        capture_dfs.append(df_cap)
        print(f"      - {cap_id} ({desc}): {timings['packet_count']:,} pkts, {timings['flow_count']:,} flows -> {len(df_cap):,} evaluated")

    pooled_test_df = pd.concat(capture_dfs, ignore_index=True)
    print(f"\n      TOTAL EVALUATION DATASET: {len(pooled_test_df):,} flows ({total_packets:,} packets processed)")
    print(f"      Ground Truth Breakdown:\n{pooled_test_df['ground_truth'].value_counts().to_string()}")

    # 2. Transform Features via Phase 3D Preprocessor
    print("\n[2/5] Transforming features via Phase 3D fitted scaler (Zero Leakage)...")
    X_pooled_raw = pooled_test_df[ALL_PREDICTIVE_FEATURES].to_numpy(dtype=float)
    X_pooled_scaled_3d = preprocessor_3d.scaler.transform(X_pooled_raw)

    # 3. Model Inference & Timing
    print("\n[3/5] Running inference across entire pooled evaluation dataset...")
    t0_inf = time.perf_counter()
    y_pred_3d_idx = rf_clf_3d.predict(X_pooled_scaled_3d)
    anom_scores_3d = iso_forest_3d.decision_function(X_pooled_scaled_3d)
    anom_preds_3d = iso_forest_3d.predict(X_pooled_scaled_3d)
    t_inf_total = time.perf_counter() - t0_inf

    mean_inf_latency = (t_inf_total / len(pooled_test_df)) * 1000.0
    throughput_fps = len(pooled_test_df) / t_inf_total if t_inf_total > 0 else 0.0

    y_pred_3d_lbl = label_encoder_3d.inverse_transform(y_pred_3d_idx)
    pooled_test_df["pred_3d"] = y_pred_3d_lbl
    pooled_test_df["anom_score_3d"] = anom_scores_3d
    pooled_test_df["anom_pred_3d"] = anom_preds_3d

    # RF Probabilities
    if hasattr(rf_clf_3d, "predict_proba"):
        probs = rf_clf_3d.predict_proba(X_pooled_scaled_3d)
        pooled_test_df["max_confidence"] = np.max(probs, axis=1)

    # 4. Phase 3B (Synthetic) Inference for Head-to-Head Comparison
    X_pooled_scaled_3b = pipe_3b["preprocessor"].scaler.transform(X_pooled_raw)
    y_pred_3b_idx = pipe_3b["supervised_model"].predict(X_pooled_scaled_3b)
    y_pred_3b_lbl = pipe_3b["label_encoder"].inverse_transform(y_pred_3b_idx)
    anom_preds_3b = pipe_3b["anomaly_model"].predict(X_pooled_scaled_3b)
    pooled_test_df["pred_3b"] = y_pred_3b_lbl
    pooled_test_df["anom_pred_3b"] = anom_preds_3b

    # 5. Compute Per-Capture & Aggregate Metrics
    print("\n[4/5] Computing Multi-Capture & Aggregate Validation Metrics...")
    y_true_all = pooled_test_df["ground_truth"]
    y_pred_all = pooled_test_df["pred_3d"]

    acc_pooled_3d = accuracy_score(y_true_all, y_pred_all)
    macro_f1_3d = f1_score(y_true_all, y_pred_all, average="macro", zero_division=0)
    weighted_f1_3d = f1_score(y_true_all, y_pred_all, average="weighted", zero_division=0)
    macro_p_3d = precision_score(y_true_all, y_pred_all, average="macro", zero_division=0)
    macro_r_3d = recall_score(y_true_all, y_pred_all, average="macro", zero_division=0)

    # Phase 3B pooled metrics
    acc_pooled_3b = accuracy_score(y_true_all, y_pred_3b_lbl)
    macro_f1_3b = f1_score(y_true_all, y_pred_3b_lbl, average="macro", zero_division=0)

    # Benign False Positive Rate & Threat Recall
    benign_mask = y_true_all == ThreatClass.BENIGN.value
    threat_mask = ~benign_mask
    benign_total = int(np.sum(benign_mask))
    threat_total = int(np.sum(threat_mask))

    fp_3d = int(np.sum((y_pred_all != ThreatClass.BENIGN.value) & benign_mask))
    fp_rate_3d = (fp_3d / benign_total) * 100.0 if benign_total > 0 else 0.0

    fp_3b = int(np.sum((y_pred_3b_lbl != ThreatClass.BENIGN.value) & benign_mask))
    fp_rate_3b = (fp_3b / benign_total) * 100.0 if benign_total > 0 else 0.0

    # Isolation Forest Metrics
    iso_fpr_3d = float(np.mean(anom_preds_3d[benign_mask] == -1)) if benign_total > 0 else 0.0
    iso_recall_3d = float(np.mean(anom_preds_3d[threat_mask] == -1)) if threat_total > 0 else 0.0

    iso_fpr_3b = float(np.mean(anom_preds_3b[benign_mask] == -1)) if benign_total > 0 else 0.0
    iso_recall_3b = float(np.mean(anom_preds_3b[threat_mask] == -1)) if threat_total > 0 else 0.0

    print("\n--- PHASE 3E AGGREGATE MULTI-CAPTURE CLASSIFICATION REPORT (Phase 3D Model) ---")
    all_classes = sorted(list(set(y_true_all.unique()).union(set(y_pred_all.unique()))))
    print(classification_report(y_true_all, y_pred_all, labels=all_classes, digits=4, zero_division=0))
    print(f"Aggregate Accuracy:          {acc_pooled_3d:.4f} ({acc_pooled_3d*100:.2f}%)")
    print(f"Aggregate Macro F1:          {macro_f1_3d:.4f}")
    print(f"Benign False Positive Rate:  {fp_3d} / {benign_total} flows ({fp_rate_3d:.2f}%)")
    print(f"Isolation Forest Benign FPR: {iso_fpr_3d:.2%}")
    print(f"Isolation Forest Threat Recall: {iso_recall_3d:.2%}")

    print("\n--- AGGREGATE CONFUSION MATRIX ---")
    cm_pooled = confusion_matrix(y_true_all, y_pred_all, labels=all_classes)
    cm_df = pd.DataFrame(cm_pooled, index=[f"Actual {c}" for c in all_classes], columns=[f"Pred {c}" for c in all_classes])
    print(cm_df.to_string())

    print("\n[5/5] Multi-Capture Performance Breakdown:")
    for df_c in capture_dfs:
        c_id = df_c["capture_id"].iloc[0]
        y_t_c = df_c["ground_truth"]
        y_p_c = pooled_test_df.loc[df_c.index, "pred_3d"]
        acc_c = accuracy_score(y_t_c, y_p_c)
        f1_c = f1_score(y_t_c, y_p_c, average="macro", zero_division=0)
        b_mask = y_t_c == ThreatClass.BENIGN.value
        fp_c = int(np.sum((y_p_c != ThreatClass.BENIGN.value) & b_mask))
        fp_rate_c = (fp_c / int(np.sum(b_mask))) * 100.0 if np.sum(b_mask) > 0 else 0.0
        print(f"  Capture [{c_id:18s}]: Flows={len(df_c):5d} | Accuracy={acc_c*100:6.2f}% | Macro F1={f1_c:6.4f} | Benign FPR={fp_rate_c:5.2f}%")

    print("\n================================================================================")
    print("      HEAD-TO-HEAD COMPARISON: PHASE 3B (Synthetic) vs PHASE 3D (Real-Trained)")
    print("                 ON POOLED MULTI-CAPTURE TEST DATASET")
    print("================================================================================")
    print(f"  Metric                             Phase 3B (Synthetic)     Phase 3D (Real-Trained)")
    print(f"  -----------------------------------------------------------------------------")
    print(f"  Aggregate Accuracy:                 {acc_pooled_3b*100:6.2f}%                 {acc_pooled_3d*100:6.2f}%")
    print(f"  Aggregate Macro F1:                 {macro_f1_3b:6.4f}                  {macro_f1_3d:6.4f}")
    print(f"  Benign False Positive Rate:         {fp_rate_3b:6.2f}%                 {fp_rate_3d:6.2f}%")
    print(f"  Isolation Forest Benign FPR:        {iso_fpr_3b*100:6.2f}%                 {iso_fpr_3d*100:6.2f}%")
    print(f"  Isolation Forest Threat Recall:     {iso_recall_3b*100:6.2f}%                 {iso_recall_3d*100:6.2f}%")
    print(f"  Inference Latency (Mean):           {mean_inf_latency:6.4f} ms               {mean_inf_latency:6.4f} ms")
    print(f"  Inference Throughput:               {throughput_fps:6.0f} flows/sec          {throughput_fps:6.0f} flows/sec")
    print("================================================================================")

    return {
        "total_packets": total_packets,
        "total_flows": total_flows,
        "evaluated_flows": len(pooled_test_df),
        "aggregate_accuracy_3d": acc_pooled_3d,
        "aggregate_macro_f1_3d": macro_f1_3d,
        "aggregate_accuracy_3b": acc_pooled_3b,
        "aggregate_macro_f1_3b": macro_f1_3b,
        "benign_fpr_3d": fp_rate_3d,
        "benign_fpr_3b": fp_rate_3b,
        "iso_fpr_3d": iso_fpr_3d,
        "iso_recall_3d": iso_recall_3d,
        "iso_fpr_3b": iso_fpr_3b,
        "iso_recall_3b": iso_recall_3b,
        "mean_latency_ms": mean_inf_latency,
        "throughput_flows_sec": throughput_fps,
    }


if __name__ == "__main__":
    run_multi_capture_evaluation()
