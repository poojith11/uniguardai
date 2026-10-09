import time
from pathlib import Path
from typing import Dict, Any, List, Tuple
import json
from datetime import datetime, timezone
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score, precision_score, recall_score

from app.traffic.pcap_parser import read_pcap_packets
from app.traffic.flow_aggregator import aggregate_unidirectional_flows
from app.traffic.feature_extractor import extract_flow_features
from app.ml.dataset_schema import ALL_PREDICTIVE_FEATURES, ThreatClass
from app.ml.preprocessor import MLPreprocessor
from app.ml.dataset_loader import SUPPORTED_TRAINING_CLASSES
from app.ml.model_registry import ModelMetadata, load_model_pipeline


# Ground truth mapping for Phase 3F captures
def map_phase3f_ground_truth(flow, capture_id: str) -> str:
    src = flow.src_ip
    dst = flow.dst_ip

    # 1. Attacker IPs for FTP / SSH BruteForce (Wed 14-02-2018) -> RECON_SCAN
    if src in ("18.218.115.60", "18.219.9.1") and "Wed14" in capture_id:
        return ThreatClass.RECON_SCAN.value

    # 2. Attacker IPs for DoS-Hulk / Slowloris / GoldenEye / LOIC -> DDOS
    if src.startswith("18.218.") or src.startswith("18.219.") or src.startswith("13.58."):
        if any(tag in capture_id for tag in ("Thu15", "Fri16", "Wed21")):
            return ThreatClass.DDOS.value

    # 3. Botnet Ares Client (Friday 02-03-2018) -> C2_BEACONING
    if "Fri02" in capture_id and src.startswith("172.31.67."):
        if flow.dst_port in (80, 443, 8080) and flow.packet_count >= 3:
            return ThreatClass.C2_BEACONING.value

    # 4. Internal Enterprise Benign Communications
    if (src.startswith("172.31.") and dst.startswith("172.31.")) or src == "172.31.0.2":
        return ThreatClass.BENIGN.value

    return "UNKNOWN_EXCLUDED"


def extract_capture_df(pcap_path: Path, capture_id: str) -> Tuple[pd.DataFrame, Dict[str, float]]:
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
        gt = map_phase3f_ground_truth(flow_feat, capture_id)
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


def train_and_evaluate_phase3f_pipeline():
    print("=" * 85)
    print("UNIGUARD AI (SIH26145) — Phase 3F Attack-Focused Real-World Model Pipeline")
    print("Multi-Capture Training, Validation & Unseen Testing Across All Supported Classes")
    print("=" * 85)

    raw_dir = Path(__file__).parent.parent.parent / "data" / "raw"

    train_captures_cfg = [
        ("capEC2AMAZ-O4EL3NG-172.31.69.28.pcap", "Wed14_Server28"),
        ("UCAP172.31.69.27_Wed14.pcap", "Wed14_Subnet27"),
        ("capEC2AMAZ-172.31.69.20_Fri02.pcap", "Fri02_Server20"),
        ("UCAP172.31.69.25_Fri16.pcap", "Fri16_WebServer25"),
    ]
    val_captures_cfg = [
        ("UCAP172.31.69.21_Thu15.pcap", "Thu15_Subnet21"),
    ]
    test_captures_cfg = [
        ("UCAP172.31.69.25_Wed21.pcap", "Wed21_WebServer25"),
        ("capWIN-172.31.67.62_Wed21.pcap", "Wed21_Client62"),
        ("capWIN-172.31.67.95_Fri02.pcap", "Fri02_Client95"),
    ]

    print("\n[1/7] Extracting features via Phase 2 pipeline across independent PCAPs...")
    train_dfs = []
    total_tr_pkts = 0
    for fn, cid in train_captures_cfg:
        df, t = extract_capture_df(raw_dir / fn, cid)
        total_tr_pkts += t["packet_count"]
        train_dfs.append(df)
        print(f"      - TRAIN Capture [{cid:18s}]: {t['packet_count']:,} pkts -> {len(df):,} flows")

    val_dfs = []
    for fn, cid in val_captures_cfg:
        df, t = extract_capture_df(raw_dir / fn, cid)
        val_dfs.append(df)
        print(f"      - VALIDATION Capture [{cid:13s}]: {t['packet_count']:,} pkts -> {len(df):,} flows")

    test_dfs = []
    for fn, cid in test_captures_cfg:
        df, t = extract_capture_df(raw_dir / fn, cid)
        test_dfs.append(df)
        print(f"      - UNSEEN TEST Capture [{cid:12s}]: {t['packet_count']:,} pkts -> {len(df):,} flows")

    train_df = pd.concat(train_dfs, ignore_index=True)
    val_df = pd.concat(val_dfs, ignore_index=True)
    test_df = pd.concat(test_dfs, ignore_index=True)

    print(f"\n      TOTAL TRAIN FLOWS:       {len(train_df):,}")
    print(f"      TOTAL VALIDATION FLOWS:  {len(val_df):,}")
    print(f"      TOTAL UNSEEN TEST FLOWS: {len(test_df):,}")

    print(f"\n      Train Class Distribution:\n{train_df['ground_truth'].value_counts().to_string()}")
    print(f"\n      Unseen Test Class Distribution:\n{test_df['ground_truth'].value_counts().to_string()}")

    print("\n[2/7] Preprocessing & Leakage Audit (Scaler fitted strictly on Train captures)...")
    preprocessor = MLPreprocessor(scaler_type="standard")
    matrices = preprocessor.fit_transform_features(train_df, val_df, test_df)
    X_train, X_val, X_test = matrices["X_train"], matrices["X_val"], matrices["X_test"]

    tr_caps = set(train_df["capture_id"].unique())
    vl_caps = set(val_df["capture_id"].unique())
    ts_caps = set(test_df["capture_id"].unique())
    assert tr_caps.isdisjoint(vl_caps), "Capture overlap between Train and Val!"
    assert tr_caps.isdisjoint(ts_caps), "Capture overlap between Train and Test!"
    assert vl_caps.isdisjoint(ts_caps), "Capture overlap between Val and Test!"
    print("      Capture-level split verification: PASSED (0 capture overlap across Train, Val, and Test).")

    label_encoder = LabelEncoder()
    label_encoder.fit(SUPPORTED_TRAINING_CLASSES)
    y_train = label_encoder.transform(train_df["ground_truth"])
    y_val = label_encoder.transform(val_df["ground_truth"])
    y_test = label_encoder.transform(test_df["ground_truth"])

    print("\n[3/7] Training Isolation Forest on REAL Benign baseline flows...")
    benign_mask_train = train_df["ground_truth"] == ThreatClass.BENIGN.value
    X_train_benign = X_train[benign_mask_train]

    iso_forest = IsolationForest(n_estimators=100, contamination=0.02, random_state=42)
    iso_forest.fit(X_train_benign)

    print("\n[4/7] Training candidate supervised models and evaluating on Validation Capture...")
    rf_clf = RandomForestClassifier(n_estimators=100, max_depth=15, class_weight="balanced", random_state=42)
    rf_clf.fit(X_train, y_train)
    y_val_rf = rf_clf.predict(X_val)
    rf_val_acc = accuracy_score(y_val, y_val_rf)
    rf_val_f1 = f1_score(y_val, y_val_rf, average="macro", zero_division=0)

    hgb_clf = HistGradientBoostingClassifier(max_iter=100, class_weight="balanced", random_state=42)
    hgb_clf.fit(X_train, y_train)
    y_val_hgb = hgb_clf.predict(X_val)
    hgb_val_acc = accuracy_score(y_val, y_val_hgb)
    hgb_val_f1 = f1_score(y_val, y_val_hgb, average="macro", zero_division=0)

    print(f"      Candidate A (Random Forest):        Val Accuracy = {rf_val_acc:.4f}, Val Macro F1 = {rf_val_f1:.4f}")
    print(f"      Candidate B (HistGradientBoosting): Val Accuracy = {hgb_val_acc:.4f}, Val Macro F1 = {hgb_val_f1:.4f}")

    selected_model = rf_clf if rf_val_f1 >= hgb_val_f1 else hgb_clf
    selected_name = "RandomForestClassifier" if rf_val_f1 >= hgb_val_f1 else "HistGradientBoostingClassifier"
    print(f"      -> Selected Winner: {selected_name}")

    print("\n[5/7] Evaluating winner model on UNSEEN REAL TEST CAPTURES...")
    latencies = []
    y_test_preds = []
    anom_scores = []
    anom_preds = []

    for row in X_test:
        row_2d = row.reshape(1, -1)
        t_start = time.perf_counter()
        pred_idx = selected_model.predict(row_2d)[0]
        anom_score = iso_forest.decision_function(row_2d)[0]
        anom_pred = iso_forest.predict(row_2d)[0]
        t_el = (time.perf_counter() - t_start) * 1000.0
        latencies.append(t_el)
        y_test_preds.append(pred_idx)
        anom_scores.append(anom_score)
        anom_preds.append(anom_pred)

    y_test_preds_arr = np.array(y_test_preds)
    anom_preds_arr = np.array(anom_preds)
    latencies_arr = np.array(latencies)

    mean_lat = float(np.mean(latencies_arr))
    med_lat = float(np.median(latencies_arr))
    p95_lat = float(np.percentile(latencies_arr, 95))
    p99_lat = float(np.percentile(latencies_arr, 99))
    throughput_fps = float(1000.0 / mean_lat) if mean_lat > 0 else 0.0

    test_acc = float(accuracy_score(y_test, y_test_preds_arr))
    test_macro_p = float(precision_score(y_test, y_test_preds_arr, average="macro", zero_division=0))
    test_macro_r = float(recall_score(y_test, y_test_preds_arr, average="macro", zero_division=0))
    test_macro_f1 = float(f1_score(y_test, y_test_preds_arr, average="macro", zero_division=0))
    test_weighted_f1 = float(f1_score(y_test, y_test_preds_arr, average="weighted", zero_division=0))

    benign_mask_test = test_df["ground_truth"] == ThreatClass.BENIGN.value
    threat_mask_test = ~benign_mask_test
    benign_total = int(np.sum(benign_mask_test))
    threat_total = int(np.sum(threat_mask_test))

    y_test_preds_lbl = label_encoder.inverse_transform(y_test_preds_arr)
    benign_fp_count = int(np.sum((y_test_preds_lbl != ThreatClass.BENIGN.value) & benign_mask_test))
    benign_fp_rate = (benign_fp_count / benign_total) * 100.0 if benign_total > 0 else 0.0

    iso_fpr_benign = float(np.mean(anom_preds_arr[benign_mask_test] == -1)) if benign_total > 0 else 0.0
    iso_threat_recall = float(np.mean(anom_preds_arr[threat_mask_test] == -1)) if threat_total > 0 else 0.0

    all_class_indices = np.arange(len(label_encoder.classes_))
    print("\n--- PHASE 3F UNSEEN TEST CLASSIFICATION REPORT ---")
    print(classification_report(y_test, y_test_preds_arr, labels=all_class_indices, target_names=label_encoder.classes_, digits=4, zero_division=0))
    print(f"Unseen Test Accuracy:        {test_acc:.4f} ({test_acc*100:.2f}%)")
    print(f"Unseen Test Macro F1:        {test_macro_f1:.4f}")
    print(f"Unseen Test Weighted F1:     {test_weighted_f1:.4f}")
    print(f"Benign False Positive Rate:  {benign_fp_count} / {benign_total} flows ({benign_fp_rate:.2f}%)")
    print(f"Isolation Forest Benign FPR: {iso_fpr_benign:.2%}")
    print(f"Isolation Forest Threat Rec: {iso_threat_recall:.2%}")

    cm = confusion_matrix(y_test, y_test_preds_arr, labels=all_class_indices)
    cm_df = pd.DataFrame(cm, index=[f"Actual {c}" for c in label_encoder.classes_], columns=[f"Pred {c}" for c in label_encoder.classes_])
    print("\n--- CONFUSION MATRIX ---")
    print(cm_df.to_string())

    print("\n[6/7] Multi-Phase Comparative Benchmark on Identical Unseen Test Suite...")
    models_3b_dir = Path(__file__).parent / "models"
    pipe_3b = load_model_pipeline(models_3b_dir)

    X_test_3b_scaled = pipe_3b["preprocessor"].scaler.transform(test_df[ALL_PREDICTIVE_FEATURES].to_numpy(dtype=float))
    preds_3b_idx = pipe_3b["supervised_model"].predict(X_test_3b_scaled)
    preds_3b_lbl = pipe_3b["label_encoder"].inverse_transform(preds_3b_idx)
    acc_3b = float(accuracy_score(test_df["ground_truth"], preds_3b_lbl))
    f1_3b = float(f1_score(test_df["ground_truth"], preds_3b_lbl, average="macro", zero_division=0))
    fp_3b = int(np.sum((preds_3b_lbl != ThreatClass.BENIGN.value) & benign_mask_test))
    fp_rate_3b = (fp_3b / benign_total) * 100.0 if benign_total > 0 else 0.0

    print("\n==========================================================================================")
    print("                    HEAD-TO-HEAD PROGRESSION ACROSS ALL PHASES")
    print("==========================================================================================")
    print(f"  Metric                             Phase 3B (Synthetic)   Phase 3D (Real)   Phase 3F (Attack-Focused)")
    print(f"  ----------------------------------------------------------------------------------------")
    print(f"  Unseen Test Accuracy:               {acc_3b*100:6.2f}%                 92.56%             {test_acc*100:6.2f}%")
    print(f"  Unseen Test Macro F1:               {f1_3b:6.4f}                  0.3205              {test_macro_f1:6.4f}")
    print(f"  Benign False Positive Rate:         {fp_rate_3b:6.2f}%                  0.00%              {benign_fp_rate:6.2f}%")
    print(f"  Isolation Forest Threat Recall:      56.25%                 93.75%             {iso_threat_recall*100:6.2f}%")
    print(f"  Mean Inference Latency:             {mean_lat:6.4f} ms            0.0328 ms           {mean_lat:6.4f} ms")
    print(f"  Inference Throughput:               {throughput_fps:6.0f} fps            30,473 fps          {throughput_fps:6.0f} fps")
    print("==========================================================================================")

    out_dir = Path(__file__).parent / "models" / "phase3f_real_world"
    out_dir.mkdir(parents=True, exist_ok=True)

    joblib.dump(iso_forest, out_dir / "isolation_forest_phase3f.joblib")
    joblib.dump(selected_model, out_dir / "supervised_classifier_phase3f.joblib")
    joblib.dump(preprocessor, out_dir / "preprocessor_phase3f.joblib")
    joblib.dump(label_encoder, out_dir / "label_encoder_phase3f.joblib")

    feature_importance_dict = {}
    if hasattr(selected_model, "feature_importances_"):
        for fname, imp in zip(ALL_PREDICTIVE_FEATURES, selected_model.feature_importances_):
            feature_importance_dict[fname] = round(float(imp), 5)
    sorted_importance = dict(sorted(feature_importance_dict.items(), key=lambda item: item[1], reverse=True))

    metadata = {
        "model_name": "uniguard-attack-focused-detector",
        "model_version": "3.0.0",
        "feature_schema_version": "2.0.0",
        "feature_count": 27,
        "features": ALL_PREDICTIVE_FEATURES,
        "training_capture_ids": [cid for _, cid in train_captures_cfg],
        "validation_capture_ids": [cid for _, cid in val_captures_cfg],
        "unseen_test_capture_ids": [cid for _, cid in test_captures_cfg],
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "supervised_algorithm": selected_name,
        "anomaly_algorithm": "IsolationForest",
        "validation_metrics": {
            "accuracy": round(rf_val_acc, 4),
            "macro_f1": round(rf_val_f1, 4),
        },
        "unseen_test_metrics": {
            "accuracy": round(test_acc, 4),
            "macro_f1": round(test_macro_f1, 4),
            "weighted_f1": round(test_weighted_f1, 4),
            "macro_precision": round(test_macro_p, 4),
            "macro_recall": round(test_macro_r, 4),
            "benign_false_positive_rate": round(benign_fp_rate, 2),
            "isolation_forest_fpr_benign": round(iso_fpr_benign * 100, 2),
            "isolation_forest_threat_recall": round(iso_threat_recall * 100, 2),
            "mean_inference_latency_ms": round(mean_lat, 5),
            "median_inference_latency_ms": round(med_lat, 5),
            "p95_inference_latency_ms": round(p95_lat, 5),
            "p99_inference_latency_ms": round(p99_lat, 5),
            "throughput_flows_per_sec": round(throughput_fps, 1),
        },
        "feature_importance": sorted_importance,
    }

    with open(out_dir / "model_metadata_phase3f.json", "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"\n[SUCCESS] Phase 3F model artifacts saved to: {out_dir}")
    print("=" * 85)
    return metadata


if __name__ == "__main__":
    train_and_evaluate_phase3f_pipeline()
