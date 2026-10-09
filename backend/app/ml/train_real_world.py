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
from app.ml.model_registry import ModelMetadata, ModelEvaluationMetrics, load_model_pipeline


# Ground truth mapping for CSE-CIC-IDS2018 captures
def map_capture_ground_truth(flow, capture_id: str) -> str:
    src = flow.src_ip
    dst = flow.dst_ip

    # Known CSE-CIC-IDS2018 Attackers
    if src in ("18.218.115.60", "18.219.9.1"):
        return ThreatClass.RECON_SCAN.value
    if src.startswith("18.218.") and ("Thu" in capture_id or "15-02" in capture_id):
        return ThreatClass.DDOS.value
    if "Fri02" in capture_id and src.startswith("172.31.67."):
        # Client infected with Ares botnet on Friday 02-03-2018
        if flow.dst_port in (80, 443, 8080) and flow.packet_count >= 3:
            return ThreatClass.C2_BEACONING.value

    # Internal enterprise communications
    if (src.startswith("172.31.") and dst.startswith("172.31.")) or src == "172.31.0.2":
        return ThreatClass.BENIGN.value

    return "UNKNOWN_EXCLUDED"


def extract_capture_features(pcap_path: Path, capture_id: str) -> Tuple[pd.DataFrame, Dict[str, float]]:
    """Extracts 27 canonical UNIGUARD features from a real PCAP file."""
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
        gt = map_capture_ground_truth(flow_feat, capture_id)
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


def train_and_evaluate_real_world_pipeline():
    print("=" * 80)
    print("UNIGUARD AI (SIH26145) — Phase 3D Real-World Model Training Pipeline")
    print("Capture-Level Train / Validation / Test Independence")
    print("=" * 80)

    raw_dir = Path(__file__).parent.parent.parent / "data" / "raw"
    pcap_train_1 = raw_dir / "capEC2AMAZ-O4EL3NG-172.31.69.28.pcap"
    pcap_train_2 = raw_dir / "UCAP172.31.69.27_Wed14.pcap"
    pcap_val = raw_dir / "UCAP172.31.69.21_Thu15.pcap"
    pcap_test = raw_dir / "capWIN-172.31.67.95_Fri02.pcap"

    # 1. Feature Extraction Across Independent Real Captures
    print("\n[1/7] Extracting features from independent authentic PCAP captures...")
    df_tr1, t_tr1 = extract_capture_features(pcap_train_1, "Wed14_Server28")
    df_tr2, t_tr2 = extract_capture_features(pcap_train_2, "Wed14_Subnet27")
    df_val, t_val = extract_capture_features(pcap_val, "Thu15_Subnet21")
    df_test, t_test = extract_capture_features(pcap_test, "Fri02_Client95")

    # Combine Train captures
    train_df = pd.concat([df_tr1, df_tr2], ignore_index=True)
    val_df = df_val.copy().reset_index(drop=True)
    test_df = df_test.copy().reset_index(drop=True)

    print(f"      TRAIN Captures:      {len(train_df):,} flows (Captures: Wed14_Server28, Wed14_Subnet27)")
    print(f"      VALIDATION Capture:  {len(val_df):,} flows (Capture: Thu15_Subnet21)")
    print(f"      UNSEEN TEST Capture: {len(test_df):,} flows (Capture: Fri02_Client95)")

    # 2. Preprocessing & Leakage Audit
    print("\n[2/7] Preprocessing & Leakage Audit (Scaler fitted strictly on Train captures)...")
    preprocessor = MLPreprocessor(scaler_type="standard")
    matrices = preprocessor.fit_transform_features(train_df, val_df, test_df)
    X_train, X_val, X_test = matrices["X_train"], matrices["X_val"], matrices["X_test"]

    # Verify zero capture overlap
    train_caps = set(train_df["capture_id"].unique())
    val_caps = set(val_df["capture_id"].unique())
    test_caps = set(test_df["capture_id"].unique())
    assert len(train_caps.intersection(val_caps)) == 0, "Capture leakage between Train and Val!"
    assert len(train_caps.intersection(test_caps)) == 0, "Capture leakage between Train and Test!"
    print("      Capture-level split verification: PASSED (0 capture overlap across splits).")

    # Encode labels using the authoritative supported classes list
    label_encoder = LabelEncoder()
    label_encoder.fit(SUPPORTED_TRAINING_CLASSES)
    y_train = label_encoder.transform(train_df["ground_truth"])
    y_val = label_encoder.transform(val_df["ground_truth"])
    y_test = label_encoder.transform(test_df["ground_truth"])

    # 3. Train Model 1: Real-Data Isolation Forest (Anomaly Baseline)
    print("\n[3/7] Training Isolation Forest on REAL Benign baseline flows...")
    benign_mask_train = train_df["ground_truth"] == ThreatClass.BENIGN.value
    X_train_benign = X_train[benign_mask_train]

    iso_forest = IsolationForest(n_estimators=100, contamination=0.02, random_state=42)
    iso_forest.fit(X_train_benign)

    # Evaluate Anomaly Model on Unseen Test
    anom_scores_test = iso_forest.decision_function(X_test)
    anom_preds_test = iso_forest.predict(X_test)
    benign_mask_test = test_df["ground_truth"] == ThreatClass.BENIGN.value
    anom_fpr_benign_test = float(np.mean(anom_preds_test[benign_mask_test] == -1)) if np.sum(benign_mask_test) > 0 else 0.0
    threat_mask_test = ~benign_mask_test
    anom_recall_threat_test = float(np.mean(anom_preds_test[threat_mask_test] == -1)) if np.sum(threat_mask_test) > 0 else 0.0

    print(f"      Isolation Forest FPR on Unseen Real Benign Test: {anom_fpr_benign_test:.2%}")
    print(f"      Isolation Forest Recall on Unseen Threat Test:   {anom_recall_threat_test:.2%}")

    # 4. Train & Compare Supervised Classifier Candidates
    print("\n[4/7] Training and comparing candidate models on real validation capture...")
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

    # 5. Final Evaluation on Unseen Real Test Capture (Fri02_Client95)
    print("\n[5/7] Evaluating winner model on UNSEEN REAL TEST CAPTURE (Fri02_Client95)...")
    t0_infer = time.perf_counter()
    y_test_pred = selected_model.predict(X_test)
    total_test_infer_time = time.perf_counter() - t0_infer
    mean_infer_latency = (total_test_infer_time / len(X_test)) * 1000.0

    test_acc = float(accuracy_score(y_test, y_test_pred))
    test_f1_macro = float(f1_score(y_test, y_test_pred, average="macro", zero_division=0))
    test_f1_weighted = float(f1_score(y_test, y_test_pred, average="weighted", zero_division=0))
    test_precision_macro = float(precision_score(y_test, y_test_pred, average="macro", zero_division=0))
    test_recall_macro = float(recall_score(y_test, y_test_pred, average="macro", zero_division=0))

    # Phase 3D Benign FP Rate on Unseen Test
    y_test_pred_lbl = label_encoder.inverse_transform(y_test_pred)
    benign_fp_count = int(np.sum((y_test_pred_lbl != ThreatClass.BENIGN.value) & benign_mask_test))
    benign_fp_rate = (benign_fp_count / int(benign_mask_test.sum())) * 100.0 if benign_mask_test.sum() > 0 else 0.0

    all_class_indices = np.arange(len(label_encoder.classes_))
    print("\n--- PHASE 3D UNSEEN TEST CLASSIFICATION REPORT ---")
    print(classification_report(y_test, y_test_pred, labels=all_class_indices, target_names=label_encoder.classes_, digits=4, zero_division=0))
    print(f"Phase 3D Unseen Test Accuracy:       {test_acc:.4f} ({test_acc*100:.2f}%)")
    print(f"Phase 3D Unseen Test Macro F1:       {test_f1_macro:.4f}")
    print(f"Phase 3D Benign False Positive Rate: {benign_fp_count} / {int(benign_mask_test.sum())} ({benign_fp_rate:.2f}%)")

    # 6. Comparison: Phase 3B (Synthetic-Trained) vs Phase 3D (Real-Trained) on Same Unseen Test Capture
    print("\n[6/7] Comparing Phase 3B (Synthetic-Trained) vs Phase 3D (Real-Trained) on Unseen Capture...")
    models_3b_dir = Path(__file__).parent / "models"
    pipe_3b = load_model_pipeline(models_3b_dir)

    X_test_3b_scaled = pipe_3b["preprocessor"].scaler.transform(test_df[ALL_PREDICTIVE_FEATURES].to_numpy(dtype=float))
    preds_3b_idx = pipe_3b["supervised_model"].predict(X_test_3b_scaled)
    preds_3b_lbl = pipe_3b["label_encoder"].inverse_transform(preds_3b_idx)

    acc_3b = float(accuracy_score(test_df["ground_truth"], preds_3b_lbl))
    f1_3b = float(f1_score(test_df["ground_truth"], preds_3b_lbl, average="macro", zero_division=0))
    fp_3b = int(np.sum((preds_3b_lbl != ThreatClass.BENIGN.value) & benign_mask_test))
    fp_rate_3b = (fp_3b / int(benign_mask_test.sum())) * 100.0 if benign_mask_test.sum() > 0 else 0.0

    print("\n================================================================================")
    print("                PHASE 3B (Synthetic) vs PHASE 3D (Real-Data Trained)")
    print("                          ON UNSEEN REAL TEST CAPTURE")
    print("================================================================================")
    print(f"  Metric                     Phase 3B (Synthetic)     Phase 3D (Real-Trained)")
    print(f"  -----------------------------------------------------------------------------")
    print(f"  Unseen Test Accuracy:       {acc_3b*100:6.2f}%                 {test_acc*100:6.2f}%")
    print(f"  Unseen Test Macro F1:       {f1_3b:6.4f}                  {test_f1_macro:6.4f}")
    print(f"  Benign False Positive Rate: {fp_rate_3b:6.2f}%                 {benign_fp_rate:6.2f}%")
    print("================================================================================")

    # 7. Save Phase 3D Artifacts to backend/app/ml/models/real_world/
    out_dir = Path(__file__).parent / "models" / "real_world"
    out_dir.mkdir(parents=True, exist_ok=True)

    joblib.dump(iso_forest, out_dir / "isolation_forest_real.joblib")
    joblib.dump(selected_model, out_dir / "supervised_classifier_real.joblib")
    joblib.dump(preprocessor, out_dir / "preprocessor_real.joblib")
    joblib.dump(label_encoder, out_dir / "label_encoder_real.joblib")

    feature_importance_dict = {}
    if hasattr(selected_model, "feature_importances_"):
        for fname, imp in zip(ALL_PREDICTIVE_FEATURES, selected_model.feature_importances_):
            feature_importance_dict[fname] = round(float(imp), 5)
    sorted_importance = dict(sorted(feature_importance_dict.items(), key=lambda item: item[1], reverse=True))

    metadata = {
        "model_name": "uniguard-real-world-detector",
        "model_version": "2.0.0",
        "feature_schema_version": "2.0.0",
        "feature_count": 27,
        "features": ALL_PREDICTIVE_FEATURES,
        "training_capture_ids": ["Wed14_Server28", "Wed14_Subnet27"],
        "validation_capture_ids": ["Thu15_Subnet21"],
        "unseen_test_capture_ids": ["Fri02_Client95"],
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "supervised_algorithm": selected_name,
        "anomaly_algorithm": "IsolationForest",
        "validation_metrics": {
            "accuracy": round(rf_val_acc, 4),
            "macro_f1": round(rf_val_f1, 4),
        },
        "unseen_test_metrics": {
            "accuracy": round(test_acc, 4),
            "macro_f1": round(test_f1_macro, 4),
            "weighted_f1": round(test_f1_weighted, 4),
            "macro_precision": round(test_precision_macro, 4),
            "macro_recall": round(test_recall_macro, 4),
            "benign_false_positive_rate": round(benign_fp_rate, 2),
            "mean_inference_latency_ms": round(mean_infer_latency, 5),
        },
        "comparison_vs_phase_3b": {
            "phase_3b_accuracy": round(acc_3b, 4),
            "phase_3b_false_positive_rate": round(fp_rate_3b, 2),
            "phase_3d_accuracy": round(test_acc, 4),
            "phase_3d_false_positive_rate": round(benign_fp_rate, 2),
        },
        "feature_importance": sorted_importance,
    }

    with open(out_dir / "model_metadata_real.json", "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"\n[SUCCESS] Phase 3D Real-World model artifacts saved to: {out_dir}")
    print("=" * 80)
    return metadata


if __name__ == "__main__":
    train_and_evaluate_real_world_pipeline()
