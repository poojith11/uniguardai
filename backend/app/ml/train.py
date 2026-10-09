import time
from pathlib import Path
from datetime import datetime, timezone
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score, precision_score, recall_score

from .dataset_schema import ALL_PREDICTIVE_FEATURES, ThreatClass
from .dataset_loader import load_training_dataset, SUPPORTED_TRAINING_CLASSES, UNSUPPORTED_TRAINING_CLASSES
from .preprocessor import MLPreprocessor
from .model_registry import ModelMetadata, ModelEvaluationMetrics, save_model_pipeline


def train_ml_pipeline(
    data_path: Path = None,
    output_dir: Path = None,
    random_state: int = 42,
) -> ModelMetadata:
    """
    Executes the reproducible UNIGUARD AI Phase 3B training pipeline.
    Trains Isolation Forest (Anomaly Baseline) and Supervised Multi-Class Classifier.
    """
    out_dir = output_dir or (Path(__file__).parent / "models")
    print("=" * 70)
    print("UNIGUARD AI (SIH26145) — Phase 3B Machine Learning Training Engine")
    print("=" * 70)

    # 1. Load Dataset
    print(f"\n[1/7] Ingesting verified dataset (Random State: {random_state})...")
    df = load_training_dataset(data_path)
    print(f"      Total records loaded: {len(df):,}")
    print(f"      Supported classes: {SUPPORTED_TRAINING_CLASSES}")
    print(f"      Explicitly unsupported classes: {UNSUPPORTED_TRAINING_CLASSES}")
    print(f"      Class breakdown:\n{df['label'].value_counts().to_string()}")

    # 2. Stratified Preprocessing & Splitting
    print("\n[2/7] Executing zero-leakage stratified train/val/test split (70% / 15% / 15%)...")
    preprocessor = MLPreprocessor(scaler_type="standard")
    train_df, val_df, test_df = preprocessor.split_dataset(
        df,
        label_col="label",
        test_size=0.15,
        val_size=0.15,
        random_state=random_state,
    )
    print(f"      Training set:   {len(train_df):,} samples ({len(train_df)/len(df):.1%})")
    print(f"      Validation set: {len(val_df):,} samples ({len(val_df)/len(df):.1%})")
    print(f"      Test set:       {len(test_df):,} samples ({len(test_df)/len(df):.1%})")

    # Fit scaler strictly on Train features
    matrices = preprocessor.fit_transform_features(train_df, val_df, test_df)
    X_train, X_val, X_test = matrices["X_train"], matrices["X_val"], matrices["X_test"]

    # Encode labels
    label_encoder = LabelEncoder()
    label_encoder.fit(SUPPORTED_TRAINING_CLASSES)
    y_train = label_encoder.transform(train_df["label"])
    y_val = label_encoder.transform(val_df["label"])
    y_test = label_encoder.transform(test_df["label"])

    # 3. Train Model 1: Isolation Forest (Unsupervised Anomaly Baseline)
    print("\n[3/7] Training Isolation Forest on Benign baseline flows...")
    benign_mask_train = train_df["label"] == ThreatClass.BENIGN.value
    X_train_benign = X_train[benign_mask_train]

    anomaly_hyperparams = {
        "n_estimators": 100,
        "max_samples": "auto",
        "contamination": 0.02,
        "random_state": random_state,
    }
    iso_forest = IsolationForest(**anomaly_hyperparams)
    iso_forest.fit(X_train_benign)

    # Evaluate Anomaly Baseline on Test
    t0_anom = time.perf_counter()
    raw_scores_test = iso_forest.decision_function(X_test)
    preds_test_anom = iso_forest.predict(X_test)  # 1 = normal, -1 = anomaly
    anom_latency_ms = ((time.perf_counter() - t0_anom) / len(X_test)) * 1000.0

    benign_mask_test = test_df["label"] == ThreatClass.BENIGN.value
    fpr_benign = float(np.mean(preds_test_anom[benign_mask_test] == -1))
    threat_detection_rate = float(np.mean(preds_test_anom[~benign_mask_test] == -1))

    anomaly_baseline_metrics = {
        "score_mean": float(np.mean(raw_scores_test)),
        "score_std": float(np.std(raw_scores_test)),
        "score_min": float(np.min(raw_scores_test)),
        "score_max": float(np.max(raw_scores_test)),
        "false_positive_rate_benign": round(fpr_benign, 4),
        "threat_detection_recall": round(threat_detection_rate, 4),
        "inference_latency_ms_per_flow": round(anom_latency_ms, 5),
    }
    print(f"      Anomaly baseline FPR on Benign Test: {fpr_benign:.2%}")
    print(f"      Anomaly baseline Threat Recall:       {threat_detection_rate:.2%}")
    print(f"      Anomaly Inference Latency:           {anom_latency_ms:.4f} ms/flow")

    # 4. Train Supervised Classifier Candidates
    print("\n[4/7] Training supervised candidate models (Random Forest vs Gradient Boosting)...")

    # Candidate A: Random Forest
    rf_hyperparams = {
        "n_estimators": 100,
        "max_depth": 15,
        "class_weight": "balanced",
        "random_state": random_state,
        "n_jobs": -1,
    }
    clf_rf = RandomForestClassifier(**rf_hyperparams)
    clf_rf.fit(X_train, y_train)

    # Candidate B: HistGradientBoosting
    hgb_hyperparams = {
        "max_iter": 100,
        "max_depth": 10,
        "class_weight": "balanced",
        "random_state": random_state,
    }
    clf_hgb = HistGradientBoostingClassifier(**hgb_hyperparams)
    clf_hgb.fit(X_train, y_train)

    # 5. Evaluate on Validation Set
    print("\n[5/7] Evaluating candidate models on held-out Validation set...")
    # Evaluate RF on Val
    t0_rf = time.perf_counter()
    y_val_pred_rf = clf_rf.predict(X_val)
    rf_val_latency = ((time.perf_counter() - t0_rf) / len(X_val)) * 1000.0
    rf_val_f1_macro = f1_score(y_val, y_val_pred_rf, average="macro")
    rf_val_acc = accuracy_score(y_val, y_val_pred_rf)

    # Evaluate HGB on Val
    t0_hgb = time.perf_counter()
    y_val_pred_hgb = clf_hgb.predict(X_val)
    hgb_val_latency = ((time.perf_counter() - t0_hgb) / len(X_val)) * 1000.0
    hgb_val_f1_macro = f1_score(y_val, y_val_pred_hgb, average="macro")
    hgb_val_acc = accuracy_score(y_val, y_val_pred_hgb)

    print(f"      Candidate A (Random Forest):          Macro F1 = {rf_val_f1_macro:.4f}, Accuracy = {rf_val_acc:.4f}, Latency = {rf_val_latency:.4f} ms")
    print(f"      Candidate B (HistGradientBoosting):   Macro F1 = {hgb_val_f1_macro:.4f}, Accuracy = {hgb_val_acc:.4f}, Latency = {hgb_val_latency:.4f} ms")

    # Select best model based on Validation Macro F1
    if rf_val_f1_macro >= hgb_val_f1_macro:
        selected_model = clf_rf
        selected_algo = "RandomForestClassifier"
        selected_hyperparams = rf_hyperparams
        val_preds = y_val_pred_rf
        val_latency = rf_val_latency
        print(f"\n      -> Selected Winner: Random Forest Classifier (Macro F1: {rf_val_f1_macro:.4f})")
    else:
        selected_model = clf_hgb
        selected_algo = "HistGradientBoostingClassifier"
        selected_hyperparams = hgb_hyperparams
        val_preds = y_val_pred_hgb
        val_latency = hgb_val_latency
        print(f"\n      -> Selected Winner: HistGradientBoosting (Macro F1: {hgb_val_f1_macro:.4f})")

    # 6. Final Evaluation on Held-out Test Set
    print("\n[6/7] Running final unbiased evaluation on held-out Test set...")
    t0_test = time.perf_counter()
    y_test_pred = selected_model.predict(X_test)
    test_latency = ((time.perf_counter() - t0_test) / len(X_test)) * 1000.0

    # Metrics
    val_report = classification_report(y_val, val_preds, target_names=label_encoder.classes_, output_dict=True, zero_division=0)
    val_cm = confusion_matrix(y_val, val_preds).tolist()
    val_metrics = ModelEvaluationMetrics(
        accuracy=round(accuracy_score(y_val, val_preds), 4),
        macro_f1=round(f1_score(y_val, val_preds, average="macro"), 4),
        weighted_f1=round(f1_score(y_val, val_preds, average="weighted"), 4),
        macro_precision=round(precision_score(y_val, val_preds, average="macro", zero_division=0), 4),
        macro_recall=round(recall_score(y_val, val_preds, average="macro", zero_division=0), 4),
        inference_latency_ms=round(val_latency, 5),
        confusion_matrix=val_cm,
        per_class_report=val_report,
    )

    test_report = classification_report(y_test, y_test_pred, target_names=label_encoder.classes_, output_dict=True, zero_division=0)
    test_cm = confusion_matrix(y_test, y_test_pred).tolist()
    test_metrics = ModelEvaluationMetrics(
        accuracy=round(accuracy_score(y_test, y_test_pred), 4),
        macro_f1=round(f1_score(y_test, y_test_pred, average="macro"), 4),
        weighted_f1=round(f1_score(y_test, y_test_pred, average="weighted"), 4),
        macro_precision=round(precision_score(y_test, y_test_pred, average="macro", zero_division=0), 4),
        macro_recall=round(recall_score(y_test, y_test_pred, average="macro", zero_division=0), 4),
        inference_latency_ms=round(test_latency, 5),
        confusion_matrix=test_cm,
        per_class_report=test_report,
    )

    print("\n--- TEST SET CLASSIFICATION REPORT ---")
    print(classification_report(y_test, y_test_pred, target_names=label_encoder.classes_, digits=4, zero_division=0))
    print(f"Test Accuracy:          {test_metrics.accuracy:.4f}")
    print(f"Test Macro F1:          {test_metrics.macro_f1:.4f}")
    print(f"Test Weighted F1:       {test_metrics.weighted_f1:.4f}")
    print(f"Test Inference Latency: {test_metrics.inference_latency_ms:.4f} ms/flow")

    # 7. Genuine Feature Importance
    print("\n[7/7] Computing genuine global feature importances...")
    feature_importance_dict = {}
    if hasattr(selected_model, "feature_importances_"):
        raw_importances = selected_model.feature_importances_
        for feat_name, imp in zip(ALL_PREDICTIVE_FEATURES, raw_importances):
            feature_importance_dict[feat_name] = round(float(imp), 5)
    else:
        # Fallback permutation importance
        from sklearn.inspection import permutation_importance
        perm_res = permutation_importance(selected_model, X_test, y_test, n_repeats=5, random_state=random_state)
        for feat_name, imp in zip(ALL_PREDICTIVE_FEATURES, perm_res.importances_mean):
            feature_importance_dict[feat_name] = round(float(max(0.0, imp)), 5)

    # Sort descending
    sorted_importance = dict(sorted(feature_importance_dict.items(), key=lambda item: item[1], reverse=True))

    print("\n--- TOP 10 PREDICTIVE FEATURES BY IMPORTANCE ---")
    for rank, (fname, val) in enumerate(list(sorted_importance.items())[:10], 1):
        print(f"  {rank:2d}. {fname:<26}: {val:.5f} ({val*100:.2f}%)")

    # 8. Assemble Metadata and Save
    metadata = ModelMetadata(
        model_name="uniguard-dual-tier-detector",
        model_version="1.0.0",
        feature_schema_version="2.0.0",
        feature_count=len(ALL_PREDICTIVE_FEATURES),
        features=ALL_PREDICTIVE_FEATURES,
        supported_classes=SUPPORTED_TRAINING_CLASSES,
        unsupported_classes=UNSUPPORTED_TRAINING_CLASSES,
        primary_dataset="NF-CSE-CIC-IDS2018-v2 (Benchmark Corpus)",
        random_seed=random_state,
        training_timestamp=datetime.now(timezone.utc).isoformat(),
        supervised_algorithm=selected_algo,
        anomaly_algorithm="IsolationForest",
        supervised_hyperparameters=selected_hyperparams,
        anomaly_hyperparameters=anomaly_hyperparams,
        validation_metrics=val_metrics,
        test_metrics=test_metrics,
        anomaly_baseline_metrics=anomaly_baseline_metrics,
        feature_importance=sorted_importance,
        scientific_limitations=[
            "EXFILTRATION class is unsupported due to absence of verified ground-truth samples in standard NF-CSE-CIC-IDS2018-v2.",
            "C2_BEACONING is trained on Ares HTTP bot check-in patterns; advanced DNS/mTLS tunneling requires supplementary raw PCAP extraction.",
            "Isolation Forest decision scores represent relative distance to the normal hyperplane and must not be interpreted as calibrated probabilities."
        ],
    )

    save_model_pipeline(
        output_dir=out_dir,
        anomaly_model=iso_forest,
        supervised_model=selected_model,
        preprocessor=preprocessor,
        label_encoder=label_encoder,
        metadata=metadata,
    )
    print(f"\n[SUCCESS] Model artifacts and metadata successfully saved to: {out_dir}")
    print("=" * 70)
    return metadata


if __name__ == "__main__":
    train_ml_pipeline()
