from pathlib import Path
import pytest
import json
import numpy as np
import joblib
from app.ml.dataset_schema import ALL_PREDICTIVE_FEATURES, ThreatClass


@pytest.fixture(scope="session")
def real_world_models_dir() -> Path:
    return Path(__file__).parent.parent / "app" / "ml" / "models" / "real_world"


def test_real_world_artifacts_exist(real_world_models_dir: Path):
    assert (real_world_models_dir / "isolation_forest_real.joblib").exists()
    assert (real_world_models_dir / "supervised_classifier_real.joblib").exists()
    assert (real_world_models_dir / "preprocessor_real.joblib").exists()
    assert (real_world_models_dir / "label_encoder_real.joblib").exists()
    assert (real_world_models_dir / "model_metadata_real.json").exists()


def test_real_world_model_loading_and_inference(real_world_models_dir: Path):
    iso_forest = joblib.load(real_world_models_dir / "isolation_forest_real.joblib")
    rf_clf = joblib.load(real_world_models_dir / "supervised_classifier_real.joblib")
    preprocessor = joblib.load(real_world_models_dir / "preprocessor_real.joblib")
    label_encoder = joblib.load(real_world_models_dir / "label_encoder_real.joblib")

    # Single flow sample with 27 features
    sample_raw = np.zeros((1, 27))
    sample_scaled = preprocessor.scaler.transform(sample_raw)

    pred_idx = rf_clf.predict(sample_scaled)[0]
    pred_label = label_encoder.inverse_transform([pred_idx])[0]
    assert pred_label in [ThreatClass.BENIGN.value, ThreatClass.DDOS.value, ThreatClass.RECON_SCAN.value, ThreatClass.C2_BEACONING.value]

    anom_score = iso_forest.decision_function(sample_scaled)[0]
    assert isinstance(float(anom_score), float)


def test_real_world_metadata_schema(real_world_models_dir: Path):
    with open(real_world_models_dir / "model_metadata_real.json", "r") as f:
        meta = json.load(f)

    assert meta["model_name"] == "uniguard-real-world-detector"
    assert meta["model_version"] == "2.0.0"
    assert meta["feature_count"] == 27
    assert len(meta["training_capture_ids"]) >= 2
    assert len(meta["validation_capture_ids"]) >= 1
    assert len(meta["unseen_test_capture_ids"]) >= 1
    # Check capture independence
    assert set(meta["training_capture_ids"]).isdisjoint(set(meta["unseen_test_capture_ids"]))
    assert "comparison_vs_phase_3b" in meta
    assert meta["comparison_vs_phase_3b"]["phase_3d_false_positive_rate"] < meta["comparison_vs_phase_3b"]["phase_3b_false_positive_rate"]
