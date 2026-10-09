from pathlib import Path
import pytest
import json
import numpy as np
import joblib
from app.ml.dataset_schema import ALL_PREDICTIVE_FEATURES, ThreatClass
from app.ml.train_phase3g import map_phase3g_ground_truth
from app.traffic.models import FlowFeatures


@pytest.fixture(scope="session")
def phase3g_models_dir() -> Path:
    return Path(__file__).parent.parent / "app" / "ml" / "models" / "phase3g_attack_robust"


def test_phase3g_artifacts_exist(phase3g_models_dir: Path):
    assert (phase3g_models_dir / "isolation_forest_phase3g.joblib").exists()
    assert (phase3g_models_dir / "supervised_classifier_phase3g.joblib").exists()
    assert (phase3g_models_dir / "preprocessor_phase3g.joblib").exists()
    assert (phase3g_models_dir / "label_encoder_phase3g.joblib").exists()
    assert (phase3g_models_dir / "model_metadata_phase3g.json").exists()
    assert (phase3g_models_dir / "training_manifest.json").exists()


def test_phase3g_model_loading_and_inference(phase3g_models_dir: Path):
    iso_forest = joblib.load(phase3g_models_dir / "isolation_forest_phase3g.joblib")
    rf_clf = joblib.load(phase3g_models_dir / "supervised_classifier_phase3g.joblib")
    preprocessor = joblib.load(phase3g_models_dir / "preprocessor_phase3g.joblib")
    label_encoder = joblib.load(phase3g_models_dir / "label_encoder_phase3g.joblib")

    sample_raw = np.zeros((1, 27))
    sample_scaled = preprocessor.scaler.transform(sample_raw)

    pred_idx = rf_clf.predict(sample_scaled)[0]
    pred_label = label_encoder.inverse_transform([pred_idx])[0]
    assert pred_label in [ThreatClass.BENIGN.value, ThreatClass.DDOS.value, ThreatClass.RECON_SCAN.value, ThreatClass.C2_BEACONING.value]

    anom_score = iso_forest.decision_function(sample_scaled)[0]
    assert isinstance(float(anom_score), float)


def test_phase3g_manifest_and_metadata(phase3g_models_dir: Path):
    with open(phase3g_models_dir / "model_metadata_phase3g.json", "r") as f:
        meta = json.load(f)
    with open(phase3g_models_dir / "training_manifest.json", "r") as f:
        manifest = json.load(f)

    assert meta["model_name"] == "uniguard-attack-robust-detector"
    assert meta["model_version"] == "4.0.0"
    assert meta["unseen_test_metrics"]["accuracy"] > 0.90
    assert meta["unseen_test_metrics"]["macro_f1"] > 0.50
    assert meta["unseen_test_metrics"]["benign_false_positive_rate"] < 5.0
    assert "CTU13_Neris" in manifest["training_captures"]


def test_phase3g_ground_truth_mappings():
    # CTU-13 Neris Botnet C2 mapping
    flow_neris = FlowFeatures(
        flow_id="f1", src_ip="147.32.84.165", dst_ip="147.32.80.9",
        src_port=49152, dst_port=6667, protocol="TCP", start_time=10.0, end_time=15.0,
        duration_seconds=5.0, packet_count=10, byte_count=1200, packets_per_second=2.0,
        bytes_per_second=240.0, mean_packet_size=120.0, std_packet_size=20.0,
        min_packet_size=40, max_packet_size=300, packet_size_entropy=1.5,
        mean_iat_seconds=0.5, std_iat_seconds=0.05, min_iat_seconds=0.4, max_iat_seconds=0.6,
        iat_jitter_seconds=0.02, burstiness_ratio=0.1, syn_count=1, ack_count=9,
        fin_count=0, rst_count=0, psh_count=4, urg_count=0, syn_ratio=0.1,
        ack_ratio=0.9, rst_ratio=0.0, is_well_known_dst_port=False, is_ephemeral_src_port=True,
    )
    assert map_phase3g_ground_truth(flow_neris, "CTU13_Neris") == ThreatClass.C2_BEACONING.value
