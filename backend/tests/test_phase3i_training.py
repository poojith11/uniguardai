from pathlib import Path
import pytest
import json
import numpy as np
import joblib
from app.ml.dataset_schema import ALL_PREDICTIVE_FEATURES, ThreatClass
from app.ml.train_phase3i import map_phase3i_ground_truth
from app.traffic.models import FlowFeatures


@pytest.fixture(scope="session")
def phase3i_models_dir() -> Path:
    return Path(__file__).parent.parent / "app" / "ml" / "models" / "phase3i_multiclass"


def test_phase3i_artifacts_exist(phase3i_models_dir: Path):
    assert (phase3i_models_dir / "isolation_forest_phase3i.joblib").exists()
    assert (phase3i_models_dir / "supervised_classifier_phase3i.joblib").exists()
    assert (phase3i_models_dir / "preprocessor_phase3i.joblib").exists()
    assert (phase3i_models_dir / "label_encoder_phase3i.joblib").exists()
    assert (phase3i_models_dir / "model_metadata_phase3i.json").exists()
    assert (phase3i_models_dir / "training_manifest.json").exists()


def test_phase3i_model_classes_and_inference(phase3i_models_dir: Path):
    iso_forest = joblib.load(phase3i_models_dir / "isolation_forest_phase3i.joblib")
    clf = joblib.load(phase3i_models_dir / "supervised_classifier_phase3i.joblib")
    preprocessor = joblib.load(phase3i_models_dir / "preprocessor_phase3i.joblib")
    label_encoder = joblib.load(phase3i_models_dir / "label_encoder_phase3i.joblib")

    # Verify that all 4 classes are trained in the classifier
    assert len(clf.classes_) == 4
    assert set(clf.classes_) == {0, 1, 2, 3}
    assert len(label_encoder.classes_) == 4

    sample_raw = np.zeros((1, 27))
    sample_scaled = preprocessor.scaler.transform(sample_raw)

    pred_idx = clf.predict(sample_scaled)[0]
    pred_label = label_encoder.inverse_transform([pred_idx])[0]
    assert pred_label in [ThreatClass.BENIGN.value, ThreatClass.DDOS.value, ThreatClass.RECON_SCAN.value, ThreatClass.C2_BEACONING.value]

    anom_score = iso_forest.decision_function(sample_scaled)[0]
    assert isinstance(float(anom_score), float)


def test_phase3i_ground_truth_mappings():
    # DDoS Mapping
    flow_ddos = FlowFeatures(
        flow_id="f_ddos", src_ip="18.218.115.60", dst_ip="172.31.69.25",
        src_port=55000, dst_port=80, protocol="TCP", start_time=10.0, end_time=10.1,
        duration_seconds=0.1, packet_count=100, byte_count=100000, packets_per_second=1000.0,
        bytes_per_second=1000000.0, mean_packet_size=1000.0, std_packet_size=0.0,
        min_packet_size=1000, max_packet_size=1000, packet_size_entropy=0.0,
        mean_iat_seconds=0.001, std_iat_seconds=0.0001, min_iat_seconds=0.001, max_iat_seconds=0.001,
        iat_jitter_seconds=0.0001, burstiness_ratio=0.9, syn_count=1, ack_count=99,
        fin_count=0, rst_count=0, psh_count=99, urg_count=0, syn_ratio=0.01,
        ack_ratio=0.99, rst_ratio=0.0, is_well_known_dst_port=True, is_ephemeral_src_port=True,
    )
    assert map_phase3i_ground_truth(flow_ddos, "Wed21_WebServer25") == ThreatClass.DDOS.value

    # Recon Scan Mapping
    flow_recon = FlowFeatures(
        flow_id="f_recon", src_ip="18.218.115.60", dst_ip="172.31.69.28",
        src_port=50000, dst_port=22, protocol="TCP", start_time=10.0, end_time=11.0,
        duration_seconds=1.0, packet_count=5, byte_count=500, packets_per_second=5.0,
        bytes_per_second=500.0, mean_packet_size=100.0, std_packet_size=10.0,
        min_packet_size=40, max_packet_size=150, packet_size_entropy=1.0,
        mean_iat_seconds=0.2, std_iat_seconds=0.05, min_iat_seconds=0.1, max_iat_seconds=0.3,
        iat_jitter_seconds=0.02, burstiness_ratio=0.25, syn_count=1, ack_count=4,
        fin_count=0, rst_count=0, psh_count=1, urg_count=0, syn_ratio=0.2,
        ack_ratio=0.8, rst_ratio=0.0, is_well_known_dst_port=True, is_ephemeral_src_port=True,
    )
    assert map_phase3i_ground_truth(flow_recon, "Wed14_Server28") == ThreatClass.RECON_SCAN.value
