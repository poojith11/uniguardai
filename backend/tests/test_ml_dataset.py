import pytest
import pandas as pd
import numpy as np
from app.ml.dataset_schema import (
    ALL_PREDICTIVE_FEATURES,
    CANONICAL_NUMERICAL_FEATURES,
    CANONICAL_CATEGORICAL_FEATURES,
    FORBIDDEN_LEAKAGE_COLUMNS,
    FLOW_METADATA_COLUMNS,
    ThreatClass,
    PRIMARY_DATASET_LABEL_MAPPING,
)
from app.ml.validator import DatasetValidator
from app.ml.preprocessor import MLPreprocessor
from app.traffic.models import FlowFeatures


def _create_mock_flow_features(flow_id: str, src_ip: str, label: str) -> FlowFeatures:
    """Helper to generate mock FlowFeatures with all 35 fields."""
    return FlowFeatures(
        flow_id=flow_id,
        src_ip=src_ip,
        dst_ip="192.0.2.80",
        src_port=49152,
        dst_port=80,
        protocol="TCP",
        start_time=10.0,
        end_time=12.0,
        duration_seconds=2.0,
        packet_count=10,
        byte_count=1000,
        packets_per_second=5.0,
        bytes_per_second=500.0,
        mean_packet_size=100.0,
        std_packet_size=10.0,
        min_packet_size=50,
        max_packet_size=150,
        packet_size_entropy=1.5,
        mean_iat_seconds=0.2,
        std_iat_seconds=0.05,
        min_iat_seconds=0.1,
        max_iat_seconds=0.3,
        iat_jitter_seconds=0.02,
        burstiness_ratio=0.25,
        syn_count=1,
        ack_count=9,
        fin_count=1,
        rst_count=0,
        psh_count=2,
        urg_count=0,
        syn_ratio=0.1,
        ack_ratio=0.9,
        rst_ratio=0.0,
        is_well_known_dst_port=True,
        is_ephemeral_src_port=True,
    )


def test_exact_feature_matrix_dimensions():
    # Exact authoritative breakdown: 25 numerical + 2 contextual = 27 predictive features
    assert len(CANONICAL_NUMERICAL_FEATURES) == 25
    assert len(CANONICAL_CATEGORICAL_FEATURES) == 2
    assert len(ALL_PREDICTIVE_FEATURES) == 27
    assert len(FLOW_METADATA_COLUMNS) == 8

    # Verify that flow vector matches 27 dimensions
    mock_flow = _create_mock_flow_features("f1", "192.0.2.1", "BENIGN")
    vector = mock_flow.as_vector()
    assert len(vector) == 27

    # Verify that NO forbidden identifier is present in predictive features
    for forbidden in FORBIDDEN_LEAKAGE_COLUMNS:
        assert forbidden not in ALL_PREDICTIVE_FEATURES


def test_dataset_validator_clean():
    flows = [_create_mock_flow_features(f"flow_{i}", f"192.0.2.{i}", "BENIGN") for i in range(20)]
    df = MLPreprocessor.flows_to_dataframe(flows, label="BENIGN")

    report = DatasetValidator.validate_dataset(df, label_column="label")
    assert report.is_valid is True
    assert report.total_records == 20
    assert report.feature_count == 27
    assert len(report.missing_features) == 0
    assert len(report.leakage_warnings) == 0
    assert len(report.nan_inf_columns) == 0


def test_dataset_validator_detects_leakage():
    flows = [_create_mock_flow_features(f"flow_{i}", f"192.0.2.{i}", "BENIGN") for i in range(5)]
    df = MLPreprocessor.flows_to_dataframe(flows, label="BENIGN")

    corrupted_features = list(ALL_PREDICTIVE_FEATURES) + ["src_ip"]
    report = DatasetValidator.validate_dataset(df, expected_features=corrupted_features)

    assert report.is_valid is False
    assert any("Data Leakage Risk" in w for w in report.leakage_warnings)


def test_dataset_validator_detects_nan_inf():
    flows = [_create_mock_flow_features(f"flow_{i}", f"192.0.2.{i}", "BENIGN") for i in range(5)]
    df = MLPreprocessor.flows_to_dataframe(flows, label="BENIGN")

    df.loc[0, "bytes_per_second"] = np.nan
    df.loc[1, "packets_per_second"] = np.inf

    report = DatasetValidator.validate_dataset(df)
    assert "bytes_per_second" in report.nan_inf_columns
    assert "packets_per_second" in report.nan_inf_columns


def test_preprocessor_clean_feature_matrix():
    flows = [_create_mock_flow_features(f"flow_{i}", f"192.0.2.{i}", "BENIGN") for i in range(5)]
    df = MLPreprocessor.flows_to_dataframe(flows, label="BENIGN")

    df.loc[0, "bytes_per_second"] = np.nan
    df.loc[1, "packets_per_second"] = np.inf

    cleaned_df = MLPreprocessor.clean_feature_matrix(df)
    assert not cleaned_df["bytes_per_second"].isna().any()
    assert not np.isinf(cleaned_df["packets_per_second"]).any()


def test_preprocessor_stratified_split_and_scaling():
    records = []
    for i in range(100):
        lbl = ThreatClass.BENIGN.value if i < 70 else (ThreatClass.DDOS.value if i < 90 else ThreatClass.C2_BEACONING.value)
        f = _create_mock_flow_features(f"flow_{i}", f"192.0.2.{i%20}", lbl)
        records.append(f)

    df = MLPreprocessor.flows_to_dataframe(records)
    labels = [ThreatClass.BENIGN.value if i < 70 else (ThreatClass.DDOS.value if i < 90 else ThreatClass.C2_BEACONING.value) for i in range(100)]
    df["label"] = labels

    preprocessor = MLPreprocessor(scaler_type="standard")
    train_df, val_df, test_df = preprocessor.split_dataset(df, label_col="label", test_size=0.15, val_size=0.15, random_state=42)

    assert len(train_df) + len(val_df) + len(test_df) == 100
    assert len(test_df) == 15
    assert len(val_df) in (15, 16)
    assert len(train_df) in (69, 70)

    assert train_df["label"].nunique() == 3
    assert test_df["label"].nunique() == 3

    matrices = preprocessor.fit_transform_features(train_df, val_df, test_df)
    assert "X_train" in matrices
    assert "X_val" in matrices
    assert "X_test" in matrices
    assert matrices["X_train"].shape == (len(train_df), 27)
    assert matrices["X_test"].shape == (15, 27)


def test_primary_dataset_label_mapping():
    assert PRIMARY_DATASET_LABEL_MAPPING["Benign"]["uniguard_class"] == ThreatClass.BENIGN.value
    assert PRIMARY_DATASET_LABEL_MAPPING["DDOS attack-HOIC"]["uniguard_class"] == ThreatClass.DDOS.value
    assert PRIMARY_DATASET_LABEL_MAPPING["SSH-Bruteforce"]["uniguard_class"] == ThreatClass.RECON_SCAN.value
    assert PRIMARY_DATASET_LABEL_MAPPING["Bot"]["uniguard_class"] == ThreatClass.C2_BEACONING.value
    assert PRIMARY_DATASET_LABEL_MAPPING["Data Exfiltration"]["uniguard_class"] == "NOT_AVAILABLE"
