from pathlib import Path
import pytest
import numpy as np
from app.ml.model_registry import load_model_pipeline, ModelMetadata
from app.ml.dataset_schema import ALL_PREDICTIVE_FEATURES, ThreatClass
from app.traffic.models import FlowFeatures


@pytest.fixture(scope="session")
def models_dir() -> Path:
    return Path(__file__).parent.parent / "app" / "ml" / "models"


@pytest.fixture(scope="session")
def loaded_pipeline(models_dir: Path):
    return load_model_pipeline(models_dir)


def test_model_pipeline_loading(loaded_pipeline):
    assert "anomaly_model" in loaded_pipeline
    assert "supervised_model" in loaded_pipeline
    assert "preprocessor" in loaded_pipeline
    assert "label_encoder" in loaded_pipeline
    assert "metadata" in loaded_pipeline
    assert isinstance(loaded_pipeline["metadata"], ModelMetadata)


def test_feature_schema_compatibility(loaded_pipeline):
    metadata = loaded_pipeline["metadata"]
    assert metadata.feature_count == 27
    assert len(metadata.features) == 27
    assert metadata.features == ALL_PREDICTIVE_FEATURES

    # Verify input shape: 1 sample with 27 features
    sample_raw = np.zeros((1, 27))
    # Transform via scaler
    scaler = loaded_pipeline["preprocessor"].scaler
    sample_scaled = scaler.transform(sample_raw)

    # Supervised prediction
    pred_idx = loaded_pipeline["supervised_model"].predict(sample_scaled)
    pred_label = loaded_pipeline["label_encoder"].inverse_transform(pred_idx)[0]
    assert pred_label in metadata.supported_classes


def test_deterministic_inference(loaded_pipeline):
    sample_raw = np.ones((5, 27)) * 42.0
    scaler = loaded_pipeline["preprocessor"].scaler
    sample_scaled = scaler.transform(sample_raw)

    preds1 = loaded_pipeline["supervised_model"].predict(sample_scaled)
    preds2 = loaded_pipeline["supervised_model"].predict(sample_scaled)
    np.testing.assert_array_equal(preds1, preds2)

    anom1 = loaded_pipeline["anomaly_model"].decision_function(sample_scaled)
    anom2 = loaded_pipeline["anomaly_model"].decision_function(sample_scaled)
    np.testing.assert_array_equal(anom1, anom2)


def test_unsupported_class_handling(loaded_pipeline):
    metadata = loaded_pipeline["metadata"]
    assert ThreatClass.EXFILTRATION.value in metadata.unsupported_classes
    assert ThreatClass.EXFILTRATION.value not in metadata.supported_classes
    assert len(metadata.supported_classes) == 4


def test_anomaly_model_decision_function(loaded_pipeline):
    sample_raw = np.random.RandomState(42).randn(10, 27)
    scaler = loaded_pipeline["preprocessor"].scaler
    sample_scaled = scaler.transform(sample_raw)

    scores = loaded_pipeline["anomaly_model"].decision_function(sample_scaled)
    assert len(scores) == 10
    # Isolation Forest scores are floats where positive = normal, negative = anomaly
    assert all(isinstance(float(s), float) for s in scores)


def test_model_metadata_validity(loaded_pipeline):
    metadata = loaded_pipeline["metadata"]
    assert metadata.model_version == "1.0.0"
    assert metadata.test_metrics.macro_f1 >= 0.90
    assert metadata.test_metrics.accuracy >= 0.90
    assert len(metadata.feature_importance) == 27
    assert len(metadata.scientific_limitations) >= 2
