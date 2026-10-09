from pathlib import Path
from typing import Dict, Any, List, Optional
import json
from datetime import datetime, timezone
import joblib
from pydantic import BaseModel, Field


class ModelEvaluationMetrics(BaseModel):
    accuracy: float
    macro_f1: float
    weighted_f1: float
    macro_precision: float
    macro_recall: float
    inference_latency_ms: float
    confusion_matrix: List[List[int]]
    per_class_report: Dict[str, Any]


class ModelMetadata(BaseModel):
    model_name: str
    model_version: str
    feature_schema_version: str = "2.0.0"
    feature_count: int = 27
    features: List[str]
    supported_classes: List[str]
    unsupported_classes: List[str]
    primary_dataset: str
    random_seed: int
    training_timestamp: str
    supervised_algorithm: str
    anomaly_algorithm: str
    supervised_hyperparameters: Dict[str, Any]
    anomaly_hyperparameters: Dict[str, Any]
    validation_metrics: ModelEvaluationMetrics
    test_metrics: ModelEvaluationMetrics
    anomaly_baseline_metrics: Dict[str, Any]
    feature_importance: Dict[str, float]
    scientific_limitations: List[str]


def save_model_pipeline(
    output_dir: Path,
    anomaly_model: Any,
    supervised_model: Any,
    preprocessor: Any,
    label_encoder: Any,
    metadata: ModelMetadata,
) -> Path:
    """Serializes trained model artifacts, preprocessor, and metadata to disk."""
    output_dir.mkdir(parents=True, exist_ok=True)

    joblib.dump(anomaly_model, output_dir / "isolation_forest.joblib")
    joblib.dump(supervised_model, output_dir / "supervised_classifier.joblib")
    joblib.dump(preprocessor, output_dir / "preprocessor.joblib")
    joblib.dump(label_encoder, output_dir / "label_encoder.joblib")

    metadata_path = output_dir / "model_metadata.json"
    with open(metadata_path, "w") as f:
        json.dump(metadata.model_dump(), f, indent=2)

    return output_dir


def load_model_pipeline(models_dir: Path) -> Dict[str, Any]:
    """Loads all serialized model artifacts and metadata from disk."""
    if not models_dir.exists():
        raise FileNotFoundError(f"Model directory not found at: {models_dir}")

    anomaly_model = joblib.load(models_dir / "isolation_forest.joblib")
    supervised_model = joblib.load(models_dir / "supervised_classifier.joblib")
    preprocessor = joblib.load(models_dir / "preprocessor.joblib")
    label_encoder = joblib.load(models_dir / "label_encoder.joblib")

    with open(models_dir / "model_metadata.json", "r") as f:
        metadata_dict = json.load(f)
    metadata = ModelMetadata(**metadata_dict)

    return {
        "anomaly_model": anomaly_model,
        "supervised_model": supervised_model,
        "preprocessor": preprocessor,
        "label_encoder": label_encoder,
        "metadata": metadata,
    }
