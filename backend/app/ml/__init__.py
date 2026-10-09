"""UNIGUARD AI - Machine Learning & Preprocessing Package"""
from .dataset_schema import (
    ThreatClass,
    CANONICAL_NUMERICAL_FEATURES,
    CANONICAL_CATEGORICAL_FEATURES,
    ALL_PREDICTIVE_FEATURES,
    FORBIDDEN_LEAKAGE_COLUMNS,
    FLOW_METADATA_COLUMNS,
    DATASET_COLUMN_MAPPINGS,
    PRIMARY_DATASET_LABEL_MAPPING,
)
from .validator import DatasetValidator, DatasetValidationReport
from .preprocessor import MLPreprocessor
from .dataset_loader import load_training_dataset, create_verified_benchmark_dataset, SUPPORTED_TRAINING_CLASSES, UNSUPPORTED_TRAINING_CLASSES
from .model_registry import ModelMetadata, ModelEvaluationMetrics, save_model_pipeline, load_model_pipeline
from .train import train_ml_pipeline

__all__ = [
    "ThreatClass",
    "CANONICAL_NUMERICAL_FEATURES",
    "CANONICAL_CATEGORICAL_FEATURES",
    "ALL_PREDICTIVE_FEATURES",
    "FORBIDDEN_LEAKAGE_COLUMNS",
    "FLOW_METADATA_COLUMNS",
    "DATASET_COLUMN_MAPPINGS",
    "PRIMARY_DATASET_LABEL_MAPPING",
    "DatasetValidator",
    "DatasetValidationReport",
    "MLPreprocessor",
    "load_training_dataset",
    "create_verified_benchmark_dataset",
    "SUPPORTED_TRAINING_CLASSES",
    "UNSUPPORTED_TRAINING_CLASSES",
    "ModelMetadata",
    "ModelEvaluationMetrics",
    "save_model_pipeline",
    "load_model_pipeline",
    "train_ml_pipeline",
]
