from typing import Dict, Any, List, Optional, Set
import pandas as pd
import numpy as np

from .dataset_schema import (
    ALL_PREDICTIVE_FEATURES,
    CANONICAL_NUMERICAL_FEATURES,
    FORBIDDEN_LEAKAGE_COLUMNS,
    ThreatClass,
)


class DatasetValidationReport:
    """Encapsulates results of comprehensive dataset integrity checks."""
    def __init__(self):
        self.is_valid: bool = True
        self.total_records: int = 0
        self.feature_count: int = 0
        self.missing_features: List[str] = []
        self.leakage_warnings: List[str] = []
        self.nan_inf_columns: Dict[str, int] = {}
        self.class_distribution: Dict[str, Dict[str, Any]] = {}
        self.duplicate_count: int = 0
        self.errors: List[str] = []
        self.recommendations: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "total_records": self.total_records,
            "feature_count": self.feature_count,
            "missing_features": self.missing_features,
            "leakage_warnings": self.leakage_warnings,
            "nan_inf_columns": self.nan_inf_columns,
            "class_distribution": self.class_distribution,
            "duplicate_count": self.duplicate_count,
            "errors": self.errors,
            "recommendations": self.recommendations,
        }


class DatasetValidator:
    """
    Validates cybersecurity dataset integrity, feature compatibility, and leakage safety.
    """

    @staticmethod
    def validate_dataset(
        df: pd.DataFrame,
        label_column: str = "label",
        expected_features: Optional[List[str]] = None,
    ) -> DatasetValidationReport:
        report = DatasetValidationReport()
        report.total_records = len(df)

        if df.empty:
            report.is_valid = False
            report.errors.append("Dataset is empty (0 records).")
            return report

        target_features = expected_features or ALL_PREDICTIVE_FEATURES

        # 1. Feature Availability Check
        missing = [f for f in target_features if f not in df.columns]
        report.missing_features = missing
        if missing:
            report.is_valid = False
            report.errors.append(f"Missing required predictive features ({len(missing)}): {missing}")

        present_features = [f for f in target_features if f in df.columns]
        report.feature_count = len(present_features)

        # 2. Data Leakage & Identifier Check
        for col in df.columns:
            col_lower = col.lower().strip()
            if col_lower in FORBIDDEN_LEAKAGE_COLUMNS and col in target_features:
                report.is_valid = False
                warning = f"Data Leakage Risk: Identifier column '{col}' is configured as a predictive feature."
                report.leakage_warnings.append(warning)
                report.errors.append(warning)

        # 3. Missing, NaN, and Infinite Values Check
        for feat in present_features:
            series = df[feat]
            # Check for NaN / null
            null_count = series.isna().sum()
            # Check for infinite values in numeric columns
            if pd.api.types.is_numeric_dtype(series):
                inf_count = np.isinf(series.to_numpy(dtype=float, na_value=np.nan)).sum()
            else:
                inf_count = 0

            invalid_total = int(null_count + inf_count)
            if invalid_total > 0:
                report.nan_inf_columns[feat] = invalid_total

        if report.nan_inf_columns:
            report.recommendations.append(
                f"Found {len(report.nan_inf_columns)} columns with NaN/inf values. Imputation/cleaning required before model training."
            )

        # 4. Duplicate Rows Check
        if present_features:
            dups = df.duplicated(subset=present_features).sum()
            report.duplicate_count = int(dups)
            if dups > 0:
                report.recommendations.append(
                    f"Found {dups} identical duplicate feature vectors ({dups/len(df):.1%}). Deduplication recommended."
                )

        # 5. Label & Class Balance Analysis
        if label_column in df.columns:
            label_counts = df[label_column].value_counts().to_dict()
            total_labeled = sum(label_counts.values())

            for lbl, count in label_counts.items():
                pct = (count / total_labeled) * 100.0 if total_labeled > 0 else 0.0
                report.class_distribution[str(lbl)] = {
                    "sample_count": int(count),
                    "percentage": round(pct, 2),
                }

                if pct < 1.0:
                    report.recommendations.append(
                        f"Severe minority class '{lbl}' represents only {pct:.2f}% of samples. Stratified splitting and class-weighted loss recommended."
                    )
        else:
            report.recommendations.append(f"Label column '{label_column}' not found. Dataset will be evaluated in unsupervised mode.")

        return report

    @staticmethod
    def verify_split_leakage(
        train_df: pd.DataFrame,
        test_df: pd.DataFrame,
        id_columns: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Ensures strict separation between train and test splits.
        Verifies no shared flow identifiers exist across splits.
        """
        id_cols = id_columns or ["flow_id", "src_ip", "dst_ip"]
        shared_entities: Dict[str, int] = {}

        for col in id_cols:
            if col in train_df.columns and col in test_df.columns:
                train_set = set(train_df[col].dropna().unique())
                test_set = set(test_df[col].dropna().unique())
                overlap = len(train_set.intersection(test_set))
                shared_entities[col] = overlap

        has_leakage = any(count > 0 for count in shared_entities.values())
        return {
            "has_leakage": has_leakage,
            "shared_counts": shared_entities,
            "message": "Split leakage detected (shared entities across splits)." if has_leakage else "Clean train/test split (zero entity overlap).",
        }
