from typing import Tuple, List, Optional, Dict, Any
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, RobustScaler

from .dataset_schema import (
    ALL_PREDICTIVE_FEATURES,
    CANONICAL_NUMERICAL_FEATURES,
    CANONICAL_CATEGORICAL_FEATURES,
    ThreatClass,
    PRIMARY_DATASET_LABEL_MAPPING,
)
from app.traffic.models import FlowFeatures


class MLPreprocessor:
    """
    Reproducible preprocessing and dataset splitting pipeline for UNIGUARD AI.
    Guarantees zero data leakage and strict adherence to canonical feature vectors.
    """

    def __init__(self, scaler_type: str = "standard"):
        self.scaler_type = scaler_type
        self.scaler = StandardScaler() if scaler_type == "standard" else RobustScaler()
        self.is_fitted: bool = False
        self.feature_names: List[str] = list(ALL_PREDICTIVE_FEATURES)

    @staticmethod
    def flows_to_dataframe(flows: List[FlowFeatures], label: Optional[str] = None) -> pd.DataFrame:
        """
        Converts a list of Phase 2 FlowFeatures into an ML-ready DataFrame.
        Produces exactly 27 predictive features + 8 metadata fields.
        """
        records = []
        for f in flows:
            rec = {
                # Identifiers & Metadata (NOT used for model training)
                "flow_id": f.flow_id,
                "src_ip": f.src_ip,
                "dst_ip": f.dst_ip,
                "src_port": f.src_port,
                "dst_port": f.dst_port,
                "protocol": f.protocol,
                "start_time": f.start_time,
                "end_time": f.end_time,
                # 1. Volume & Timing (5)
                "duration_seconds": f.duration_seconds,
                "packet_count": f.packet_count,
                "byte_count": f.byte_count,
                "packets_per_second": f.packets_per_second,
                "bytes_per_second": f.bytes_per_second,
                # 2. Packet Size Distribution (5)
                "mean_packet_size": f.mean_packet_size,
                "std_packet_size": f.std_packet_size,
                "min_packet_size": f.min_packet_size,
                "max_packet_size": f.max_packet_size,
                "packet_size_entropy": f.packet_size_entropy,
                # 3. Inter-Arrival Dynamics (6)
                "mean_iat_seconds": f.mean_iat_seconds,
                "std_iat_seconds": f.std_iat_seconds,
                "min_iat_seconds": f.min_iat_seconds,
                "max_iat_seconds": f.max_iat_seconds,
                "iat_jitter_seconds": f.iat_jitter_seconds,
                "burstiness_ratio": f.burstiness_ratio,
                # 4. TCP Flags (9)
                "syn_count": f.syn_count,
                "ack_count": f.ack_count,
                "fin_count": f.fin_count,
                "rst_count": f.rst_count,
                "psh_count": f.psh_count,
                "urg_count": f.urg_count,
                "syn_ratio": f.syn_ratio,
                "ack_ratio": f.ack_ratio,
                "rst_ratio": f.rst_ratio,
                # 5. Contextual Binary Port Flags (2)
                "is_well_known_dst_port": int(f.is_well_known_dst_port),
                "is_ephemeral_src_port": int(f.is_ephemeral_src_port),
            }
            if label is not None:
                rec["label"] = label
            records.append(rec)

        return pd.DataFrame(records)

    @staticmethod
    def normalize_labels(df: pd.DataFrame, raw_label_col: str = "raw_label") -> pd.DataFrame:
        """
        Normalizes arbitrary dataset attack names into standard UNIGUARD ThreatClass values.
        """
        df_out = df.copy()
        if raw_label_col not in df_out.columns:
            return df_out

        def map_label(val: Any) -> str:
            if pd.isna(val):
                return ThreatClass.BENIGN.value
            raw_str = str(val).strip()
            if raw_str in PRIMARY_DATASET_LABEL_MAPPING:
                mapped = PRIMARY_DATASET_LABEL_MAPPING[raw_str]["uniguard_class"]
                if mapped != "NOT_AVAILABLE":
                    return mapped

            # Fallback simple lower-case match
            clean_lower = raw_str.lower()
            if "benign" in clean_lower:
                return ThreatClass.BENIGN.value
            if "ddos" in clean_lower or "dos" in clean_lower:
                return ThreatClass.DDOS.value
            if "bot" in clean_lower or "c2" in clean_lower:
                return ThreatClass.C2_BEACONING.value
            if "scan" in clean_lower or "probe" in clean_lower or "infilter" in clean_lower:
                return ThreatClass.RECON_SCAN.value
            if "exfil" in clean_lower:
                return ThreatClass.EXFILTRATION.value

            return ThreatClass.BENIGN.value

        df_out["label"] = df_out[raw_label_col].apply(map_label)
        return df_out

    @staticmethod
    def clean_feature_matrix(df: pd.DataFrame, feature_cols: Optional[List[str]] = None) -> pd.DataFrame:
        """
        Replaces NaNs, infinite values, and negative timing anomalies deterministically.
        """
        cols = feature_cols or ALL_PREDICTIVE_FEATURES
        df_out = df.copy()

        for c in cols:
            if c in df_out.columns:
                series = df_out[c].astype(float)
                # Replace inf and -inf with NaN
                series = series.replace([np.inf, -np.inf], np.nan)
                # Fill NaN with column median or 0.0
                median_val = series.median()
                fill_val = 0.0 if pd.isna(median_val) else median_val
                df_out[c] = series.fillna(fill_val)

        return df_out

    def split_dataset(
        self,
        df: pd.DataFrame,
        label_col: str = "label",
        test_size: float = 0.15,
        val_size: float = 0.15,
        random_state: int = 42,
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Splits dataset into stratified Train (70%), Validation (15%), and Test (15%) subsets.
        """
        if label_col in df.columns and df[label_col].nunique() > 1:
            train_val_df, test_df = train_test_split(
                df,
                test_size=test_size,
                stratify=df[label_col],
                random_state=random_state,
            )
            adjusted_val_size = val_size / (1.0 - test_size)
            train_df, val_df = train_test_split(
                train_val_df,
                test_size=adjusted_val_size,
                stratify=train_val_df[label_col],
                random_state=random_state,
            )
        else:
            train_val_df, test_df = train_test_split(
                df,
                test_size=test_size,
                random_state=random_state,
            )
            adjusted_val_size = val_size / (1.0 - test_size)
            train_df, val_df = train_test_split(
                train_val_df,
                test_size=adjusted_val_size,
                random_state=random_state,
            )

        return train_df.reset_index(drop=True), val_df.reset_index(drop=True), test_df.reset_index(drop=True)

    def fit_transform_features(
        self,
        train_df: pd.DataFrame,
        val_df: Optional[pd.DataFrame] = None,
        test_df: Optional[pd.DataFrame] = None,
    ) -> Dict[str, np.ndarray]:
        """
        Fits scaler strictly on Train features to avoid data snooping leakage,
        then transforms Train, Validation, and Test feature matrices.
        """
        X_train_raw = train_df[self.feature_names].to_numpy(dtype=float)
        X_train_scaled = self.scaler.fit_transform(X_train_raw)
        self.is_fitted = True

        out = {"X_train": X_train_scaled}

        if val_df is not None:
            X_val_raw = val_df[self.feature_names].to_numpy(dtype=float)
            out["X_val"] = self.scaler.transform(X_val_raw)

        if test_df is not None:
            X_test_raw = test_df[self.feature_names].to_numpy(dtype=float)
            out["X_test"] = self.scaler.transform(X_test_raw)

        return out
