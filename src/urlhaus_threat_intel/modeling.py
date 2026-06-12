"""Machine-learning utilities for anomaly-based threat-indicator prioritization."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .feature_engineering import build_model_features


def _percentile_rank(values: pd.Series) -> pd.Series:
    if values.empty:
        return values
    minimum = values.min()
    maximum = values.max()
    if maximum == minimum:
        return pd.Series([0.5] * len(values), index=values.index)
    return (values - minimum) / (maximum - minimum)


def fit_anomaly_model(
    frame: pd.DataFrame,
    model_path: str | Path,
    output_path: str | Path,
    feature_output_path: str | Path | None = None,
    metadata_output_path: str | Path | None = None,
    contamination: float = 0.10,
    random_state: int = 42,
) -> pd.DataFrame:
    """Train an IsolationForest anomaly baseline and export scored indicators.

    The model is trained on engineered URL, host, network, and threat-feed
    metadata features. It is intentionally unsupervised because public URLhaus
    rows are malicious indicators rather than balanced benign/malicious labels.
    """

    feature_set = build_model_features(frame)
    features = feature_set.features

    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(features)

    model = IsolationForest(
        n_estimators=300,
        contamination=contamination,
        random_state=random_state,
    )
    model.fit(scaled_features)

    result = frame.copy()
    result["ml_anomaly_score"] = -model.score_samples(scaled_features)
    result["ml_anomaly_percentile"] = _percentile_rank(result["ml_anomaly_score"]).round(4)
    result["is_ml_anomaly"] = model.predict(scaled_features) == -1

    if "risk_score" in result.columns:
        risk = pd.to_numeric(result["risk_score"], errors="coerce").fillna(0.0)
        result["hybrid_priority_score"] = (
            (0.65 * result["ml_anomaly_percentile"]) + (0.35 * risk)
        ).round(4)
        sort_columns = ["hybrid_priority_score", "ml_anomaly_score"]
    else:
        sort_columns = ["ml_anomaly_score"]

    result = result.sort_values(sort_columns, ascending=False)

    model_file = Path(model_path)
    model_file.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "scaler": scaler,
            "model": model,
            "encoded_feature_names": feature_set.encoded_feature_names,
            "numeric_features": feature_set.numeric_features,
            "binary_features": feature_set.binary_features,
            "categorical_features": feature_set.categorical_features,
        },
        model_file,
    )

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(output_file, index=False)

    if feature_output_path is not None:
        feature_file = Path(feature_output_path)
        feature_file.parent.mkdir(parents=True, exist_ok=True)
        features.to_csv(feature_file, index=False)

    if metadata_output_path is not None:
        metadata_file = Path(metadata_output_path)
        metadata_file.parent.mkdir(parents=True, exist_ok=True)
        metadata = _build_model_metadata(
            row_count=len(result),
            feature_count=features.shape[1],
            contamination=contamination,
            random_state=random_state,
            feature_set=feature_set.__dict__,
        )
        metadata_file.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    return result


def _build_model_metadata(
    row_count: int,
    feature_count: int,
    contamination: float,
    random_state: int,
    feature_set: dict[str, Any],
) -> dict[str, Any]:
    return {
        "model_type": "IsolationForest",
        "learning_task": "unsupervised anomaly scoring for malicious URL indicators",
        "row_count": row_count,
        "feature_count": feature_count,
        "contamination": contamination,
        "random_state": random_state,
        "numeric_features": feature_set["numeric_features"],
        "binary_features": feature_set["binary_features"],
        "categorical_features": feature_set["categorical_features"],
        "encoded_feature_names": feature_set["encoded_feature_names"],
        "notes": [
            (
                "URLhaus rows are already threat indicators, so this model does not "
                "classify benign vs malicious URLs."
            ),
            (
                "The model ranks unusual indicators within the current batch to "
                "support analyst triage."
            ),
            "A hybrid priority score is exported when rule-based risk_score is available.",
        ],
    }


# Backward-compatible alias for earlier README/CLI references.
fit_isolation_forest = fit_anomaly_model
