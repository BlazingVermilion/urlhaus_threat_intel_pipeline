"""Feature engineering for URLhaus threat-intelligence indicators.

The project is intentionally built around real-world, imperfect threat-feed data.
This module converts normalized URLhaus indicators into a deterministic ML-ready
feature matrix for unsupervised anomaly scoring.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import log2

import pandas as pd

EXECUTABLE_EXTENSIONS = {
    "apk",
    "bat",
    "bin",
    "cmd",
    "dll",
    "elf",
    "exe",
    "jar",
    "js",
    "msi",
    "ps1",
    "scr",
    "sh",
    "vbs",
}

SUSPICIOUS_PATH_KEYWORDS = {
    "admin",
    "bin",
    "bot",
    "cmd",
    "gate",
    "install",
    "loader",
    "login",
    "panel",
    "payload",
    "shell",
    "update",
    "upload",
}

NUMERIC_FEATURES = [
    "port",
    "path_depth",
    "url_length",
    "tag_count",
    "host_length",
    "host_digit_ratio",
    "host_entropy",
    "path_length",
    "path_digit_ratio",
]

BINARY_FEATURES = [
    "has_query",
    "is_ip_host",
    "is_default_port",
    "is_non_standard_port",
    "has_executable_extension",
    "has_suspicious_path_keyword",
]

CATEGORICAL_FEATURES = ["scheme", "host_type", "url_status", "threat", "tld"]


@dataclass(frozen=True)
class FeatureMatrix:
    """Container for a deterministic ML feature matrix and its schema."""

    features: pd.DataFrame
    numeric_features: list[str]
    binary_features: list[str]
    categorical_features: list[str]
    encoded_feature_names: list[str]


def shannon_entropy(value: str | None) -> float:
    """Return character-level Shannon entropy for a string."""

    text = "" if value is None else str(value)
    if not text:
        return 0.0
    probabilities = [text.count(character) / len(text) for character in set(text)]
    return float(-sum(probability * log2(probability) for probability in probabilities))


def _digit_ratio(value: str | None) -> float:
    text = "" if value is None else str(value)
    if not text:
        return 0.0
    return sum(character.isdigit() for character in text) / len(text)


def _extension_from_path(path: str | None) -> str | None:
    path_text = "" if path is None else str(path).split("?")[0].rstrip("/")
    if "." not in path_text:
        return None
    extension = path_text.rsplit(".", maxsplit=1)[-1].lower()
    if not extension or len(extension) > 8:
        return None
    return extension


def add_engineered_features(frame: pd.DataFrame) -> pd.DataFrame:
    """Add URL, host, and path-derived features for analytics and ML.

    The output remains tabular and explainable so the same features can be used
    by both a security analyst and an ML baseline.
    """

    enriched = frame.copy()

    for column in ["host", "path", "scheme", "host_type", "url_status", "threat", "tld"]:
        if column not in enriched:
            enriched[column] = "missing"

    enriched["host"] = enriched["host"].fillna("").astype(str)
    enriched["path"] = enriched["path"].fillna("").astype(str)
    enriched["scheme"] = enriched["scheme"].fillna("missing").astype(str).str.lower()
    enriched["host_type"] = enriched["host_type"].fillna("missing").astype(str).str.lower()
    enriched["url_status"] = enriched["url_status"].fillna("missing").astype(str).str.lower()
    enriched["threat"] = enriched["threat"].fillna("missing").astype(str).str.lower()
    enriched["tld"] = enriched["tld"].fillna("missing").astype(str).str.lower()

    enriched["host_length"] = enriched["host"].str.len().astype("int64")
    enriched["host_digit_ratio"] = enriched["host"].apply(_digit_ratio)
    enriched["host_entropy"] = enriched["host"].apply(shannon_entropy)
    enriched["path_length"] = enriched["path"].str.len().astype("int64")
    enriched["path_digit_ratio"] = enriched["path"].apply(_digit_ratio)
    enriched["file_extension"] = enriched["path"].apply(_extension_from_path).fillna("missing")
    enriched["has_executable_extension"] = (
        enriched["file_extension"].isin(EXECUTABLE_EXTENSIONS).astype(int)
    )
    enriched["has_suspicious_path_keyword"] = enriched["path"].str.lower().apply(
        lambda value: int(any(keyword in value for keyword in SUSPICIOUS_PATH_KEYWORDS))
    )
    enriched["is_ip_host"] = (enriched["host_type"] == "ip").astype(int)

    port_series = pd.to_numeric(enriched.get("port", 0), errors="coerce").fillna(0).astype(int)
    enriched["port"] = port_series
    enriched["is_default_port"] = (
        ((enriched["scheme"] == "http") & (port_series == 80))
        | ((enriched["scheme"] == "https") & (port_series == 443))
    ).astype(int)
    enriched["is_non_standard_port"] = (
        (port_series > 0)
        & ~(
            ((enriched["scheme"] == "http") & (port_series == 80))
            | ((enriched["scheme"] == "https") & (port_series == 443))
        )
    ).astype(int)

    enriched["has_query"] = enriched.get("has_query", 0).astype(int)
    enriched["path_depth"] = pd.to_numeric(enriched.get("path_depth", 0), errors="coerce").fillna(0)
    enriched["url_length"] = pd.to_numeric(enriched.get("url_length", 0), errors="coerce").fillna(0)
    enriched["tag_count"] = pd.to_numeric(enriched.get("tag_count", 0), errors="coerce").fillna(0)

    return enriched


def build_model_features(frame: pd.DataFrame, max_categories: int = 25) -> FeatureMatrix:
    """Build a deterministic numeric matrix for anomaly detection.

    Categorical columns are one-hot encoded with a small cap on category count
    to keep the model stable when full real-world feeds contain many TLDs or
    threat labels.
    """

    engineered = add_engineered_features(frame)
    model_input = engineered[NUMERIC_FEATURES + BINARY_FEATURES + CATEGORICAL_FEATURES].copy()

    numeric = model_input[NUMERIC_FEATURES].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    binary = (
        model_input[BINARY_FEATURES]
        .apply(pd.to_numeric, errors="coerce")
        .fillna(0)
        .astype(int)
    )

    categorical_frames = []
    for column in CATEGORICAL_FEATURES:
        values = model_input[column].fillna("missing").astype(str).str.lower()
        top_values = set(values.value_counts().head(max_categories).index)
        capped = values.where(values.isin(top_values), other="other")
        categorical_frames.append(pd.get_dummies(capped, prefix=column, dtype=int))

    features = pd.concat([numeric, binary, *categorical_frames], axis=1)
    features = features.reindex(sorted(features.columns), axis=1)
    return FeatureMatrix(
        features=features,
        numeric_features=NUMERIC_FEATURES,
        binary_features=BINARY_FEATURES,
        categorical_features=CATEGORICAL_FEATURES,
        encoded_feature_names=list(features.columns),
    )
