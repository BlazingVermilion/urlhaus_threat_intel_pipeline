"""Aggregate analytics for normalized URLhaus indicators."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd


def _explode_tags(frame: pd.DataFrame) -> pd.Series:
    tags = frame["tags"].fillna("None").astype(str)
    tags = tags[~tags.isin(["", "None", "nan", "<NA>"])]
    if tags.empty:
        return pd.Series(dtype="string")
    return tags.str.split(",").explode().str.strip().loc[lambda values: values != ""]


def create_summary(frame: pd.DataFrame) -> dict:
    """Create a compact JSON-serializable summary."""

    date_series = pd.to_datetime(frame["dateadded_utc"], utc=True, errors="coerce")
    return {
        "total_indicators": int(len(frame)),
        "unique_hosts": int(frame["host"].nunique(dropna=True)),
        "unique_registered_domains": int(frame["registered_domain"].nunique(dropna=True)),
        "unique_reporters": int(frame["reporter"].nunique(dropna=True)),
        "online_indicators": int((frame["url_status"].astype(str).str.lower() == "online").sum()),
        "ip_host_indicators": int((frame["host_type"] == "ip").sum()),
        "domain_host_indicators": int((frame["host_type"] == "domain").sum()),
        "first_seen_utc": str(date_series.min()) if date_series.notna().any() else None,
        "last_seen_utc": str(date_series.max()) if date_series.notna().any() else None,
    }


def value_counts(frame: pd.DataFrame, column: str, limit: int = 20) -> pd.DataFrame:
    """Return a stable value-count table for a column."""

    counts = frame[column].fillna("missing").astype(str).value_counts().head(limit)
    return counts.rename_axis(column).reset_index(name="count")


def daily_trend(frame: pd.DataFrame) -> pd.DataFrame:
    """Count indicators by day and URL status."""

    date_series = pd.to_datetime(frame["dateadded_utc"], utc=True, errors="coerce")
    trend = frame.assign(date=date_series.dt.date.astype(str))
    trend = trend.groupby(["date", "url_status"], dropna=False).size().reset_index(name="count")
    return trend.sort_values(["date", "url_status"])


def top_tags(frame: pd.DataFrame, limit: int = 30) -> pd.DataFrame:
    """Return the most common malware tags."""

    exploded = _explode_tags(frame)
    if exploded.empty:
        return pd.DataFrame(columns=["tag", "count"])
    return exploded.value_counts().head(limit).rename_axis("tag").reset_index(name="count")


def write_reports(frame: pd.DataFrame, output_dir: str | Path) -> dict[str, Path]:
    """Write analytical reports to disk and return generated paths."""

    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)

    outputs = {
        "summary": path / "summary.json",
        "status_distribution": path / "status_distribution.csv",
        "threat_distribution": path / "threat_distribution.csv",
        "top_ports": path / "top_ports.csv",
        "top_tlds": path / "top_tlds.csv",
        "top_reporters": path / "top_reporters.csv",
        "top_tags": path / "top_tags.csv",
        "daily_trend": path / "daily_trend.csv",
    }

    outputs["summary"].write_text(json.dumps(create_summary(frame), indent=2), encoding="utf-8")
    value_counts(frame, "url_status").to_csv(outputs["status_distribution"], index=False)
    value_counts(frame, "threat").to_csv(outputs["threat_distribution"], index=False)
    value_counts(frame, "port").to_csv(outputs["top_ports"], index=False)
    value_counts(frame, "tld").to_csv(outputs["top_tlds"], index=False)
    value_counts(frame, "reporter").to_csv(outputs["top_reporters"], index=False)
    top_tags(frame).to_csv(outputs["top_tags"], index=False)
    daily_trend(frame).to_csv(outputs["daily_trend"], index=False)

    return outputs
