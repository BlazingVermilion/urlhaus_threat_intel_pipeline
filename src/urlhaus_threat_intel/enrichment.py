"""Threat indicator enrichment and feature engineering."""

from __future__ import annotations

import pandas as pd

from .feature_engineering import add_engineered_features
from .url_utils import parse_url


def _count_tags(tags: str | None) -> int:
    if tags is None:
        return 0
    cleaned = str(tags).strip()
    if cleaned in {"", "None", "nan", "<NA>"}:
        return 0
    return len([tag for tag in cleaned.split(",") if tag.strip()])


def normalize_indicators(raw_frame: pd.DataFrame) -> pd.DataFrame:
    """Normalize and enrich raw URLhaus indicators."""

    frame = raw_frame.copy()
    frame["dateadded_utc"] = pd.to_datetime(frame["dateadded"], utc=True, errors="coerce")

    parsed_urls = frame["url"].apply(parse_url)
    parsed_frame = pd.DataFrame([item.__dict__ for item in parsed_urls])

    enriched = pd.concat([frame, parsed_frame], axis=1)
    enriched["tag_count"] = enriched["tags"].apply(_count_tags).astype("int64")
    enriched = add_engineered_features(enriched)

    # Keep IDs stable as strings in files, while storing numeric IDs is handled
    # by SQLite schema where possible.
    return enriched
