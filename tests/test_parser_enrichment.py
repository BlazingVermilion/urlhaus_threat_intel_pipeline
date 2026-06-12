from pathlib import Path

from urlhaus_threat_intel.enrichment import normalize_indicators
from urlhaus_threat_intel.parser import read_urlhaus_csv

SAMPLE_PATH = Path("data/sample/urlhaus_recent_sample.csv")


def test_read_urlhaus_csv_skips_comments():
    frame = read_urlhaus_csv(SAMPLE_PATH)
    assert len(frame) == 150
    assert list(frame.columns)[:3] == ["id", "dateadded", "url"]
    assert not frame["id"].astype(str).str.startswith("#").any()


def test_normalize_indicators_adds_network_features():
    raw = read_urlhaus_csv(SAMPLE_PATH)
    normalized = normalize_indicators(raw)
    expected = {"host", "host_type", "port", "path_depth", "url_length", "tag_count"}
    assert expected.issubset(set(normalized.columns))
    assert normalized["url_length"].min() > 0


def test_engineered_features_support_ml_pipeline():
    raw = read_urlhaus_csv(SAMPLE_PATH)
    normalized = normalize_indicators(raw)
    expected = {
        "host_entropy",
        "host_digit_ratio",
        "file_extension",
        "has_executable_extension",
        "is_non_standard_port",
    }
    assert expected.issubset(set(normalized.columns))
    assert normalized["host_entropy"].ge(0).all()
    assert set(normalized["has_executable_extension"].unique()).issubset({0, 1})
