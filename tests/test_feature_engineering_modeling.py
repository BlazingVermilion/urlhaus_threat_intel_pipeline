from pathlib import Path

from urlhaus_threat_intel.enrichment import normalize_indicators
from urlhaus_threat_intel.feature_engineering import build_model_features, shannon_entropy
from urlhaus_threat_intel.modeling import fit_anomaly_model
from urlhaus_threat_intel.parser import read_urlhaus_csv
from urlhaus_threat_intel.risk import score_indicators

SAMPLE_PATH = Path("data/sample/urlhaus_recent_sample.csv")


def test_shannon_entropy_empty_string():
    assert shannon_entropy("") == 0.0


def test_build_model_features_returns_deterministic_matrix():
    normalized = normalize_indicators(read_urlhaus_csv(SAMPLE_PATH))
    feature_set = build_model_features(normalized)
    assert len(feature_set.features) == len(normalized)
    assert feature_set.features.shape[1] > 10
    assert feature_set.features.columns.tolist() == sorted(feature_set.features.columns.tolist())


def test_fit_anomaly_model_exports_scores(tmp_path):
    normalized = normalize_indicators(read_urlhaus_csv(SAMPLE_PATH))
    scored = score_indicators(normalized)
    result = fit_anomaly_model(
        scored,
        model_path=tmp_path / "model.joblib",
        output_path=tmp_path / "scores.csv",
        feature_output_path=tmp_path / "features.csv",
        metadata_output_path=tmp_path / "metadata.json",
        contamination=0.1,
    )
    assert (tmp_path / "model.joblib").exists()
    assert (tmp_path / "scores.csv").exists()
    assert (tmp_path / "features.csv").exists()
    assert (tmp_path / "metadata.json").exists()
    assert "ml_anomaly_score" in result.columns
    assert "hybrid_priority_score" in result.columns
