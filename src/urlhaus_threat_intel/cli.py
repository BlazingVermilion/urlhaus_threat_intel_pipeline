"""Command-line interface for the URLhaus threat-intelligence pipeline."""

from __future__ import annotations

import argparse
from pathlib import Path

from .analytics import write_reports
from .collector import DEFAULT_URLHAUS_CSV_URL, download_urlhaus_csv
from .enrichment import normalize_indicators
from .modeling import fit_anomaly_model
from .parser import read_urlhaus_csv
from .risk import score_indicators
from .storage import upsert_indicators


def _load_normalized(input_path: str | Path):
    import pandas as pd

    return pd.read_csv(input_path)


def command_download(args: argparse.Namespace) -> None:
    output = download_urlhaus_csv(args.output, url=args.url)
    print(f"Downloaded URLhaus CSV to {output}")


def command_ingest(args: argparse.Namespace) -> None:
    raw = read_urlhaus_csv(args.input)
    normalized = normalize_indicators(raw)

    normalized_path = Path(args.normalized_output)
    normalized_path.parent.mkdir(parents=True, exist_ok=True)
    normalized.to_csv(normalized_path, index=False)

    inserted = upsert_indicators(normalized, args.db)
    print(f"Parsed {len(raw)} raw indicators")
    print(f"Stored {inserted} normalized indicators in {args.db}")
    print(f"Wrote normalized CSV to {normalized_path}")


def command_analyze(args: argparse.Namespace) -> None:
    normalized = _load_normalized(args.input)
    outputs = write_reports(normalized, args.output_dir)
    print("Generated reports:")
    for name, path in outputs.items():
        print(f"- {name}: {path}")


def command_score(args: argparse.Namespace) -> None:
    normalized = _load_normalized(args.input)
    scored = score_indicators(normalized)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    scored.to_csv(output, index=False)
    print(f"Wrote scored indicators to {output}")


def command_model(args: argparse.Namespace) -> None:
    normalized = _load_normalized(args.input)
    result = fit_anomaly_model(
        normalized,
        model_path=args.model_output,
        output_path=args.scored_output,
        feature_output_path=args.feature_output,
        metadata_output_path=args.metadata_output,
        contamination=args.contamination,
    )
    print(f"Trained IsolationForest on {len(result)} indicators")
    print(f"Wrote model to {args.model_output}")
    print(f"Wrote anomaly scores to {args.scored_output}")


def command_run(args: argparse.Namespace) -> None:
    output_dir = Path(args.output_dir)
    processed_dir = output_dir / "processed"
    report_dir = output_dir / "reports"
    model_dir = output_dir / "models"

    normalized_csv = processed_dir / "urlhaus_normalized.csv"
    risk_csv = processed_dir / "urlhaus_prioritized_indicators.csv"
    anomaly_csv = processed_dir / "urlhaus_ml_anomaly_scores.csv"
    feature_csv = processed_dir / "urlhaus_ml_feature_matrix.csv"
    db_path = output_dir / "threat_intel.db"

    raw = read_urlhaus_csv(args.input)
    normalized = normalize_indicators(raw)
    processed_dir.mkdir(parents=True, exist_ok=True)
    normalized.to_csv(normalized_csv, index=False)
    upsert_indicators(normalized, db_path)

    write_reports(normalized, report_dir)
    prioritized = score_indicators(normalized)
    prioritized.to_csv(risk_csv, index=False)
    fit_anomaly_model(
        prioritized,
        model_path=model_dir / "isolation_forest.joblib",
        output_path=anomaly_csv,
        feature_output_path=feature_csv,
        metadata_output_path=model_dir / "model_metadata.json",
        contamination=args.contamination,
    )

    print("Pipeline completed")
    print(f"- normalized CSV: {normalized_csv}")
    print(f"- SQLite database: {db_path}")
    print(f"- reports: {report_dir}")
    print(f"- prioritized indicators: {risk_csv}")
    print(f"- ML feature matrix: {feature_csv}")
    print(f"- ML anomaly scores: {anomaly_csv}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="urlhaus-ti",
        description="URLhaus threat-intelligence ETL, enrichment, analytics, and scoring pipeline.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    download_parser = subparsers.add_parser("download", help="Download the latest URLhaus CSV feed")
    download_parser.add_argument("--url", default=DEFAULT_URLHAUS_CSV_URL)
    download_parser.add_argument("--output", default="data/raw/urlhaus_recent.csv")
    download_parser.set_defaults(func=command_download)

    ingest_parser = subparsers.add_parser(
        "ingest",
        help="Parse, enrich, and store URLhaus indicators",
    )
    ingest_parser.add_argument("--input", required=True)
    ingest_parser.add_argument("--db", default="data/processed/threat_intel.db")
    ingest_parser.add_argument(
        "--normalized-output",
        default="data/processed/urlhaus_normalized.csv",
    )
    ingest_parser.set_defaults(func=command_ingest)

    analyze_parser = subparsers.add_parser("analyze", help="Generate analytical CSV/JSON reports")
    analyze_parser.add_argument("--input", required=True)
    analyze_parser.add_argument("--output-dir", default="reports/generated")
    analyze_parser.set_defaults(func=command_analyze)

    score_parser = subparsers.add_parser(
        "score",
        help="Prioritize indicators with a rule-based triage score",
    )
    score_parser.add_argument("--input", required=True)
    score_parser.add_argument(
        "--output",
        default="data/processed/urlhaus_prioritized_indicators.csv",
    )
    score_parser.set_defaults(func=command_score)

    model_parser = subparsers.add_parser(
        "model",
        help="Train a lightweight anomaly-scoring baseline",
    )
    model_parser.add_argument("--input", required=True)
    model_parser.add_argument("--model-output", default="models/isolation_forest.joblib")
    model_parser.add_argument(
        "--scored-output",
        default="data/processed/urlhaus_ml_anomaly_scores.csv",
    )
    model_parser.add_argument(
        "--feature-output",
        default="data/processed/urlhaus_ml_feature_matrix.csv",
    )
    model_parser.add_argument(
        "--metadata-output",
        default="models/model_metadata.json",
    )
    model_parser.add_argument("--contamination", type=float, default=0.10)
    model_parser.set_defaults(func=command_model)

    run_parser = subparsers.add_parser("run", help="Run the complete offline pipeline")
    run_parser.add_argument("--input", default="data/sample/urlhaus_recent_sample.csv")
    run_parser.add_argument("--output-dir", default="outputs/demo")
    run_parser.add_argument("--contamination", type=float, default=0.10)
    run_parser.set_defaults(func=command_run)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
