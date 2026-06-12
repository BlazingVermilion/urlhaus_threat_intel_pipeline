# Data and ML Design

This project is intentionally centered on data quality and ML-readiness rather than a single notebook-style experiment.

## Data Engineering Layer

The pipeline transforms raw URLhaus CSV rows into a normalized indicator dataset. Each row is parsed, enriched, and persisted in SQLite so it can support both investigation queries and downstream ML workflows.

Key design choices:

- Explicit input schema for URLhaus CSV rows.
- Robust handling of URLhaus metadata comments.
- Deterministic URL parsing using Python standard-library parsing.
- Structured outputs in CSV, JSON, SQLite, and Joblib formats.
- Generated outputs are separated from source code.

## Feature Engineering Layer

The feature matrix is generated from interpretable fields rather than raw strings. This makes the model easier to reproduce and inspect.

Feature groups:

- Numeric: port, path depth, URL length, tag count, host entropy, host digit ratio, path length.
- Binary: IP host flag, default-port flag, non-standard-port flag, executable-extension flag, suspicious path keyword flag.
- Categorical: scheme, host type, URL status, threat label, TLD.

## ML Layer

The ML component uses IsolationForest for unsupervised anomaly scoring.

Rationale:

- The feed contains threat indicators rather than a balanced benign/malicious classification dataset.
- The task is therefore framed as prioritization: which indicators look unusual within the current malicious feed batch?
- The exported model artifact includes the scaler, trained model, encoded feature names, and model metadata.

## Output Interpretation

The most useful operational columns are:

- `risk_score`: transparent rule-based triage score.
- `risk_reason`: explanation for the rule score.
- `ml_anomaly_score`: model-based anomaly score.
- `ml_anomaly_percentile`: normalized anomaly position within the current batch.
- `hybrid_priority_score`: a combined triage score for analyst review.
