# Code Review and Refactor Report

## Original issues found

The uploaded project contained a useful idea but was structured like a quick
internship script:

- project name contained a typo: `url_hause` instead of URLhaus;
- `.git`, `.idea`, and `__pycache__` were included in the ZIP;
- database path was hard-coded to a local Windows path;
- CSV parsing depended on manual row deletion and implicit column positions;
- URL parsing used string splitting, which breaks on malformed URLs, IPv6,
  missing schemes, and default ports;
- network download happened at import time in `UrlHausAPI.py`;
- database connection was created globally at import time;
- no CLI, tests, README, requirements pinning, or reusable package structure.

## Refactor decisions

The project was rebuilt as a professional Python package:

```text
src/urlhaus_threat_intel/
├── analytics.py      # reports and aggregate statistics
├── cli.py            # reproducible command-line workflow
├── collector.py      # safe feed download utility
├── enrichment.py     # URL/network feature extraction
├── modeling.py       # IsolationForest anomaly-scoring baseline
├── parser.py         # robust URLhaus CSV parser
├── risk.py           # operational prioritization score
├── schema.py         # shared data contracts
├── storage.py        # SQLite storage layer
└── url_utils.py      # URL parsing helpers
```

## Safety and GitHub-readiness

- No internal VNPT report files are included.
- No offensive DDoS tooling is included.
- Sample data is small and reproducible.
- Full recent URLhaus data can be downloaded by command.
- The pipeline runs offline using `data/sample/urlhaus_recent_sample.csv`.
