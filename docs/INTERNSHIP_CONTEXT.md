# Internship Context and Portfolio Reframing

This repository was refactored from a small internship-era script that collected
URLhaus data and inserted it into SQLite. The GitHub version reframes that work
as a professional threat-intelligence data pipeline.

## Why this project fits Network / Cyber Security

The internship report focused on network-security monitoring, DDoS alert
analysis, and mitigation concepts around Arbor Sightline. Instead of publishing
internal screenshots, customer information, or operational details, this project
uses public URLhaus indicators to demonstrate similar defensive skills in a safe
and reproducible way:

- collecting public threat indicators;
- extracting URL, host, IP, port, and path features;
- storing indicators in SQLite for investigation;
- generating operational reports for triage;
- building rule-based prioritization and an ML-ready anomaly baseline.

## What was intentionally excluded

The original internship report and any internal screenshots should not be pushed
to GitHub. The public project avoids:

- private customer names or internal monitoring screenshots;
- real attack tooling or offensive instructions;
- hard-coded local paths;
- generated `.git`, `.idea`, and `__pycache__` folders;
- large raw data dumps that can be downloaded again from the public source.
