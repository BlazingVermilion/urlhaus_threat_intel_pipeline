"""Operational triage scoring for threat indicators.

URLhaus entries are already malicious or suspicious indicators. This scoring
module does not classify benign vs malicious traffic. It creates a practical
prioritization score for defenders who need to decide which indicators deserve
attention first.
"""

from __future__ import annotations

import pandas as pd

HIGH_SIGNAL_TAGS = {
    "Mozi",
    "Mirai",
    "Emotet",
    "Qakbot",
    "IcedID",
    "SocGholish",
    "CobaltStrike",
    "AsyncRAT",
    "AgentTesla",
    "elf",
}
SUSPICIOUS_PORTS = {23, 2323, 445, 8080, 8443, 9001, 5555, 37215, 52869}


def _tag_signal(tags: str | None) -> float:
    if tags is None:
        return 0.0
    tag_values = {tag.strip() for tag in str(tags).split(",") if tag.strip()}
    if not tag_values or tag_values == {"None"}:
        return 0.0
    if tag_values & HIGH_SIGNAL_TAGS:
        return 0.25
    return 0.10


def score_indicators(frame: pd.DataFrame) -> pd.DataFrame:
    """Add risk_score and risk_level columns to a normalized indicator frame."""

    scored = frame.copy()
    scores = []
    reasons = []

    for _, row in scored.iterrows():
        score = 0.0
        reason_parts = []

        if str(row.get("url_status", "")).lower() == "online":
            score += 0.30
            reason_parts.append("online")

        if row.get("host_type") == "ip":
            score += 0.20
            reason_parts.append("ip-host")

        port = row.get("port")
        try:
            port_int = int(port) if pd.notna(port) else None
        except (TypeError, ValueError):
            port_int = None
        if port_int in SUSPICIOUS_PORTS:
            score += 0.15
            reason_parts.append(f"suspicious-port-{port_int}")

        tag_score = _tag_signal(row.get("tags"))
        if tag_score:
            score += tag_score
            reason_parts.append("malware-tag-signal")

        if int(row.get("path_depth", 0) or 0) >= 3:
            score += 0.05
            reason_parts.append("deep-path")

        if int(row.get("has_executable_extension", 0) or 0) == 1:
            score += 0.10
            reason_parts.append("executable-path")

        if int(row.get("has_suspicious_path_keyword", 0) or 0) == 1:
            score += 0.05
            reason_parts.append("suspicious-path-keyword")

        if bool(row.get("has_query")):
            score += 0.05
            reason_parts.append("query-string")

        score = min(score, 1.0)
        scores.append(round(score, 3))
        reasons.append(";".join(reason_parts) if reason_parts else "baseline")

    scored["risk_score"] = scores
    scored["risk_level"] = [
        "high" if score >= 0.70 else "medium" if score >= 0.40 else "low"
        for score in scores
    ]
    scored["risk_reason"] = reasons
    return scored.sort_values(["risk_score", "dateadded_utc"], ascending=[False, False])
