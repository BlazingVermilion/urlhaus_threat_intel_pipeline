"""Data collection utilities for public URLhaus CSV feeds."""

from __future__ import annotations

from pathlib import Path

import requests

DEFAULT_URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"


def download_urlhaus_csv(
    output_path: str | Path,
    url: str = DEFAULT_URLHAUS_CSV_URL,
    timeout: int = 60,
    chunk_size: int = 1024 * 128,
) -> Path:
    """Download the recent URLhaus CSV dump to a local file."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with requests.get(url, stream=True, timeout=timeout) as response:
        response.raise_for_status()
        with path.open("wb") as file_obj:
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    file_obj.write(chunk)

    return path
