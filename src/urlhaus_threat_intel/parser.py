"""Input parsing for URLhaus CSV dumps."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from .schema import URLHAUS_COLUMNS


def read_urlhaus_csv(input_path: str | Path) -> pd.DataFrame:
    """Read a URLhaus CSV dump and return a clean DataFrame.

    URLhaus CSV dumps contain metadata comments before the actual rows. The
    header itself is also included as a commented line, so the parser supplies
    an explicit schema and skips all comment lines.
    """

    path = Path(input_path)
    if not path.exists():
        raise FileNotFoundError(f"Input CSV not found: {path}")

    frame = pd.read_csv(
        path,
        comment="#",
        names=URLHAUS_COLUMNS,
        dtype="string",
        keep_default_na=False,
        quotechar='"',
    )

    # Drop fully empty rows and duplicate indicators by URLhaus ID.
    frame = frame.dropna(how="all")
    frame = frame[frame["id"].astype(str).str.strip() != ""]
    frame = frame.drop_duplicates(subset=["id"], keep="last")

    return frame.reset_index(drop=True)
