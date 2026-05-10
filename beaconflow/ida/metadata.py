from __future__ import annotations

import json
from pathlib import Path

from beaconflow.models import ProgramMetadata


def load_metadata(path: str | Path) -> ProgramMetadata:
    return ProgramMetadata.from_json(json.loads(Path(path).read_text(encoding="utf-8")))


def save_metadata(metadata: ProgramMetadata, path: str | Path) -> None:
    Path(path).write_text(json.dumps(metadata.to_json(), indent=2), encoding="utf-8")

