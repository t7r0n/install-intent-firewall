from __future__ import annotations

import json
from pathlib import Path

from agentguard_local.models import Catalog, SuiteFile, project_root


def catalog_path() -> Path:
    return project_root() / "data" / "catalog.json"


def suite_path() -> Path:
    return project_root() / "suites" / "dependency_intents.json"


def load_catalog(path: Path | None = None) -> Catalog:
    with (path or catalog_path()).open("r", encoding="utf-8") as handle:
        return Catalog.model_validate(json.load(handle))


def load_suite(path: Path | None = None) -> SuiteFile:
    with (path or suite_path()).open("r", encoding="utf-8") as handle:
        return SuiteFile.model_validate(json.load(handle))
