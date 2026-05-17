from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field


class Ecosystem(StrEnum):
    PYPI = "pypi"
    NPM = "npm"
    MAVEN = "maven"
    CRATES = "crates"


class DecisionStatus(StrEnum):
    ALLOWED = "allowed"
    REPLACED = "replaced"
    BLOCKED = "blocked"


class CatalogEntry(BaseModel):
    name: str
    ecosystem: Ecosystem
    safe_versions: list[str]
    guarded_ref: str
    sigstore_bundle: str
    aliases: list[str] = Field(default_factory=list)


class RiskRule(BaseModel):
    name: str
    ecosystem: Ecosystem
    version: str | None = None
    reason: str
    score: float
    cve: str | None = None
    replacement: str | None = None


class Catalog(BaseModel):
    entries: list[CatalogEntry]
    risk_rules: list[RiskRule]
    top_packages: list[str]


class InstallIntent(BaseModel):
    raw: str
    ecosystem: Ecosystem
    name: str
    version: str | None = None


class Decision(BaseModel):
    raw: str
    ecosystem: Ecosystem
    name: str
    version: str | None
    status: DecisionStatus
    reason: str
    reason_human: str
    guarded_ref: str | None
    sigstore_bundle: str | None
    typo_suggestion: str | None
    malcontent_score: float
    latency_ms: float


class SuiteCase(BaseModel):
    id: str
    command: str
    expected_status: DecisionStatus
    expected_name: str
    malicious: bool = False


class SuiteFile(BaseModel):
    cases: list[SuiteCase]


class RunSummary(BaseModel):
    run_id: str
    decision_count: int
    malicious_recall: float
    false_positive_rate: float
    p95_allowed_latency_ms: float
    p95_scan_latency_ms: float
    pass_gates: bool
    status_counts: dict[str, int]


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]
