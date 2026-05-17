from __future__ import annotations

import re
import time

from agentguard_local.catalog import load_catalog
from agentguard_local.models import Catalog, CatalogEntry, Decision, DecisionStatus, Ecosystem, InstallIntent, RiskRule

PIP_RE = re.compile(r"pip(?:3)?\s+install\s+([a-zA-Z0-9_.-]+)(?:==([a-zA-Z0-9_.-]+))?")
NPM_RE = re.compile(r"npm\s+install\s+(@?[a-zA-Z0-9_.\\/-]+)(?:@([a-zA-Z0-9_.-]+))?")
MAVEN_RE = re.compile(r"mvn\s+dependency:get\s+-Dartifact=([a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+):([a-zA-Z0-9_.-]+)")
CRATE_RE = re.compile(r"cargo\s+add\s+([a-zA-Z0-9_.-]+)(?:@([a-zA-Z0-9_.-]+))?")


def normalize(name: str) -> str:
    return name.lower().replace("_", "-")


def damerau_levenshtein(a: str, b: str) -> int:
    da: dict[str, int] = {}
    maxdist = len(a) + len(b)
    d = [[0] * (len(b) + 2) for _ in range(len(a) + 2)]
    d[0][0] = maxdist
    for i in range(len(a) + 1):
        d[i + 1][0] = maxdist
        d[i + 1][1] = i
    for j in range(len(b) + 1):
        d[0][j + 1] = maxdist
        d[1][j + 1] = j
    for i, ca in enumerate(a, start=1):
        db = 0
        for j, cb in enumerate(b, start=1):
            i1 = da.get(cb, 0)
            j1 = db
            cost = 0 if ca == cb else 1
            if cost == 0:
                db = j
            d[i + 1][j + 1] = min(
                d[i][j] + cost,
                d[i + 1][j] + 1,
                d[i][j + 1] + 1,
                d[i1][j1] + (i - i1 - 1) + 1 + (j - j1 - 1),
            )
        da[ca] = i
    return d[len(a) + 1][len(b) + 1]


def parse_intent(raw: str) -> InstallIntent:
    for ecosystem, regex in (
        (Ecosystem.PYPI, PIP_RE),
        (Ecosystem.NPM, NPM_RE),
        (Ecosystem.MAVEN, MAVEN_RE),
        (Ecosystem.CRATES, CRATE_RE),
    ):
        match = regex.search(raw)
        if match:
            return InstallIntent(raw=raw, ecosystem=ecosystem, name=normalize(match.group(1)), version=match.group(2))
    raise ValueError(f"Unsupported dependency intent: {raw}")


def find_entry(intent: InstallIntent, catalog: Catalog) -> CatalogEntry | None:
    for entry in catalog.entries:
        names = [normalize(entry.name), *[normalize(alias) for alias in entry.aliases]]
        if entry.ecosystem == intent.ecosystem and intent.name in names:
            return entry
    return None


def find_risk(intent: InstallIntent, catalog: Catalog) -> RiskRule | None:
    for rule in catalog.risk_rules:
        version_match = rule.version is None or rule.version == intent.version
        if rule.ecosystem == intent.ecosystem and normalize(rule.name) == intent.name and version_match:
            return rule
    return None


def typo_suggestion(name: str, catalog: Catalog) -> str | None:
    candidates = [normalize(item) for item in catalog.top_packages]
    scored = sorted((damerau_levenshtein(name, candidate), candidate) for candidate in candidates)
    if scored and scored[0][0] <= 2 and scored[0][1] != name:
        return scored[0][1]
    return None


def decide(raw: str, catalog: Catalog | None = None) -> Decision:
    active_catalog = catalog or load_catalog()
    started = time.perf_counter()
    intent = parse_intent(raw)
    risk = find_risk(intent, active_catalog)
    entry = find_entry(intent, active_catalog)
    suggestion = typo_suggestion(intent.name, active_catalog)
    status = DecisionStatus.ALLOWED
    reason = "catalog_hit"
    reason_human = "Dependency is present in the trusted local catalog."
    guarded_ref = entry.guarded_ref if entry else None
    bundle = entry.sigstore_bundle if entry else None
    score = 0.0

    if risk:
        status = DecisionStatus.REPLACED if risk.replacement else DecisionStatus.BLOCKED
        reason = "risk_rule_match"
        reason_human = risk.reason
        guarded_ref = risk.replacement
        bundle = entry.sigstore_bundle if entry else None
        score = risk.score
    elif suggestion and not entry:
        status = DecisionStatus.BLOCKED
        reason = "typo_squat_candidate"
        reason_human = f"Package resembles trusted package `{suggestion}` but is not in the trusted catalog."
        score = 0.91
    elif not entry:
        status = DecisionStatus.BLOCKED
        reason = "not_in_trusted_catalog"
        reason_human = "Dependency is not present in the trusted local catalog."
        score = 0.64

    return Decision(
        raw=raw,
        ecosystem=intent.ecosystem,
        name=intent.name,
        version=intent.version,
        status=status,
        reason=reason,
        reason_human=reason_human,
        guarded_ref=guarded_ref,
        sigstore_bundle=bundle,
        typo_suggestion=suggestion,
        malcontent_score=score,
        latency_ms=round((time.perf_counter() - started) * 1000, 4),
    )
