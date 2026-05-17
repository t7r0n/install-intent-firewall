from __future__ import annotations

import shutil
import statistics
import uuid
from pathlib import Path
from typing import Any

import duckdb

from agentguard_local.catalog import load_catalog, load_suite
from agentguard_local.engine import decide
from agentguard_local.models import Decision, DecisionStatus, RunSummary, SuiteCase, project_root


def init_demo(force: bool = False) -> dict[str, str]:
    root = project_root()
    for name in ("runs", "outputs", "data/runtime"):
        path = root / name
        if force and path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True, exist_ok=True)
    return {"catalog": str(root / "data" / "catalog.json"), "suite": str(root / "suites" / "dependency_intents.json")}


def connect_store(path: Path) -> duckdb.DuckDBPyConnection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = duckdb.connect(str(path))
    conn.execute(
        """
        create table if not exists decisions (
          run_id varchar,
          case_id varchar,
          command varchar,
          ecosystem varchar,
          package varchar,
          version varchar,
          status varchar,
          expected_status varchar,
          malicious boolean,
          malcontent_score double,
          latency_ms double,
          reason varchar
        )
        """
    )
    return conn


def persist(conn: duckdb.DuckDBPyConnection, run_id: str, case: SuiteCase, decision: Decision) -> None:
    conn.execute(
        "insert into decisions values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            run_id,
            case.id,
            case.command,
            decision.ecosystem.value,
            decision.name,
            decision.version,
            decision.status.value,
            case.expected_status.value,
            case.malicious,
            decision.malcontent_score,
            decision.latency_ms,
            decision.reason,
        ],
    )


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    return float(statistics.quantiles(values, n=100, method="inclusive")[int(pct) - 1])


def summarize(run_id: str, rows: list[tuple[SuiteCase, Decision]]) -> RunSummary:
    malicious = [(case, decision) for case, decision in rows if case.malicious]
    clean = [(case, decision) for case, decision in rows if not case.malicious]
    caught = sum(1 for _, decision in malicious if decision.status in {DecisionStatus.BLOCKED, DecisionStatus.REPLACED})
    false_positive = sum(1 for _, decision in clean if decision.status == DecisionStatus.BLOCKED)
    allowed_latencies = [decision.latency_ms for _, decision in clean if decision.status in {DecisionStatus.ALLOWED, DecisionStatus.REPLACED}]
    scan_latencies = [decision.latency_ms for _, decision in rows if decision.malcontent_score > 0]
    status_counts: dict[str, int] = {}
    for _, decision in rows:
        status_counts[decision.status.value] = status_counts.get(decision.status.value, 0) + 1
    recall = caught / len(malicious) if malicious else 1.0
    fp_rate = false_positive / len(clean) if clean else 0.0
    p95_allowed = percentile(allowed_latencies, 95)
    p95_scan = percentile(scan_latencies, 95)
    return RunSummary(
        run_id=run_id,
        decision_count=len(rows),
        malicious_recall=round(recall, 4),
        false_positive_rate=round(fp_rate, 4),
        p95_allowed_latency_ms=round(p95_allowed, 4),
        p95_scan_latency_ms=round(p95_scan, 4),
        pass_gates=recall == 1.0 and fp_rate <= 0.005 and p95_allowed < 5 and p95_scan < 300,
        status_counts=status_counts,
    )


def run_suite(iterations: int = 50) -> RunSummary:
    init_demo()
    catalog = load_catalog()
    suite = load_suite()
    run_id = f"run-{uuid.uuid4().hex[:12]}"
    root = project_root()
    run_dir = root / "runs" / "latest"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    conn = connect_store(run_dir / "results.duckdb")
    stream_path = root / "outputs" / "decision_stream.jsonl"
    if stream_path.exists():
        stream_path.unlink()
    rows: list[tuple[SuiteCase, Decision]] = []
    with stream_path.open("w", encoding="utf-8") as stream:
        for _ in range(iterations):
            for case in suite.cases:
                decision = decide(case.command, catalog)
                persist(conn, run_id, case, decision)
                stream.write(decision.model_dump_json() + "\n")
                rows.append((case, decision))
    conn.close()
    summary = summarize(run_id, rows)
    (root / "outputs" / "summary.json").write_text(summary.model_dump_json(indent=2), encoding="utf-8")
    return summary


def verify_outputs() -> dict[str, Any]:
    root = project_root()
    summary_path = root / "outputs" / "summary.json"
    stream_path = root / "outputs" / "decision_stream.jsonl"
    db_path = root / "runs" / "latest" / "results.duckdb"
    if not summary_path.exists() or not stream_path.exists() or not db_path.exists():
        raise FileNotFoundError("Run `uv run agentguard-local run-suite` before verification.")
    summary = RunSummary.model_validate_json(summary_path.read_text(encoding="utf-8"))
    conn = duckdb.connect(str(db_path), read_only=True)
    mismatch = conn.execute("select count(*) from decisions where status != expected_status").fetchone()[0]
    row_count = conn.execute("select count(*) from decisions").fetchone()[0]
    conn.close()
    stream_count = sum(1 for _ in stream_path.open("r", encoding="utf-8"))
    checks = {
        "required_outputs_present": summary_path.exists() and stream_path.exists() and db_path.exists(),
        "decision_count_at_least_250": row_count >= 250,
        "all_expected_statuses_match": mismatch == 0,
        "malicious_recall_100_percent": summary.malicious_recall == 1.0,
        "false_positive_rate_under_0_5_percent": summary.false_positive_rate <= 0.005,
        "p95_allowed_under_5ms": summary.p95_allowed_latency_ms < 5,
        "p95_scan_under_300ms": summary.p95_scan_latency_ms < 300,
        "jsonl_stream_matches_db": stream_count == row_count,
    }
    return {"run_id": summary.run_id, "summary": summary.model_dump(), "checks": checks, "passed": all(checks.values())}


def export_demo_pack() -> Path:
    root = project_root()
    pack = root / "outputs" / "demo_pack"
    if pack.exists():
        shutil.rmtree(pack)
    pack.mkdir(parents=True, exist_ok=True)
    for name in ("summary.json", "decision_stream.jsonl", "dashboard.html"):
        source = root / "outputs" / name
        if source.exists():
            shutil.copy2(source, pack / name)
    shutil.copy2(root / "data" / "catalog.json", pack / "catalog.json")
    shutil.copy2(root / "suites" / "dependency_intents.json", pack / "dependency_intents.json")
    return pack
