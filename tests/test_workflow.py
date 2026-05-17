from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from agentguard_local.dashboard import build_dashboard
from agentguard_local.engine import damerau_levenshtein, decide, parse_intent
from agentguard_local.models import DecisionStatus, Ecosystem
from agentguard_local.runner import init_demo, run_suite, verify_outputs


def test_single_decisions_cover_allow_replace_block() -> None:
    assert decide("pip install numpy").status == DecisionStatus.ALLOWED
    assert decide("pip install litellm==1.74.0").status == DecisionStatus.REPLACED
    typo = decide("pip install nuumpy")
    assert typo.status == DecisionStatus.BLOCKED
    assert typo.typo_suggestion == "numpy"


def test_intent_parser_handles_ecosystems() -> None:
    assert parse_intent("npm install left-pad").ecosystem == Ecosystem.NPM
    assert parse_intent("cargo add serde").ecosystem == Ecosystem.CRATES
    assert parse_intent("mvn dependency:get -Dartifact=org.apache.commons:commons-text:1.10.0").name.endswith("commons-text")


def test_distance_catches_transposition() -> None:
    assert damerau_levenshtein("nuumpy", "numpy") <= 2


def test_end_to_end_suite_and_verify() -> None:
    init_demo(force=True)
    summary = run_suite(iterations=50)
    report = verify_outputs()
    assert summary.malicious_recall == 1.0
    assert summary.false_positive_rate == 0.0
    assert report["passed"] is True


def test_dashboard_and_stdio_contract() -> None:
    init_demo(force=True)
    run_suite(iterations=50)
    html = Path(build_dashboard()).read_text(encoding="utf-8")
    assert "Decision Mix" in html
    assert "Verification passed" in html
    process = subprocess.run(
        [sys.executable, "-m", "agentguard_local.cli", "stdio"],
        input='{"command":"pip install nuumpy"}\n',
        text=True,
        capture_output=True,
        check=True,
    )
    decision = json.loads(process.stdout)
    assert decision["status"] == "blocked"
