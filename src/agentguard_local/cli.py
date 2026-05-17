from __future__ import annotations

import json
import sys

import typer
from rich.console import Console

from agentguard_local.dashboard import benchmark_summary, build_dashboard
from agentguard_local.engine import decide
from agentguard_local.runner import export_demo_pack, init_demo, run_suite, verify_outputs

app = typer.Typer(help="Local dependency-intent guard for coding agents.")
console = Console()


@app.command("init-demo")
def init_demo_command(force: bool = typer.Option(False, "--force")) -> None:
    console.print_json(data=init_demo(force=force))


@app.command("decide")
def decide_command(command: str) -> None:
    console.print_json(decide(command).model_dump_json(indent=2))


@app.command("run-suite")
def run_suite_command(iterations: int = typer.Option(50, min=1, max=1000)) -> None:
    console.print_json(run_suite(iterations=iterations).model_dump_json(indent=2))


@app.command("verify")
def verify_command() -> None:
    report = verify_outputs()
    console.print_json(data=report)
    if not report["passed"]:
        raise typer.Exit(1)


@app.command("dashboard")
def dashboard_command() -> None:
    console.print(str(build_dashboard()))


@app.command("benchmark")
def benchmark_command() -> None:
    console.print_json(data=benchmark_summary())


@app.command("export-demo-pack")
def export_demo_pack_command() -> None:
    console.print(str(export_demo_pack()))


@app.command("stdio")
def stdio_command() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        payload = json.loads(line)
        command = payload.get("command", "")
        sys.stdout.write(decide(command).model_dump_json() + "\n")
        sys.stdout.flush()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
