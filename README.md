# Local Agent Dependency Guard

A local dependency-intent guard for AI coding agents. It evaluates package install requests before a tool call reaches a registry, then returns structured JSON that an agent can use to allow, block, or rewrite its plan.

The demo is fully offline. It uses a synthetic trusted catalog, seeded compromised-package samples, typo-squat probes, latency benchmarks, and a self-contained dashboard.

## Quick Start

```bash
uv sync
uv run agentguard-local init-demo
uv run agentguard-local run-suite --iterations 50
uv run agentguard-local verify
uv run agentguard-local dashboard
```

Try a single decision:

```bash
uv run agentguard-local decide "pip install nuumpy"
```

## Outputs

- `runs/latest/results.duckdb` with every decision and metric
- `outputs/summary.json` with recall, false-positive, and latency gates
- `outputs/decision_stream.jsonl` with agent-readable tool results
- `outputs/dashboard.html` with visual allow/block/replace analytics
- `outputs/demo_pack/` with a portable evidence bundle
