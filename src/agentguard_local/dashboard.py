from __future__ import annotations

from pathlib import Path

import duckdb
from jinja2 import Environment, select_autoescape

from agentguard_local.models import RunSummary, project_root
from agentguard_local.runner import verify_outputs

TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Agent Dependency Guard Dashboard</title>
  <style>
    :root { color-scheme: light dark; --bg:#f8fafc; --panel:#fff; --ink:#152033; --muted:#64748b; --line:#dbe3ef; --blue:#2563eb; --green:#0e9f6e; --amber:#d97706; --red:#c2410c; }
    @media (prefers-color-scheme: dark) { :root { --bg:#10141c; --panel:#171e2b; --ink:#eef4ff; --muted:#9aa8bc; --line:#2a3446; --blue:#7aa2ff; --green:#38c989; --amber:#f6b955; --red:#ff9363; } }
    * { box-sizing:border-box; }
    body { margin:0; background:var(--bg); color:var(--ink); font-family:Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    main { max-width:1120px; margin:0 auto; padding:32px 20px 48px; }
    header { display:flex; justify-content:space-between; align-items:flex-end; gap:20px; margin-bottom:24px; }
    h1 { margin:0 0 8px; font-size:28px; letter-spacing:0; }
    h2 { font-size:18px; margin:0 0 14px; }
    p { color:var(--muted); margin:0; }
    .grid { display:grid; gap:16px; }
    .metrics { grid-template-columns:repeat(4, minmax(0, 1fr)); }
    .charts { grid-template-columns:1fr 1fr; margin-top:16px; }
    .panel { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:18px; box-shadow:0 14px 28px rgba(15,23,42,.06); }
    .metric strong { display:block; font-size:26px; line-height:1.1; }
    .metric span { color:var(--muted); font-size:13px; }
    .stack { height:32px; display:flex; overflow:hidden; border-radius:999px; border:1px solid var(--line); }
    .seg { height:100%; }
    .allowed { background:var(--green); }
    .replaced { background:var(--blue); }
    .blocked { background:var(--red); }
    .bar-row { display:grid; grid-template-columns:180px 1fr 72px; gap:12px; align-items:center; margin:12px 0; }
    .track { height:18px; border-radius:999px; background:color-mix(in srgb, var(--line) 75%, transparent); overflow:hidden; border:1px solid var(--line); }
    .fill { height:100%; border-radius:999px; background:linear-gradient(90deg, var(--blue), var(--green)); min-width:2px; }
    table { width:100%; border-collapse:collapse; margin-top:8px; font-size:14px; }
    th, td { text-align:left; padding:10px 8px; border-bottom:1px solid var(--line); }
    th { color:var(--muted); font-weight:600; }
    .pass { color:var(--green); font-weight:700; }
    .fail { color:var(--red); font-weight:700; }
    @media (max-width:780px) { header { display:block; } .metrics, .charts { grid-template-columns:1fr; } }
  </style>
</head>
<body>
<main>
  <header>
    <div>
      <h1>Agent Dependency Guard Dashboard</h1>
      <p>Run {{ summary.run_id }} · pre-install allow, block, and trusted-replacement decisions.</p>
    </div>
    <p class="{{ 'pass' if verification.passed else 'fail' }}">{{ 'Verification passed' if verification.passed else 'Verification failed' }}</p>
  </header>
  <section class="grid metrics">
    <div class="panel metric"><strong>{{ summary.decision_count }}</strong><span>decisions</span></div>
    <div class="panel metric"><strong>{{ '%.0f'|format(summary.malicious_recall * 100) }}%</strong><span>malicious recall</span></div>
    <div class="panel metric"><strong>{{ '%.2f'|format(summary.false_positive_rate * 100) }}%</strong><span>false positive rate</span></div>
    <div class="panel metric"><strong>{{ summary.p95_allowed_latency_ms }}ms</strong><span>p95 allowed latency</span></div>
  </section>
  <section class="grid charts">
    <div class="panel">
      <h2>Decision Mix</h2>
      <div class="stack">
        {% for status, count in summary.status_counts.items() %}
          <div class="seg {{ status }}" title="{{ status }} {{ count }}" style="width: {{ (count / summary.decision_count) * 100 }}%"></div>
        {% endfor %}
      </div>
      <table><tbody>{% for status, count in summary.status_counts.items() %}<tr><td>{{ status }}</td><td>{{ count }}</td></tr>{% endfor %}</tbody></table>
    </div>
    <div class="panel">
      <h2>Latency Gates</h2>
      <div class="bar-row"><strong>Allowed p95</strong><div class="track"><div class="fill" style="width: {{ (summary.p95_allowed_latency_ms / 5) * 100 }}%"></div></div><span>{{ summary.p95_allowed_latency_ms }}ms</span></div>
      <div class="bar-row"><strong>Scan p95</strong><div class="track"><div class="fill" style="width: {{ (summary.p95_scan_latency_ms / 300) * 100 }}%"></div></div><span>{{ summary.p95_scan_latency_ms }}ms</span></div>
    </div>
  </section>
  <section class="panel" style="margin-top:16px">
    <h2>Verification Gates</h2>
    <table><tbody>{% for key, value in verification.checks.items() %}<tr><td>{{ key }}</td><td class="{{ 'pass' if value else 'fail' }}">{{ value }}</td></tr>{% endfor %}</tbody></table>
  </section>
</main>
</body>
</html>
"""


def build_dashboard() -> Path:
    root = project_root()
    summary_path = root / "outputs" / "summary.json"
    if not summary_path.exists():
        raise FileNotFoundError("Run `uv run agentguard-local run-suite` before dashboard generation.")
    summary = RunSummary.model_validate_json(summary_path.read_text(encoding="utf-8"))
    env = Environment(autoescape=select_autoescape(["html", "xml"]))
    html = env.from_string(TEMPLATE).render(summary=summary, verification=verify_outputs())
    target = root / "outputs" / "dashboard.html"
    target.write_text(html, encoding="utf-8")
    return target


def benchmark_summary() -> dict[str, float]:
    root = project_root()
    db_path = root / "runs" / "latest" / "results.duckdb"
    if not db_path.exists():
        raise FileNotFoundError("Run `uv run agentguard-local run-suite` first.")
    conn = duckdb.connect(str(db_path), read_only=True)
    row = conn.execute("select avg(latency_ms), max(latency_ms), count(*) from decisions").fetchone()
    conn.close()
    return {"avg_latency_ms": float(row[0]), "max_latency_ms": float(row[1]), "rows": float(row[2])}
