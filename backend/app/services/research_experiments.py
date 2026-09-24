from __future__ import annotations

import json
import uuid
from html import escape
from pathlib import Path
from typing import Any

from .p2cv import parse_policy, build_requirement_graph, generate_dsl, semantic_verify
from .p2cv_v3 import compile_policy_v3
from .benchmark_engine import evaluate_benchmark, benchmark_manifest

ROOT = Path(__file__).resolve().parents[3]
POLICY_GT = ROOT / "benchmark" / "policies" / "policy_ground_truth_v3_50.json"
RESULTS = ROOT / "experiments" / "results"
RESULTS.mkdir(parents=True, exist_ok=True)


def _approval(structured: dict[str, Any]) -> bool:
    return structured.get("exception") == "manager_approval" or any(c.get("field") == "manager_approval" for c in structured.get("conditions", []))


def _threshold(structured: dict[str, Any]) -> float | None:
    c = next((x for x in structured.get("conditions", []) if x.get("field") == "amount"), None)
    return None if c is None else float(c.get("value", 0))


def _score(structured: dict[str, Any], expected: dict[str, Any]) -> tuple[float, dict[str, bool]]:
    fields = {
        "action": structured.get("action") == expected.get("action"),
        "resource": structured.get("resource") == expected.get("resource"),
        "destination": structured.get("destination") == expected.get("destination"),
        "effect": structured.get("effect") == expected.get("effect"),
        "approval": _approval(structured) == bool(expected.get("approval", False)),
        "temporal": list(structured.get("temporal_constraints", [])) == list(expected.get("temporal", [])),
    }
    if "threshold" in expected:
        fields["threshold"] = _threshold(structured) == float(expected["threshold"])
    return sum(fields.values()) / len(fields), fields


def _direct_baseline(text: str) -> dict[str, Any]:
    # Deliberately minimal baseline: direct text -> DSL slots, no graph/formal feedback.
    p = parse_policy(text)
    return {
        "subject": "AnyAgent",
        "action": p.get("action", "execute"),
        "resource": p.get("resource", "AnyResource"),
        "destination": "AnyDestination",
        "effect": "DENY" if p.get("effect") == "DENY" else "ALLOW",
        "conditions": [],
        "temporal_constraints": [],
        "exception": None,
    }


def compiler_benchmark(mode: str = "p2cv_full", split: str = "all", provider: str | None = None) -> dict[str, Any]:
    items = json.loads(POLICY_GT.read_text(encoding="utf-8")) if POLICY_GT.exists() else []
    items = [x for x in items if split == "all" or x.get("split") == split]
    rows = []
    syntax_ok = formal_ok = graph_ok = 0
    semantic_sum = 0.0
    coverage_sum = 0.0
    critical_hits = critical_total = 0
    for item in items:
        text, expected = item["text"], item["expected"]
        if mode == "direct_dsl":
            structured = _direct_baseline(text)
            graph = {"nodes": [], "edges": [], "stats": {"nodes": 0, "edges": 0}}
            dsl = generate_dsl(structured, item["id"])
            formal = False
        elif mode == "structured_prompt":
            structured = parse_policy(text)
            graph = {"nodes": [], "edges": [], "stats": {"nodes": 0, "edges": 0}}
            dsl = generate_dsl(structured, item["id"])
            formal = False
        elif mode == "graph_ir":
            structured = parse_policy(text)
            graph = build_requirement_graph(structured)
            dsl = generate_dsl(structured, item["id"])
            formal = False
        else:
            compiled = compile_policy_v3(text, item["id"], provider=provider)
            structured = compiled["structured"]
            graph = compiled["graph"]
            dsl = compiled["dsl"]
            formal = bool(compiled["formal_verification"]["verified"])
        sem_score, field_scores = _score(structured, expected)
        verification = semantic_verify(structured, graph, dsl)
        syntax_ok += int(verification["syntax_validity"] == 1.0)
        graph_ok += int(bool(graph.get("nodes")))
        formal_ok += int(formal)
        semantic_sum += sem_score
        coverage_sum += verification["constraint_coverage"]
        critical_fields = ["action", "resource", "effect", "approval", "temporal"]
        critical_total += len(critical_fields)
        critical_hits += sum(int(field_scores.get(k, False)) for k in critical_fields)
        rows.append({"id": item["id"], "category": item["category"], "expected": expected, "actual": structured, "field_scores": field_scores, "semantic_score": round(sem_score, 4)})
    n = max(len(items), 1)
    return {
        "mode": mode,
        "split": split,
        "metrics": {
            "syntax_validity": round(syntax_ok / n, 4),
            "semantic_accuracy": round(semantic_sum / n, 4),
            "constraint_coverage": round(coverage_sum / n, 4),
            "critical_rule_recall": round(critical_hits / max(critical_total, 1), 4),
            "graph_validity": round(graph_ok / n, 4),
            "formal_pass_rate": round(formal_ok / n, 4),
        },
        "summary": {"total": len(items), "passed_semantic_85": sum(1 for r in rows if r["semantic_score"] >= .85)},
        "rows": rows,
    }


def run_compiler_ablation(split: str = "test") -> dict[str, Any]:
    series = []
    for mode in ["direct_dsl", "structured_prompt", "graph_ir", "p2cv_full"]:
        result = compiler_benchmark(mode=mode, split=split)
        series.append({"name": mode, **result["metrics"]})
    return {"split": split, "series": series}


def persist_run(kind: str, config: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    run_id = f"run_{uuid.uuid4().hex[:12]}"
    folder = RESULTS / run_id
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "config.json").write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    (folder / "metrics.json").write_text(json.dumps(result.get("metrics") or result.get("series") or result, ensure_ascii=False, indent=2), encoding="utf-8")
    rows = result.get("rows", [])
    with (folder / "raw.jsonl").open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    summary = [f"# AgentGuard V3 Experiment {run_id}", "", f"- kind: {kind}", f"- config: `{json.dumps(config, ensure_ascii=False)}`", "", "## Metrics", "", "```json", json.dumps(result.get("metrics") or result.get("series") or {}, ensure_ascii=False, indent=2), "```", ""]
    (folder / "summary.md").write_text("\n".join(summary), encoding="utf-8")
    from observability.evidence import write_bundle
    write_bundle(folder)
    return {"run_id": run_id, "kind": kind, "path": str(folder.relative_to(ROOT)), "artifacts": ["config.json", "raw.jsonl", "metrics.json", "summary.md", "evidence_manifest.json"]}


def runtime_ablation(contracts: list[dict[str, Any]], split: str = "test") -> dict[str, Any]:
    series = []
    for name, mode in [("No Guard", "no_guard"), ("Single-Step Guard", "single_step"), ("AgentGuard Full", "trajectory_full")]:
        result = evaluate_benchmark(contracts, mode=mode, split=split)
        series.append({"name": name, "mode": mode, **result["metrics"]})
    return {"split": split, "series": series, "manifest": benchmark_manifest()}


def render_comparison_svg(result: dict[str, Any]) -> tuple[str, str]:
    runtime = result.get("runtime")
    if runtime:
        title, key = "Attack Success Rate", "attack_success_rate"
        series = runtime["series"]
    elif result.get("compiler"):
        title, key = "Semantic Accuracy", "semantic_accuracy"
        series = result["compiler"]["series"]
    else:
        raise ValueError("Run has no comparison series")
    width, row_height = 640, 48
    height = 70 + len(series) * row_height
    bars = []
    for index, item in enumerate(series):
        value = max(0.0, min(1.0, float(item[key])))
        y = 52 + index * row_height
        label = escape(str(item["name"]), quote=True)
        bars.append(f'<text x="12" y="{y+16}" font-size="14">{label}</text>')
        bars.append(f'<rect x="205" y="{y}" width="{int(value*330)}" height="22" fill="#228f84"/>')
        bars.append(f'<text x="550" y="{y+16}" font-size="14">{value:.1%}</text>')
    svg=(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
         f'viewBox="0 0 {width} {height}" role="img" aria-label="{escape(title,quote=True)}">'
         f'<rect width="100%" height="100%" fill="#ffffff"/>'
         f'<text x="12" y="29" font-size="18" font-weight="bold">{escape(title)}</text>'
         f'{"".join(bars)}</svg>')
    return title, svg
