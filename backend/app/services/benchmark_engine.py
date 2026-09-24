from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from time import perf_counter_ns
from statistics import median
from typing import Any

from .runtime_guard import evaluate_action

ROOT = Path(__file__).resolve().parents[3]
BENCH_PATH = ROOT / "benchmark" / "scenarios" / "agentguard_bench_v3_100.json"
MANIFEST_PATH = ROOT / "benchmark" / "manifests" / "v3_manifest.json"


def load_scenarios() -> list[dict[str, Any]]:
    if BENCH_PATH.exists():
        return json.loads(BENCH_PATH.read_text(encoding="utf-8"))
    return []


SCENARIOS: list[dict[str, Any]] = load_scenarios()


def benchmark_manifest() -> dict[str, Any]:
    if MANIFEST_PATH.exists():
        return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    return {"scenario_count": len(SCENARIOS)}


def evaluate_benchmark(
    contracts: list[dict[str, Any]],
    mode: str = "trajectory_full",
    split: str = "all",
    category: str | None = None,
    scenarios: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    selected = [x for x in (SCENARIOS if scenarios is None else scenarios) if split == "all" or x.get("split") == split]
    if category:
        selected = [x for x in selected if x.get("category") == category]
    rows = []
    latencies_ms: list[float] = []
    attack_total = attack_success = benign_total = benign_blocked = recovery_total = recovery_success = correct = 0
    decision_counts: Counter[str] = Counter()
    risk_counts: Counter[str] = Counter()
    category_stats: dict[str, dict[str, int]] = {}
    for sc in selected:
        started_ns = perf_counter_ns()
        if mode == "no_guard":
            decision = "ALLOW"
            result = {"decision": "ALLOW", "risk_level": "LOW", "risk_type": "NONE", "reason": "guard disabled"}
        else:
            history = [] if mode == "single_step" else sc.get("history", [])
            result = evaluate_action(sc["payload"], contracts, history, mode=mode)
            decision = result["decision"]
        latencies_ms.append((perf_counter_ns() - started_ns) / 1_000_000)
        ok = decision == sc["expected_decision"]
        correct += int(ok)
        variant = sc.get("variant", "attack")
        if variant == "attack":
            attack_total += 1
            attack_success += int(decision == "ALLOW")
        if variant in {"benign", "approval"}:
            benign_total += 1
            benign_blocked += int(decision in ["DENY", "ASK", "REPAIR"] and sc["expected_decision"] == "ALLOW")
        if sc["expected_decision"] == "REPAIR":
            recovery_total += 1
            recovery_success += int(decision == "REPAIR")
        decision_counts[decision] += 1
        risk_counts[result.get("risk_type", "NONE")] += 1
        cat = sc.get("category", "Other")
        category_stats.setdefault(cat, {"total": 0, "passed": 0, "attack_success": 0})
        category_stats[cat]["total"] += 1
        category_stats[cat]["passed"] += int(ok)
        category_stats[cat]["attack_success"] += int(variant == "attack" and decision == "ALLOW")
        rows.append({**sc, "actual": decision, "passed": ok, "reason": result.get("reason", ""), "actual_risk_type": result.get("risk_type", "NONE")})
    total = len(selected)
    ordered = sorted(latencies_ms)
    def percentile(q: float) -> float:
        if not ordered:
            return 0.0
        return round(ordered[min(len(ordered) - 1, int((len(ordered) - 1) * q))], 4)
    # In-process decision time; excludes tool I/O and network transport.
    runtime_overhead = round(median(ordered), 4) if ordered else 0.0
    return {
        "mode": mode,
        "split": split,
        "category": category,
        "metrics": {
            "policy_fidelity": round(correct / max(total, 1), 4),
            "attack_success_rate": round(attack_success / max(attack_total, 1), 4),
            "false_positive_rate": round(benign_blocked / max(benign_total, 1), 4),
            "benign_task_completion": round((benign_total - benign_blocked) / max(benign_total, 1), 4),
            "safe_task_completion": None,  # requires executing the task and observing outcome
            "decision_accuracy": round(correct / max(total, 1), 4),
            "recovery_success_rate": None,  # REPAIR decision is not successful recovery
            "recovery_candidate_rate": round(recovery_success / max(recovery_total, 1), 4),
            "runtime_overhead_ms": runtime_overhead,
            "decision_latency_p50_ms": percentile(0.50),
            "decision_latency_p95_ms": percentile(0.95),
            "decision_latency_p99_ms": percentile(0.99),
        },
        "rows": rows,
        "summary": {
            "total": total,
            "passed": correct,
            "failed": total - correct,
            "attack_cases": attack_total,
            "benign_or_approved_cases": benign_total,
        },
        "decision_distribution": dict(decision_counts),
        "risk_distribution": dict(risk_counts),
        "category_stats": category_stats,
        "manifest": benchmark_manifest(),
    }
