"""Compatibility facade for the stable API surface.

V3 keeps legacy API names while routing the full compile operation to the V3
research pipeline. Individual V2 primitives remain importable for ablations.
"""
from .services.p2cv import (
    parse_policy,
    build_requirement_graph as build_graph,
    generate_dsl,
    semantic_repair,
    generate_counterexamples,
    semantic_verify,
)
from .services.p2cv_v3 import compile_policy_v3 as compile_policy
from .services.runtime_guard import evaluate_action, safe_recovery, is_sensitive

__all__ = [
    "parse_policy", "build_graph", "generate_dsl", "compile_policy",
    "semantic_repair", "generate_counterexamples", "semantic_verify",
    "evaluate_action", "safe_recovery", "is_sensitive",
]
