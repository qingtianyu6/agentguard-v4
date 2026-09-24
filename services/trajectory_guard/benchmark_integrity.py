"""Benchmark integrity checks before making external-validity claims."""
from __future__ import annotations
from collections import Counter, defaultdict
from hashlib import sha256
import json


def integrity_report(cases: list[dict]) -> dict:
    groups: dict[str, set[str]] = defaultdict(set)
    exact = Counter()
    for item in cases:
        canonical = json.dumps({'policy': item.get('policy'), 'payload': item.get('payload'),
                                'history': item.get('history')}, sort_keys=True, ensure_ascii=False)
        exact[sha256(canonical.encode()).hexdigest()] += 1
        family = str(item.get('task_family') or item.get('template_id') or item.get('group_id') or '')
        if family:
            groups[family].add(str(item.get('split', 'unknown')))
    leak_groups = {g: sorted(splits) for g, splits in groups.items() if len(splits & {'train','dev','test'}) > 1}
    return {'cases': len(cases), 'unique_exact': len(exact), 'duplicate_cases': sum(n-1 for n in exact.values()),
            'group_leakage': leak_groups, 'has_group_ids': len(groups) > 0,
            'status': 'cannot_certify_split_integrity' if not groups else ('leakage_detected' if leak_groups else 'group_disjoint')}
