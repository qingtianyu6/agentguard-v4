"""Upgrade V3 synthetic refund fixtures to order-bound completed events."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = ROOT / 'benchmark/scenarios/agentguard_bench_v3_100.json'
MANIFEST = ROOT / 'benchmark/manifests/v3_manifest.json'


def main() -> None:
    cases = json.loads(SCENARIOS.read_text(encoding='utf-8'))
    changed = 0
    for case in cases:
        if case.get('category') != 'Temporal Constraint Violation':
            continue
        payload = case['payload']
        order_id = payload['resource'].removeprefix('order:')
        payload.setdefault('args', {})['order_id'] = order_id
        for event in case.get('history', []):
            action = event['action']
            if action not in {'identity_verified', 'order_confirmed'}:
                continue
            event['state'] = 'completed'
            event['agent_id'] = payload['agent_id']
            event['tool_id'] = 'mcp.order.identity' if action == 'identity_verified' else 'mcp.order.verify'
            event['result'] = {'ok': True, action: True, 'order_id': order_id}
            if action == 'order_confirmed':
                event['result']['status'] = 'PAID'
        case['evidence'] = 'order-bound synthetic fixture; labels pending independent human review'
        changed += 1
    if changed != 12:
        raise ValueError(f'Expected 12 temporal cases, found {changed}')
    scenario_bytes = (json.dumps(cases, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
    manifest['scenario_sha256'] = sha256(scenario_bytes).hexdigest()
    manifest['label_process'] = 'template-generated + order-bound synthetic events + regression tests; independent human review required'
    SCENARIOS.write_bytes(scenario_bytes)
    MANIFEST.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
