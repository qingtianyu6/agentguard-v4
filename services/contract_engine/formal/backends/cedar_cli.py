"""Cedar authorization backend for a documented subset of AgentGuard IR."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from typing import Any

class UnsupportedContract(ValueError):
    pass


def compile_authorization_subset(contract: dict[str, Any]) -> tuple[str, str]:
    action = contract.get('action')
    if action not in {'send', 'refund', 'read'}:
        raise UnsupportedContract(f'unsupported Cedar action: {action!r}')
    if contract.get('temporal_constraints'):
        raise UnsupportedContract('temporal constraints are handled by trajectory engine')
    if contract.get('resource') not in {'AnyResource', 'SensitiveData', 'Order', 'File'}:
        raise UnsupportedContract('resource predicate is outside Cedar subset')
    effect = contract.get('effect')
    approved = bool(contract.get('exception') == 'manager_approval' or
                    any(c.get('field') == 'manager_approval' for c in contract.get('conditions', [])))
    if effect not in {'DENY','DENY_UNLESS','ALLOW','REQUIRE'}:
        raise UnsupportedContract(f'unsupported effect: {effect!r}')
    scope = f'AgentGuard::Action::"{action}"'
    schema = f'''namespace AgentGuard {{
  entity Agent;
  entity Resource;
  action "{action}" appliesTo {{ principal: Agent, resource: Resource, context: {{ approved: Bool }} }};
}}
'''
    if effect == 'DENY' and not approved:
        policy = f'forbid(principal, action == {scope}, resource);\n'
    elif approved:
        policy = f'permit(principal, action == {scope}, resource);\nforbid(principal, action == {scope}, resource) when {{ !context.approved }};\n'
    else:
        policy = f'permit(principal, action == {scope}, resource);\n'
    return schema, policy


def evaluate(contract: dict[str, Any], *, approved: bool, binary: str | None = None) -> dict[str, Any]:
    executable = binary or os.environ.get('AGENTGUARD_CEDAR_CLI')
    if not executable or not Path(executable).is_file():
        return {'available': False, 'decision': 'UNVERIFIED', 'reason': 'CEDAR_BINARY_MISSING'}
    schema, policy = compile_authorization_subset(contract)
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root/'schema.cedarschema').write_text(schema)
        (root/'policy.cedar').write_text(policy)
        (root/'entities.json').write_text('[]')
        (root/'context.json').write_text(json.dumps({'approved': approved}))
        validate = subprocess.run([executable, 'validate','--schema',str(root/'schema.cedarschema'),
            '--policies',str(root/'policy.cedar'),'-f','plain'], capture_output=True,text=True,timeout=10)
        if validate.returncode != 0:
            return {'available': True,'decision':'UNVERIFIED','reason':'SCHEMA_VALIDATION_FAILED','details':validate.stdout+validate.stderr}
        cmd = [executable,'authorize','--schema',str(root/'schema.cedarschema'),
            '--policies',str(root/'policy.cedar'),'--entities',str(root/'entities.json'),
            '--principal','AgentGuard::Agent::"agent"','--action',f'AgentGuard::Action::"{contract["action"]}"',
            '--resource','AgentGuard::Resource::"resource"','--context',str(root/'context.json'),'-f','plain']
        decision = subprocess.run(cmd,capture_output=True,text=True,timeout=10)
        out = decision.stdout.strip()
        if out not in {'ALLOW','DENY'}:
            return {'available': True,'decision':'UNVERIFIED','reason':'CEDAR_EXECUTION_FAILED','details':out+decision.stderr}
        return {'available': True,'decision':out,'backend':'cedar-cli','scope':'authorization subset only'}
