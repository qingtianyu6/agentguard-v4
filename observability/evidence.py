"""Reproducible run bundle manifest with integrity digests."""
from __future__ import annotations
from hashlib import sha256
from pathlib import Path
import json
import platform
import sys
from datetime import datetime, timezone


def write_bundle(run_dir: Path, *, policy_version: str | None = None, tool_fingerprints: dict | None = None) -> Path:
    run_dir = Path(run_dir)
    files = ['config.json', 'raw.jsonl', 'metrics.json', 'summary.md']
    if not all((run_dir / name).is_file() for name in files):
        raise ValueError('INCOMPLETE_RUN_ARTIFACTS')
    manifest = {
        'schema': 'agentguard.evidence/1', 'run_id': run_dir.name,
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'python': sys.version.split()[0], 'platform': platform.platform(),
        'policy_version': policy_version, 'tool_fingerprints': tool_fingerprints or {},
        'sha256': {name: sha256((run_dir / name).read_bytes()).hexdigest() for name in files},
    }
    target = run_dir / 'evidence_manifest.json'
    target.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding='utf-8')
    return target


def verify_bundle(run_dir: Path) -> bool:
    run_dir = Path(run_dir)
    manifest = json.loads((run_dir / 'evidence_manifest.json').read_text(encoding='utf-8'))
    return all((run_dir / name).is_file() and sha256((run_dir / name).read_bytes()).hexdigest() == digest
               for name, digest in manifest['sha256'].items())
