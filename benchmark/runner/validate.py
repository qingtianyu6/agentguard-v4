"""Curated scenario gate; checks provenance and independent annotation claims."""
from __future__ import annotations
from collections import Counter, defaultdict
from hashlib import sha256
import json
from pathlib import Path
from jsonschema import Draft202012Validator

SCHEMA=json.loads((Path(__file__).resolve().parents[1]/'spec'/'scenario.schema.json').read_text())
VALIDATOR=Draft202012Validator(SCHEMA)


def validate_curated(cases: list[dict]) -> dict:
    errors=[]; ids=set(); family_splits=defaultdict(set); exact=Counter()
    for index, case in enumerate(cases):
        issues=sorted(VALIDATOR.iter_errors(case),key=lambda e: list(map(str,e.path)))
        for issue in issues: errors.append({'index':index,'reason':'SCHEMA','detail':issue.message})
        if issues: continue
        if case['id'] in ids: errors.append({'index':index,'reason':'DUPLICATE_ID'})
        ids.add(case['id'])
        reviews=case['reviews']
        if len({r['reviewer_id'] for r in reviews})<2:
            errors.append({'index':index,'reason':'REVIEWERS_NOT_INDEPENDENT'})
        if any(r['decision']!=case['expected_decision'] for r in reviews):
            errors.append({'index':index,'reason':'REVIEW_DISAGREEMENT_REQUIRES_ADJUDICATION'})
        family_splits[case['template_family']].add(case['split'])
        digest=sha256(json.dumps({'task':case['task'],'policy':case['policy'],'payload':case['payload'],
                                  'history':case['history']},sort_keys=True,ensure_ascii=False).encode()).hexdigest()
        exact[digest]+=1
    for family,splits in family_splits.items():
        if len(splits)>1: errors.append({'family':family,'reason':'SPLIT_LEAKAGE'})
    duplicate=sum(n-1 for n in exact.values())
    if duplicate: errors.append({'reason':'DUPLICATE_CONTENT','count':duplicate})
    return {'valid':not errors,'count':len(cases),'distinct_families':len(family_splits),
            'unique_template_ratio':round(len(family_splits)/len(cases),4) if cases else None,
            'errors':errors,'variant_counts':dict(Counter(x.get('variant') for x in cases)),
            'scope':'structural and annotation-process gate; not proof of human reviewer identity'}
