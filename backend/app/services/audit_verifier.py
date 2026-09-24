"""Check the append-only hash chain already emitted by the V3 audit writer.

This detects accidental or unsynchronized modification, but is not a signature
and does not protect against an actor who can rewrite all rows and hashes.
"""
from __future__ import annotations
from hashlib import sha256
import json
from typing import Any


def verify_chain(events: list[Any]) -> dict:
    previous='GENESIS'
    for index, event in enumerate(events):
        if event.prev_hash != previous:
            return {'valid': False, 'checked': index, 'broken_event_id': event.event_id, 'reason': 'PREVIOUS_HASH_MISMATCH'}
        if event.hash.startswith('v2:'):
            authenticated=json.dumps({'trace_id':event.trace_id,'event_type':event.event_type,
                                      'payload':event.payload_json},sort_keys=True,
                                      ensure_ascii=False,separators=(',',':'))
            expected='v2:'+sha256((previous+authenticated).encode()).hexdigest()
        else:
            # Preserve verification of rows emitted by the V3 payload-only writer.
            expected=sha256((previous+event.payload_json).encode()).hexdigest()
        if event.hash != expected:
            return {'valid': False, 'checked': index, 'broken_event_id': event.event_id, 'reason': 'PAYLOAD_HASH_MISMATCH'}
        previous=event.hash
    return {'valid': True, 'checked': len(events), 'head': previous,
            'scope': 'v2 covers trace, event type and payload; legacy rows cover payload only; no signature'}
