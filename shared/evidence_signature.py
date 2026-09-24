"""Portable signing and verification for exported evidence bundles."""
from __future__ import annotations

import base64
import binascii
from hashlib import sha256
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), default=str).encode('utf-8')


def verify_trace_evidence(bundle: dict) -> bool:
    return isinstance(bundle,dict) and isinstance(bundle.get('content'),dict) and bundle.get('sha256')==sha256(canonical(bundle['content'])).hexdigest()


def sign_trace_evidence(bundle: dict, private_key_pem: bytes) -> dict:
    if not verify_trace_evidence(bundle):
        raise ValueError('Evidence content digest is invalid')
    if bundle['content'].get('audit_chain_verification',{}).get('valid') is not True:
        raise ValueError('Audit chain must verify before signing')
    if 'signature' in bundle:
        raise ValueError('Evidence bundle is already signed')
    key=serialization.load_pem_private_key(private_key_pem,password=None)
    if not isinstance(key,Ed25519PrivateKey):
        raise ValueError('Evidence key must be Ed25519')
    public=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    signature=key.sign(canonical(bundle))
    bundle['signature']={'algorithm':'Ed25519','key_id':sha256(public).hexdigest(),
                         'value':base64.b64encode(signature).decode('ascii')}
    return bundle


def verify_signed_trace_evidence(bundle: dict, trusted_public_key_pem: bytes) -> bool:
    if not verify_trace_evidence(bundle):
        return False
    signature=bundle.get('signature')
    if not isinstance(signature,dict) or signature.get('algorithm')!='Ed25519':
        return False
    try:
        key=serialization.load_pem_public_key(trusted_public_key_pem)
        if not isinstance(key,Ed25519PublicKey):
            return False
        public=key.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        if signature.get('key_id')!=sha256(public).hexdigest():
            return False
        signed={k:v for k,v in bundle.items() if k!='signature'}
        key.verify(base64.b64decode(signature['value'],validate=True),canonical(signed))
        return signed['content'].get('audit_chain_verification',{}).get('valid') is True
    except (InvalidSignature,binascii.Error,ValueError,KeyError,TypeError):
        return False
