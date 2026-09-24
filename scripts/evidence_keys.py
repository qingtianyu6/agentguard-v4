"""Generate an evidence signing key or verify an exported bundle offline."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from shared.evidence_signature import verify_signed_trace_evidence


def create_exclusive(path: Path, data: bytes) -> None:
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as output:
        output.write(data)


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    keygen=commands.add_parser('keygen')
    keygen.add_argument('--private',required=True,type=Path)
    keygen.add_argument('--public',required=True,type=Path)
    verify=commands.add_parser('verify')
    verify.add_argument('bundle',type=Path)
    verify.add_argument('trusted_public_key',type=Path)
    args=parser.parse_args()
    if args.command=='keygen':
        if args.private.resolve()==args.public.resolve() or args.private.exists() or args.public.exists():
            parser.error('Key paths must differ and must not already exist')
        key=Ed25519PrivateKey.generate()
        private=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())
        public=key.public_key().public_bytes(serialization.Encoding.PEM,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
        create_exclusive(args.private,private)
        create_exclusive(args.public,public)
        print('Created evidence key pair; keep the private key outside the repository')
        return 0
    try:
        bundle=json.loads(args.bundle.read_text(encoding='utf-8'))
        if isinstance(bundle,dict) and 'content' not in bundle and isinstance(bundle.get('data'),dict):
            bundle=bundle['data']
        valid=verify_signed_trace_evidence(bundle,args.trusted_public_key.read_bytes())
    except (OSError,ValueError,TypeError):
        valid=False
    print('VALID' if valid else 'INVALID')
    return 0 if valid else 1


if __name__=='__main__':
    raise SystemExit(main())
