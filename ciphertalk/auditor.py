"""Offline auditor tool.

  verify-log   check the audit log hash chain
  reveal       open the identity escrow of one board post (needs the auditor
               passphrase and a written reason; the reveal is logged)

Run:
  python -m ciphertalk.auditor verify-log
  python -m ciphertalk.auditor reveal <post_id> --reason "..."
"""

import argparse
import getpass
import json
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import crypto_utils as cu
from .store import Store

ESCROW_INFO = b"ciphertalk-escrow-v1"
MIN_REASON_LEN = 15


def load_store(data_dir: str) -> Store:
    with open(os.path.join(data_dir, "server_secrets.json"), encoding="utf-8") as fh:
        return Store(os.path.join(data_dir, "ciphertalk.db"), json.load(fh))


def load_auditor_key(path: str, passphrase: str) -> X25519PrivateKey:
    with open(path, encoding="utf-8") as fh:
        blob = json.load(fh)
    key = cu.derive_key_from_password(passphrase, cu.b64d(blob["salt"]))
    raw = cu.aes_decrypt(key, cu.b64d(blob["nonce"]), cu.b64d(blob["ct"]), b"ciphertalk-auditor")
    return X25519PrivateKey.from_private_bytes(raw)


def cmd_verify(args):
    ok, msg = load_store(args.data).verify_audit_chain()
    print(("OK: " if ok else "TAMPERING DETECTED: ") + msg)
    return 0 if ok else 1


def cmd_reveal(args):
    if len(args.reason.strip()) < MIN_REASON_LEN:
        print(f"Refused: a reason of at least {MIN_REASON_LEN} characters is required.")
        return 2
    store = load_store(args.data)
    escrow = store.get_post_escrow(args.post_id)
    if escrow is None:
        print("No such post.")
        return 1
    passphrase = os.environ.get("CIPHERTALK_AUDITOR_PASS") or getpass.getpass("Auditor passphrase: ")
    try:
        priv = load_auditor_key(args.key, passphrase)
    except cu.CryptoError:
        print("Wrong auditor passphrase.")
        return 1
    plain = cu.open_sealed(priv, escrow, args.post_id.encode(), ESCROW_INFO)
    info = json.loads(plain)
    # Record the reveal BEFORE showing the result.
    with store.lock:
        store.audit("auditor", "IDENTITY_REVEALED",
                    f"post={args.post_id} reason={args.reason.strip()[:200]}")
        store.db.commit()
    print(f"Post {args.post_id} was written by: {info['author']}")
    print("This reveal has been recorded in the audit log.")
    return 0


def main():
    ap = argparse.ArgumentParser(description="CipherTalk auditor tool")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify-log")
    v.add_argument("--data", default="server_data")
    r = sub.add_parser("reveal")
    r.add_argument("post_id")
    r.add_argument("--reason", required=True)
    r.add_argument("--data", default="server_data")
    r.add_argument("--key", default=os.path.join("auditor_vault", "auditor_private.json"))
    args = ap.parse_args()
    raise SystemExit(cmd_verify(args) if args.cmd == "verify-log" else cmd_reveal(args))


if __name__ == "__main__":
    main()
