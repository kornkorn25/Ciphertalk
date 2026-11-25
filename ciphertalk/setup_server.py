"""One-time server setup.

Creates the TLS certificate and key, server_secrets.json, the auditor key pair
(private half encrypted with a passphrase, in a separate folder), and a copy of
the certificate for clients to pin.

Run:  python -m ciphertalk.setup_server --data server_data --auditor auditor_vault
"""

import argparse
import datetime
import getpass
import ipaddress
import json
import os
import shutil

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.x509.oid import NameOID

from . import crypto_utils as cu


def make_tls_cert(data_dir: str, extra_names=()) -> None:
    """ECDSA P-256 certificate valid for one year for localhost, 127.0.0.1 and
    any extra DNS names (the real server's host name in a deployment)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CipherTalk Server")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            *(x509.DNSName(n) for n in extra_names),
        ]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    with open(os.path.join(data_dir, "tls_key.pem"), "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    with open(os.path.join(data_dir, "tls_cert.pem"), "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))


def make_auditor_key(data_dir: str, auditor_dir: str, passphrase: str) -> None:
    priv = X25519PrivateKey.generate()
    with open(os.path.join(data_dir, "auditor_public.key"), "wb") as fh:
        fh.write(cu.raw_public(priv.public_key()))
    salt = os.urandom(16)
    nonce, ct = cu.aes_encrypt(cu.derive_key_from_password(passphrase, salt),
                               cu.raw_private(priv), b"ciphertalk-auditor")
    with open(os.path.join(auditor_dir, "auditor_private.json"), "w", encoding="utf-8") as fh:
        json.dump({"salt": cu.b64e(salt), "nonce": cu.b64e(nonce), "ct": cu.b64e(ct)}, fh)


def main():
    ap = argparse.ArgumentParser(description="Provision a CipherTalk server")
    ap.add_argument("--data", default="server_data")
    ap.add_argument("--auditor", default="auditor_vault")
    ap.add_argument("--san", action="append", default=[],
                    help="extra DNS name for the certificate, e.g. ciphertalk.cmkl.ac.th")
    ap.add_argument("--client-cert", default="server_cert.pem",
                    help="where to copy the certificate clients should trust")
    args = ap.parse_args()

    if os.path.exists(os.path.join(args.data, "server_secrets.json")):
        raise SystemExit("server already provisioned - refusing to overwrite keys")
    os.makedirs(args.data, exist_ok=True)
    os.makedirs(args.auditor, exist_ok=True)

    passphrase = os.environ.get("CIPHERTALK_AUDITOR_PASS") or getpass.getpass(
        "Choose the auditor passphrase (min 12 chars): ")
    if len(passphrase) < 12:
        raise SystemExit("auditor passphrase too short")

    make_tls_cert(args.data, args.san)
    secrets_cfg = {name: cu.b64e(os.urandom(32))
                   for name in ("data_key", "pseudo_key", "integrity_key")}
    with open(os.path.join(args.data, "server_secrets.json"), "w", encoding="utf-8") as fh:
        json.dump(secrets_cfg, fh, indent=2)
    make_auditor_key(args.data, args.auditor, passphrase)
    shutil.copyfile(os.path.join(args.data, "tls_cert.pem"), args.client_cert)
    # Owner-only permissions (effective on Linux/macOS; on Windows rely on NTFS ACLs).
    for name in ("tls_key.pem", "server_secrets.json"):
        os.chmod(os.path.join(args.data, name), 0o600)
    print(f"Provisioned server in '{args.data}'.")
    print(f"Auditor key stored in '{args.auditor}' - move it off the server.")
    print(f"Give clients '{args.client_cert}' so they can verify the server.")


if __name__ == "__main__":
    main()
