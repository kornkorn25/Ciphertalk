"""All cryptographic operations used by the client, server and auditor.

Everything comes from the `cryptography` library: X25519, HKDF-SHA256,
AES-256-GCM, Ed25519, scrypt and HMAC-SHA256.
"""

import base64
import hashlib
import hmac
import json
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class CryptoError(Exception):
    """Raised whenever decryption or signature verification fails."""


# Small encoding helpers

def b64e(data: bytes) -> str:
    """Bytes -> base64 text, so binary values can travel inside JSON."""
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    """Base64 text -> bytes. validate=True rejects junk characters."""
    return base64.b64decode(text.encode("ascii"), validate=True)


def canonical_json(obj) -> bytes:
    """
    Serialise a dict the same way every time (sorted keys, no spaces).
    Signatures are computed over this form, so the sender and the receiver
    must produce byte-identical input or verification would fail randomly.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# Password hashing (server side) and password-based key derivation (client)

# scrypt cost parameters. n=2**15 took about 130-180 ms per hash on our test laptop,
# which is fine for a login but makes offline guessing of a stolen hash expensive.
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1


def hash_password(password: str, salt: bytes = None) -> tuple:
    """Return (salt, hash) for storing a password. A fresh salt per user."""
    salt = salt or os.urandom(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
        maxmem=64 * 1024 * 1024, dklen=32,
    )
    return salt, digest


def verify_password(password: str, salt: bytes, expected: bytes) -> bool:
    """Recompute the scrypt hash and compare in constant time."""
    _, digest = hash_password(password, salt)
    return hmac.compare_digest(digest, expected)


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """32-byte key used to encrypt the user's private keys on their own disk."""
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
        maxmem=64 * 1024 * 1024, dklen=32,
    )


# Symmetric authenticated encryption

def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple:
    """
    AES-256-GCM. Returns (nonce, ciphertext_with_tag).
    A random 96-bit nonce is generated every call; reusing a nonce with the
    same key would break GCM, so the caller never chooses it.
    """
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """Decrypt and check the GCM tag. Any change to ct/aad -> CryptoError."""
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise CryptoError("authentication tag mismatch - data was altered") from exc


# Key pairs

def new_identity() -> dict:
    """Create a user's two long-term key pairs (encryption + signing)."""
    return {
        "x25519": X25519PrivateKey.generate(),
        "ed25519": Ed25519PrivateKey.generate(),
    }


def raw_public(key) -> bytes:
    """Raw 32-byte encoding of an X25519 / Ed25519 public key."""
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def raw_private(key) -> bytes:
    """Raw 32-byte encoding of an X25519 / Ed25519 private key."""
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def key_fingerprint(sign_pub_raw: bytes, enc_pub_raw: bytes) -> str:
    """
    Short human-readable fingerprint of a user's public keys. Users can compare
    this out-of-band (in person, by phone) to make sure the server did not hand
    them a fake key.
    """
    digest = hashlib.sha256(sign_pub_raw + enc_pub_raw).hexdigest()[:24].upper()
    return " ".join(digest[i:i + 4] for i in range(0, len(digest), 4))


# Hybrid "sealed box": encrypt to someone's X25519 public key

def _hkdf(shared: bytes, info: bytes) -> bytes:
    # A raw X25519 output is not uniformly random, so it is never used as a
    # key directly. HKDF turns it into a proper 256-bit AES key; `info`
    # separates contexts (messages vs. escrow) so keys never cross over.
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)


def seal(recipient_enc_pub_raw: bytes, plaintext: bytes, aad: bytes, info: bytes) -> dict:
    """
    Encrypt `plaintext` so only the holder of the matching X25519 private key
    can read it. A brand new ephemeral key pair is made for every message, so
    two messages never share an AES key (forward secrecy on the sender side).
    """
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient_enc_pub_raw))
    key = _hkdf(shared, info)
    nonce, ct = aes_encrypt(key, plaintext, aad)
    return {"eph": b64e(raw_public(eph.public_key())), "nonce": b64e(nonce), "ct": b64e(ct)}


def open_sealed(recipient_enc_priv: X25519PrivateKey, box: dict, aad: bytes, info: bytes) -> bytes:
    """Reverse of seal(). Raises CryptoError if anything was tampered with."""
    try:
        eph_pub = X25519PublicKey.from_public_bytes(b64d(box["eph"]))
        shared = recipient_enc_priv.exchange(eph_pub)
    except (KeyError, ValueError) as exc:
        raise CryptoError("malformed sealed box") from exc
    key = _hkdf(shared, info)
    return aes_decrypt(key, b64d(box["nonce"]), b64d(box["ct"]), aad)


# Signatures

def sign(priv: Ed25519PrivateKey, data: bytes) -> str:
    """Ed25519 signature (deterministic, no random nonce that could leak the key)."""
    return b64e(priv.sign(data))


def verify(pub_raw: bytes, data: bytes, signature_b64: str) -> None:
    """Raise CryptoError unless `signature_b64` is valid for `data`."""
    try:
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(b64d(signature_b64), data)
    except (InvalidSignature, ValueError) as exc:
        raise CryptoError("signature check failed - sender or content is not genuine") from exc


# Keyed hashing helpers

def hmac_sha256(key: bytes, data: bytes) -> str:
    """Keyed hash: without `key` an attacker cannot recompute it, which is
    what makes row MACs, the audit chain and log pseudonyms tamper-proof."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def sha256_hex(data: bytes) -> str:
    """Unkeyed hash: only detects accidents unless it is itself signed."""
    return hashlib.sha256(data).hexdigest()
