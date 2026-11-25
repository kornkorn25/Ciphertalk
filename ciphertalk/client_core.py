"""Client logic without the user interface.

Key generation and encrypted key storage, key pinning, building and checking
envelopes, and the calls to the server. client.py and the tests both use it.
"""

import json
import os
import socket
import ssl
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import crypto_utils as cu
from . import protocol as p

DM_INFO = b"ciphertalk-dm-v1"
SEEN_LIMIT = 5000


class ClientError(Exception):
    """Anything the user should be told about in plain words."""


class KeyChangedError(ClientError):
    """The server returned different keys for a contact we already pinned."""


class ClientCore:
    def __init__(self, host="127.0.0.1", port=5443, cafile="server_cert.pem",
                 home=".ciphertalk"):
        self.host, self.port, self.cafile, self.home = host, port, cafile, home
        self.sock = None
        self.username = None
        self.token = None
        self.keys = None           # {"x25519": priv, "ed25519": priv}

    def connect(self):
        """Open a TLS 1.3 connection and verify the server's certificate."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(self.cafile)       # trust ONLY our server cert
        raw = socket.create_connection((self.host, self.port), timeout=15)
        try:
            # The name we dialled must appear in the certificate's SAN list
            # (setup_server --san adds the VM's DNS name for real deployments).
            self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        except ssl.SSLError as exc:
            raw.close()
            raise ClientError(f"could not verify the server ({exc.reason}) - "
                              "connection refused for your safety") from exc
        return self.request({"action": "hello"})

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def request(self, obj: dict) -> dict:
        if not self.sock:
            raise ClientError("not connected")
        if self.token and "token" not in obj:
            obj = dict(obj, token=self.token)
        p.send_frame(self.sock, obj)
        return p.recv_frame(self.sock)

    def _ok(self, resp: dict) -> dict:
        if not resp.get("ok"):
            raise ClientError(resp.get("error", "request failed"))
        return resp

    def _user_dir(self, username=None) -> str:
        d = os.path.join(self.home, username or self.username)
        os.makedirs(d, exist_ok=True)
        return d

    def _save_identity(self, username, password, keys):
        salt = os.urandom(16)
        secret = cu.canonical_json({"x25519": cu.b64e(cu.raw_private(keys["x25519"])),
                                    "ed25519": cu.b64e(cu.raw_private(keys["ed25519"]))})
        nonce, ct = cu.aes_encrypt(cu.derive_key_from_password(password, salt), secret,
                                   username.encode())
        path = os.path.join(self._user_dir(username), "identity.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"salt": cu.b64e(salt), "nonce": cu.b64e(nonce), "ct": cu.b64e(ct)}, fh)

    def _load_identity(self, username, password) -> dict:
        path = os.path.join(self.home, username, "identity.json")
        if not os.path.exists(path):
            raise ClientError("no keys for that account on this device")
        with open(path, encoding="utf-8") as fh:
            blob = json.load(fh)
        key = cu.derive_key_from_password(password, cu.b64d(blob["salt"]))
        try:
            secret = json.loads(cu.aes_decrypt(key, cu.b64d(blob["nonce"]),
                                               cu.b64d(blob["ct"]), username.encode()))
        except cu.CryptoError as exc:
            raise ClientError("invalid username or password") from exc
        return {"x25519": X25519PrivateKey.from_private_bytes(cu.b64d(secret["x25519"])),
                "ed25519": Ed25519PrivateKey.from_private_bytes(cu.b64d(secret["ed25519"]))}

    def _load_json(self, name, default):
        path = os.path.join(self._user_dir(), name)
        if not os.path.exists(path):
            return default
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    def _save_json(self, name, value):
        with open(os.path.join(self._user_dir(), name), "w", encoding="utf-8") as fh:
            json.dump(value, fh, indent=1)

    def register(self, username, password, email="", consent=False):
        p.check_username(username)
        p.check_password(password)
        p.check_email(email)
        if not consent:
            raise ClientError("you need to accept the privacy notice to register")
        hello = self.request({"action": "hello"})
        keys = cu.new_identity()
        sign_pub = cu.b64e(cu.raw_public(keys["ed25519"].public_key()))
        enc_pub = cu.b64e(cu.raw_public(keys["x25519"].public_key()))
        bundle_sig = cu.sign(keys["ed25519"], cu.canonical_json(
            {"username": username, "sign_pub": sign_pub, "enc_pub": enc_pub}))
        self._ok(self.request({
            "action": "register", "username": username, "password": password,
            "email": email, "consent": True, "consent_version": hello["consent_version"],
            "sign_pub": sign_pub, "enc_pub": enc_pub, "bundle_sig": bundle_sig}))
        # Only keep the keys once the server has accepted the account.
        self._save_identity(username, password, keys)

    def login(self, username, password):
        p.check_username(username)
        if not os.path.exists(os.path.join(self.home, username, "identity.json")):
            raise ClientError("no keys for that account on this device")
        # Ask the server first so every wrong guess counts towards the
        # server-side lockout, then unlock the local private keys.
        resp = self._ok(self.request({"action": "login", "username": username,
                                      "password": password}))
        self.token = resp["token"]
        try:
            self.keys = self._load_identity(username, password)
        except ClientError:
            self.request({"action": "logout"})
            self.token = None
            raise
        self.username = username

    def logout(self):
        if self.token:
            self.request({"action": "logout"})
        self.username = self.token = self.keys = None

    def _need_login(self):
        if not self.token:
            raise ClientError("please log in first")

    def contact_keys(self, username) -> dict:
        """Fetch a contact's keys and enforce trust-on-first-use pinning."""
        self._need_login()
        resp = self._ok(self.request({"action": "get_keys", "username": username}))
        pins = self._load_json("pinned_keys.json", {})
        fresh = {"sign_pub": resp["sign_pub"], "enc_pub": resp["enc_pub"]}
        if username in pins and pins[username] != fresh:
            raise KeyChangedError(
                f"WARNING: {username}'s keys have changed since you last talked. "
                "This could be a man-in-the-middle attack. Message NOT sent/accepted.")
        if username not in pins:
            pins[username] = fresh
            self._save_json("pinned_keys.json", pins)
        return {"sign_pub": cu.b64d(fresh["sign_pub"]), "enc_pub": cu.b64d(fresh["enc_pub"])}

    def fingerprint(self, username=None) -> str:
        self._need_login()
        if username in (None, self.username):
            return cu.key_fingerprint(cu.raw_public(self.keys["ed25519"].public_key()),
                                      cu.raw_public(self.keys["x25519"].public_key()))
        k = self.contact_keys(username)
        return cu.key_fingerprint(k["sign_pub"], k["enc_pub"])

    def _build_envelope(self, recipient, kind, payload: dict) -> dict:
        keys = self.contact_keys(recipient)
        header = {"msg_id": uuid.uuid4().hex, "kind": kind, "sender": self.username,
                  "recipient": recipient, "sent_at": int(time.time())}
        # The header is used as AAD: it travels in clear (the server needs it
        # for routing) but any change to it makes decryption fail.
        box = cu.seal(keys["enc_pub"], cu.canonical_json(payload),
                      cu.canonical_json(header), DM_INFO)
        sig = cu.sign(self.keys["ed25519"], cu.canonical_json({"header": header, "box": box}))
        return {"header": header, "box": box, "sig": sig}

    def send_text(self, recipient, text) -> str:
        self._need_login()
        p.check_username(recipient)
        env = self._build_envelope(recipient, "text", {"text": p.check_text(text)})
        return self._ok(self.request({"action": "send", "envelope": env}))["msg_id"]

    def send_file(self, recipient, path) -> str:
        self._need_login()
        p.check_username(recipient)
        name = p.check_filename(os.path.basename(path))
        if not os.path.isfile(path):
            raise ClientError("file not found")
        if os.path.getsize(path) > p.MAX_FILE_BYTES:
            raise ClientError(f"file is larger than {p.MAX_FILE_BYTES // 1024} KB")
        with open(path, "rb") as fh:
            data = fh.read()
        payload = {"filename": name, "data": cu.b64e(data), "sha256": cu.sha256_hex(data)}
        env = self._build_envelope(recipient, "file", payload)
        return self._ok(self.request({"action": "send", "envelope": env}))["msg_id"]

    def _open_envelope(self, env: dict, seen: set) -> dict:
        """All the receive-side checks. Returns a display dict or raises."""
        hdr, box, sig = env.get("header"), env.get("box"), env.get("sig")
        if not isinstance(hdr, dict) or not isinstance(box, dict):
            raise ClientError("malformed message")
        p.check_msg_id(hdr.get("msg_id"))
        if hdr.get("recipient") != self.username:
            raise ClientError("message was addressed to someone else")
        if hdr["msg_id"] in seen:
            raise ClientError("this message was already received once (replay)")
        sender = p.check_username(hdr.get("sender"))
        keys = self.contact_keys(sender)
        cu.verify(keys["sign_pub"], cu.canonical_json({"header": hdr, "box": box}), sig or "")
        payload = json.loads(cu.open_sealed(self.keys["x25519"], box,
                                            cu.canonical_json(hdr), DM_INFO))
        out = {"msg_id": hdr["msg_id"], "from": sender, "kind": hdr["kind"],
               "sent_at": hdr["sent_at"]}
        if hdr["kind"] == "text":
            out["text"] = p.check_text(payload["text"])
        else:
            data = cu.b64d(payload["data"])
            if cu.sha256_hex(data) != payload["sha256"]:
                raise ClientError("file hash does not match - file corrupted")
            name = p.check_filename(payload["filename"])
            folder = os.path.join(self._user_dir(), "downloads")
            os.makedirs(folder, exist_ok=True)
            target = os.path.join(folder, name)
            n = 1
            while os.path.exists(target):          # never overwrite a file
                stem, ext = os.path.splitext(name)
                target = os.path.join(folder, f"{stem} ({n}){ext}")
                n += 1
            with open(target, "wb") as fh:
                fh.write(data)
            out.update(filename=name, saved_to=target, size=len(data),
                       sha256=payload["sha256"])
        return out

    def fetch_inbox(self) -> list:
        """Download, verify and decrypt pending messages, then ack them."""
        self._need_login()
        results = []
        # The server sends the inbox in pages that fit in one frame; keep
        # fetching (and acking) until it says there is nothing more.
        for _ in range(100):
            resp = self._ok(self.request({"action": "fetch"}))
            results.extend(self._process_page(resp["messages"]))
            if not resp.get("more") or not resp["messages"]:
                break
        return results

    def _process_page(self, envs) -> list:
        seen_list = self._load_json("seen_ids.json", [])
        seen = set(seen_list)
        results, acks = [], []
        for env in envs:
            mid = (env.get("header") or {}).get("msg_id")
            try:
                msg = self._open_envelope(env, seen)
                msg["status"] = "verified"
                seen.add(msg["msg_id"])
                seen_list.append(msg["msg_id"])
            except (ClientError, cu.CryptoError, p.ProtocolError,
                    KeyError, ValueError, TypeError) as exc:
                sender = (env.get("header") or {}).get("sender")   # untrusted: shown only if valid
                msg = {"status": "rejected", "reason": str(exc), "msg_id": mid,
                       "from": sender if isinstance(sender, str) and p.USERNAME_RE.match(sender) else "?"}
            results.append(msg)
            if isinstance(mid, str) and p.HEX32_RE.match(mid):
                acks.append(mid)
        self._save_json("seen_ids.json", seen_list[-SEEN_LIMIT:])
        if acks:
            self.request({"action": "ack", "msg_ids": acks})
        return results

    def board_post(self, text) -> dict:
        self._need_login()
        return self._ok(self.request({"action": "board_post", "body": p.check_text(text)}))

    def board_list(self) -> list:
        self._need_login()
        posts = self._ok(self.request({"action": "board_list"}))["posts"]
        for post in posts:
            # Never trust text from the server: strip control and bidi
            # characters again before anything reaches the terminal.
            # A post the server cannot vouch for is flagged, never allowed to
            # break the whole board listing.
            try:
                post["body"] = p.check_text(post.get("body"))
                post["alias"] = p.check_text(post.get("alias"))
            except p.ProtocolError:
                post.update(body="(unreadable post)", alias="?", intact=False)
        return posts

    def export_data(self) -> dict:
        self._need_login()
        return self._ok(self.request({"action": "export_data"}))["data"]

    def delete_account(self, password):
        self._need_login()
        self._ok(self.request({"action": "delete_account", "password": password}))
        # Wipe local keys and history too - erasure on both ends.
        folder = self._user_dir()
        for root, _, files in os.walk(folder, topdown=False):
            for f in files:
                os.remove(os.path.join(root, f))
            os.rmdir(root)
        self.username = self.token = self.keys = None
