"""CipherTalk relay server (TLS 1.3 only).

Handles registration, login, key lookup, storing encrypted messages until they
are fetched, the anonymous board, and data export/deletion. It never sees
message plaintext.

Run:  python -m ciphertalk.server --data server_data
"""

import argparse
import json
import os
import secrets
import socketserver
import ssl
import threading
import time
import uuid
from collections import defaultdict, deque

from . import crypto_utils as cu
from . import protocol as p
from .store import Store

SESSION_TTL = 30 * 60              # a login token lasts 30 minutes
MAX_LOGIN_ATTEMPTS = 5             # then the account is locked ...
LOCK_SECONDS = 5 * 60              # ... for 5 minutes
RATE_WINDOW = 10                   # each connection may send at most
RATE_MAX_REQUESTS = 30             # 30 requests per 10 seconds
IP_FAIL_WINDOW = 60                # and each IP at most 10 failed
IP_FAIL_MAX = 10                   # logins per minute (credential stuffing)
FETCH_PAGE_BYTES = 1_500_000       # one inbox page stays under MAX_FRAME
CONSENT_VERSION = "privacy-notice-v1.0"
DM_INFO = b"ciphertalk-dm-v1"
ESCROW_INFO = b"ciphertalk-escrow-v1"


def log(msg: str) -> None:
    """Console log. Callers pass pseudonyms only - never usernames or content."""
    print(time.strftime("[%H:%M:%S]"), msg, flush=True)


class CipherTalkServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, data_dir: str):
        with open(os.path.join(data_dir, "server_secrets.json"), encoding="utf-8") as fh:
            secrets_cfg = json.load(fh)
        with open(os.path.join(data_dir, "auditor_public.key"), "rb") as fh:
            self.auditor_pub = fh.read()
        self.store = Store(os.path.join(data_dir, "ciphertalk.db"), secrets_cfg)

        # TLS 1.3 only. Older versions are refused outright.
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.minimum_version = ssl.TLSVersion.TLSv1_3
        self.tls.load_cert_chain(os.path.join(data_dir, "tls_cert.pem"),
                                 os.path.join(data_dir, "tls_key.pem"))

        self.ip_failures = defaultdict(deque)
        self.ip_lock = threading.Lock()
        # One lock per username, held across "is it locked? -> check password ->
        # record result". Without it, 30 parallel guesses all pass the check
        # before any failure is recorded (a check-then-act race).
        self.user_locks = defaultdict(threading.Lock)
        self.user_locks_guard = threading.Lock()
        super().__init__(addr, Handler)

    def user_lock(self, username: str) -> threading.Lock:
        with self.user_locks_guard:
            return self.user_locks[username]

    # Wrap each accepted TCP socket in TLS. The handshake itself runs in the
    # connection's own thread (Handler.setup) so one slow client cannot stall
    # the accept loop for everyone else.
    def get_request(self):
        raw, addr = self.socket.accept()
        raw.settimeout(120)
        return self.tls.wrap_socket(raw, server_side=True,
                                    do_handshake_on_connect=False), addr

    def handle_error(self, request, client_address):
        # A failed TLS handshake or a dropped client is not a crash, but we
        # still record that it happened (no client details, no stack trace).
        log("connection closed with an error during setup or handling")

    def ip_reserve(self, ip: str):
        """
        Atomically check the IP's failure budget AND reserve one attempt.
        Returns a reservation stamp, or None if the IP is blocked. The stamp
        counts as a failure until release() is called after a correct
        password, so parallel guesses cannot all slip under the limit.
        """
        with self.ip_lock:
            q = self.ip_failures[ip]
            while q and q[0] < time.time() - IP_FAIL_WINDOW:
                q.popleft()
            if len(q) >= IP_FAIL_MAX:
                return None
            stamp = time.time()
            q.append(stamp)
            return stamp

    def ip_release(self, ip: str, stamp: float) -> None:
        with self.ip_lock:
            try:
                self.ip_failures[ip].remove(stamp)
            except ValueError:
                pass


class Handler(socketserver.BaseRequestHandler):
    """One instance per client connection."""

    def setup(self):
        self.request.do_handshake()   # fails here if the client isn't TLS 1.3
        self.store: Store = self.server.store
        self.user = None           # username once logged in
        self.token = None
        self.recent = deque()      # request timestamps for rate limiting

    def handle(self):
        while True:
            try:
                req = p.recv_frame(self.request)
            except (ConnectionError, OSError, ssl.SSLError):
                return
            except p.ProtocolError as exc:
                self._reply({"ok": False, "error": str(exc)})
                return             # malformed framing -> drop the connection
            if not self._rate_ok():
                self._reply({"ok": False, "error": "too many requests - slow down"})
                continue
            action = req.get("action")
            fn = getattr(self, "do_" + action, None) if isinstance(action, str) else None
            if fn is None:
                self._reply({"ok": False, "error": "unknown action"})
                continue
            try:
                self._reply(fn(req))
            except p.ProtocolError as exc:
                self._reply({"ok": False, "error": str(exc)})
            except cu.CryptoError as exc:
                self._reply({"ok": False, "error": str(exc)})
            except Exception:      # never leak a stack trace to the client
                log("internal error while handling " + str(action))
                self._reply({"ok": False, "error": "internal server error"})

    def _reply(self, obj):
        try:
            p.send_frame(self.request, obj)
        except (OSError, ssl.SSLError):
            pass

    def _rate_ok(self) -> bool:
        now = time.time()
        while self.recent and self.recent[0] < now - RATE_WINDOW:
            self.recent.popleft()
        self.recent.append(now)
        return len(self.recent) <= RATE_MAX_REQUESTS

    def _require_login(self, req) -> str:
        user = self.store.session_user(req.get("token"))
        if not user:
            raise p.ProtocolError("not logged in or session expired")
        return user

    def do_hello(self, req):
        return {"ok": True, "server": "CipherTalk", "protocol": p.PROTOCOL_VERSION,
                "consent_version": CONSENT_VERSION}

    def do_register(self, req):
        username = p.check_username(req.get("username"))
        password = p.check_password(req.get("password"))
        email = p.check_email(req.get("email"))
        if req.get("consent") is not True or req.get("consent_version") != CONSENT_VERSION:
            raise p.ProtocolError("you must accept the current privacy notice to register")
        try:
            sign_pub = cu.b64d(req.get("sign_pub", ""))
            enc_pub = cu.b64d(req.get("enc_pub", ""))
        except ValueError as exc:
            raise p.ProtocolError("public keys are not valid base64") from exc
        if len(sign_pub) != 32 or len(enc_pub) != 32:
            raise p.ProtocolError("public keys must be 32 bytes")
        # Proof of possession: the client must sign its own key bundle, which
        # proves it really holds the private signing key it is registering.
        bundle = cu.canonical_json({"username": username, "sign_pub": req["sign_pub"],
                                    "enc_pub": req["enc_pub"]})
        cu.verify(sign_pub, bundle, req.get("bundle_sig", ""))
        if not self.store.create_user(username, password, email, sign_pub, enc_pub,
                                      CONSENT_VERSION):
            return {"ok": False, "error": "that username is not available"}
        log(f"registered {self.store.pseudonym(username)}")
        return {"ok": True}

    def _password_attempt(self, username, password):
        """
        One guarded password check, shared by login and account deletion so
        that both count towards the same limits. Returns (ok, error_message).

        The per-IP attempt is reserved *before* scrypt runs, and the per-user
        lock is held from the lockout check until the failure is recorded, so
        parallel requests cannot exceed MAX_LOGIN_ATTEMPTS or IP_FAIL_MAX.
        """
        ip = self.client_address[0]
        stamp = self.server.ip_reserve(ip)
        if stamp is None:
            return False, "too many failed logins from your address - wait a minute"
        if not isinstance(password, str) or len(password) > 128:
            password = ""
        valid_name = isinstance(username, str) and p.USERNAME_RE.match(username)
        if not valid_name:
            cu.hash_password(password or "x")       # same cost as a real check
            return False, "invalid username or password"
        with self.server.user_lock(username):
            user = self.store.get_user(username)
            if user and user["locked_until"] > time.time():
                return False, "account temporarily locked - try again later"
            if user:
                good = cu.verify_password(password, user["pwd_salt"], user["pwd_hash"])
            else:
                # Do the same expensive work for unknown users so response time
                # does not reveal which usernames exist.
                cu.hash_password(password or "x")
                good = False
            if not good:
                if user:
                    self.store.record_login_failure(username, MAX_LOGIN_ATTEMPTS, LOCK_SECONDS)
                # Same message whether the username or the password was wrong.
                return False, "invalid username or password"
        self.server.ip_release(ip, stamp)            # success: not a failure
        return True, ""

    def do_login(self, req):
        username = req.get("username")
        ok, error = self._password_attempt(username, req.get("password"))
        if not ok:
            return {"ok": False, "error": error}
        token = secrets.token_urlsafe(32)
        self.store.create_session(username, token, SESSION_TTL)
        self.user, self.token = username, token
        log(f"login {self.store.pseudonym(username)}")
        return {"ok": True, "token": token, "expires_in": SESSION_TTL}

    def do_logout(self, req):
        self._require_login(req)
        self.store.end_session(req["token"])
        return {"ok": True}

    def do_get_keys(self, req):
        self._require_login(req)
        username = p.check_username(req.get("username"))
        user = self.store.get_user(username)
        if not user:
            return {"ok": False, "error": "no such user"}
        if not self.store.user_row_intact(user):
            # Someone edited the key in the database. Refuse rather than hand
            # out a key that might belong to an attacker.
            log(f"INTEGRITY ALERT: key record for {self.store.pseudonym(username)} altered")
            return {"ok": False, "error": "integrity check failed for that user's keys"}
        return {"ok": True, "username": username,
                "sign_pub": cu.b64e(user["sign_pub"]), "enc_pub": cu.b64e(user["enc_pub"])}

    def do_send(self, req):
        sender = self._require_login(req)
        env = req.get("envelope")
        if not isinstance(env, dict):
            raise p.ProtocolError("missing envelope")
        hdr = env.get("header")
        if not isinstance(hdr, dict) or not isinstance(env.get("box"), dict):
            raise p.ProtocolError("malformed envelope")
        p.check_msg_id(hdr.get("msg_id"))
        if hdr.get("sender") != sender:
            raise p.ProtocolError("sender field does not match your login")
        recipient = p.check_username(hdr.get("recipient"))
        if hdr.get("kind") not in ("text", "file"):
            raise p.ProtocolError("unknown message kind")
        sent_at = hdr.get("sent_at")
        if not isinstance(sent_at, int) or abs(time.time() - sent_at) > p.CLOCK_SKEW_SECONDS:
            raise p.ProtocolError("message timestamp outside the allowed window")
        rec = self.store.get_user(recipient)
        if not rec:
            return {"ok": False, "error": "no such user"}
        # Server-side signature check stops forged envelopes at the door.
        me = self.store.get_user(sender)
        cu.verify(me["sign_pub"], cu.canonical_json({"header": hdr, "box": env["box"]}),
                  env.get("sig", ""))
        if not self.store.store_message(hdr["msg_id"], sender, recipient, env):
            return {"ok": False, "error": "duplicate message id - possible replay, rejected"}
        return {"ok": True, "msg_id": hdr["msg_id"]}

    def do_fetch(self, req):
        """
        Return waiting envelopes in pages that always fit in one frame.
        Sending everything at once let three 512 KB files push the reply over
        MAX_FRAME, which jammed the recipient's inbox until the 7-day purge.
        The client acks each page and asks again while 'more' is true.
        """
        user = self._require_login(req)
        page, size, pending = [], 0, self.store.pending_messages(user)
        for env in pending:
            n = len(json.dumps(env, separators=(",", ":")))
            if page and size + n > FETCH_PAGE_BYTES:
                break
            page.append(env)
            size += n
        return {"ok": True, "messages": page, "more": len(page) < len(pending)}

    def do_ack(self, req):
        user = self._require_login(req)
        ids = req.get("msg_ids")
        if not isinstance(ids, list) or len(ids) > 500:
            raise p.ProtocolError("msg_ids must be a list")
        ids = [p.check_msg_id(i) for i in ids]
        return {"ok": True, "deleted": self.store.ack_messages(user, ids)}

    def do_board_post(self, req):
        user = self._require_login(req)
        body = p.check_text(req.get("body"))
        post_id = uuid.uuid4().hex
        alias = "anon-" + secrets.token_hex(4)     # fresh 32-bit alias every post
        # Conditional privacy: the author's identity is sealed to the auditor's
        # PUBLIC key. The server cannot open it again; only the auditor, using
        # an offline private key and a recorded reason, can.
        escrow_plain = cu.canonical_json({"post_id": post_id, "author": user,
                                          "ts": int(time.time())})
        escrow = cu.seal(self.server.auditor_pub, escrow_plain, post_id.encode(), ESCROW_INFO)
        self.store.add_post(post_id, alias, body, escrow)
        return {"ok": True, "post_id": post_id, "alias": alias}

    def do_board_list(self, req):
        self._require_login(req)
        return {"ok": True, "posts": self.store.list_posts()}

    def do_export_data(self, req):
        """Right of access (PDPA s.30): everything the server holds about you."""
        user = self._require_login(req)
        u = self.store.get_user(user)
        return {"ok": True, "data": {
            "username": u["username"],
            "email": self.store.decrypt_email(u),
            "account_created": u["created_at"],
            "consent_version": u["consent_version"],
            "consent_given_at": u["consent_at"],
            "public_key_fingerprint": cu.key_fingerprint(u["sign_pub"], u["enc_pub"]),
            "messages_waiting_for_you": len(self.store.pending_messages(user)),
            "note": "Board posts are not linked to accounts and cannot be exported. "
                    "Message contents are end-to-end encrypted and unreadable by the server.",
        }}

    def do_delete_account(self, req):
        """Right to erasure (PDPA s.33). Requires the password again."""
        user = self._require_login(req)
        # Goes through the same guarded check as login, so a stolen session
        # token cannot be used to guess the password without limit.
        ok, error = self._password_attempt(user, req.get("password"))
        if not ok:
            return {"ok": False, "error": error.replace("invalid username or password",
                                                        "password incorrect - account not deleted")}
        self.store.delete_user(user)
        log(f"account deleted {self.store.pseudonym(user)}")
        return {"ok": True}


def purge_loop(store: Store, every: int = 60):
    """Background retention job."""
    while True:
        time.sleep(every)
        try:
            m, p_, _ = store.purge_expired()
        except Exception as exc:          # keep retention running after a DB error
            log(f"RETENTION ERROR: purge failed ({type(exc).__name__}), will retry")
            continue
        if m or p_:
            log(f"retention purge: {m} messages, {p_} posts removed")


def main():
    ap = argparse.ArgumentParser(description="CipherTalk relay server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5443)
    ap.add_argument("--data", default="server_data", help="folder made by setup_server")
    args = ap.parse_args()
    srv = CipherTalkServer((args.host, args.port), args.data)
    srv.store.purge_expired()
    threading.Thread(target=purge_loop, args=(srv.store,), daemon=True).start()
    log(f"CipherTalk server listening on {args.host}:{args.port} (TLS 1.3 only)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        log("shutting down")


if __name__ == "__main__":
    main()
