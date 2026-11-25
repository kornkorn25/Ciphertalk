"""SQLite storage for the server.

Passwords are scrypt hashes, emails are AES-GCM encrypted, user keys and board
posts carry a row MAC, and the audit log is an HMAC hash chain that only
contains pseudonyms.
"""

import hmac
import json
import sqlite3
import threading
import time

from . import crypto_utils as cu

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username        TEXT PRIMARY KEY,
    pwd_salt        BLOB NOT NULL,
    pwd_hash        BLOB NOT NULL,
    email_nonce     BLOB,
    email_ct        BLOB,
    sign_pub        BLOB NOT NULL,
    enc_pub         BLOB NOT NULL,
    consent_version TEXT NOT NULL,
    consent_at      INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    INTEGER NOT NULL DEFAULT 0,
    row_mac         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,
    username    TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    expires_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    msg_id      TEXT PRIMARY KEY,          -- UNIQUE => replayed ids are refused
    sender      TEXT NOT NULL,
    recipient   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    envelope    TEXT NOT NULL,
    stored_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS board_posts (
    post_id     TEXT PRIMARY KEY,
    alias       TEXT NOT NULL,
    body        TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    escrow      TEXT NOT NULL,             -- identity sealed to auditor key
    row_mac     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    actor       TEXT NOT NULL,             -- pseudonym, never a username
    action      TEXT NOT NULL,
    detail      TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    entry_hash  TEXT NOT NULL
);
"""

MESSAGE_RETENTION_SECONDS = 7 * 24 * 3600   # undelivered messages: 7 days
BOARD_RETENTION_SECONDS = 90 * 24 * 3600    # board posts: 90 days
GENESIS_HASH = "0" * 64


class Store:
    """Thread-safe wrapper: one connection guarded by a lock."""

    def __init__(self, db_path: str, secrets: dict):
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(SCHEMA)
        self.lock = threading.Lock()
        self.data_key = cu.b64d(secrets["data_key"])
        self.pseudo_key = cu.b64d(secrets["pseudo_key"])
        self.integrity_key = cu.b64d(secrets["integrity_key"])

    def pseudonym(self, username: str) -> str:
        """Stable keyed pseudonym used in logs instead of the real username."""
        return "u_" + cu.hmac_sha256(self.pseudo_key, username.encode())[:12]

    def _mac(self, *fields) -> str:
        return cu.hmac_sha256(self.integrity_key, cu.canonical_json(list(fields)))

    def _user_mac(self, username, sign_pub: bytes, enc_pub: bytes, email_ct) -> str:
        return self._mac("user", username, cu.b64e(sign_pub), cu.b64e(enc_pub),
                         cu.b64e(email_ct or b""))

    def audit(self, actor: str, action: str, detail: str = "") -> None:
        """Append one tamper-evident entry. Caller must already hold the lock."""
        row = self.db.execute(
            "SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row[0] if row else GENESIS_HASH
        ts = int(time.time())
        entry_hash = self._mac("audit", prev, ts, actor, action, detail)
        self.db.execute(
            "INSERT INTO audit_log (ts, actor, action, detail, prev_hash, entry_hash) "
            "VALUES (?,?,?,?,?,?)", (ts, actor, action, detail, prev, entry_hash))

    def verify_audit_chain(self) -> tuple:
        """Return (ok, message). Walks the chain and recomputes every HMAC."""
        with self.lock:
            rows = self.db.execute(
                "SELECT seq, ts, actor, action, detail, prev_hash, entry_hash "
                "FROM audit_log ORDER BY seq").fetchall()
        prev = GENESIS_HASH
        expected_seq = 1
        for seq, ts, actor, action, detail, prev_hash, entry_hash in rows:
            if seq != expected_seq:
                return False, f"entry {expected_seq} is missing (found {seq})"
            if prev_hash != prev:
                return False, f"entry {seq}: chain link broken"
            if entry_hash != self._mac("audit", prev, ts, actor, action, detail):
                return False, f"entry {seq}: contents were modified"
            prev = entry_hash
            expected_seq += 1
        return True, f"{len(rows)} entries verified, chain intact"

    def create_user(self, username, password, email, sign_pub, enc_pub, consent_version):
        salt, pwd_hash = cu.hash_password(password)
        e_nonce = e_ct = None
        if email:
            # AAD binds the ciphertext to this username, so an attacker can't
            # swap two users' encrypted emails inside the database.
            e_nonce, e_ct = cu.aes_encrypt(self.data_key, email.encode(), username.encode())
        now = int(time.time())
        mac = self._user_mac(username, sign_pub, enc_pub, e_ct)
        with self.lock:
            try:
                self.db.execute(
                    "INSERT INTO users (username, pwd_salt, pwd_hash, email_nonce, email_ct,"
                    " sign_pub, enc_pub, consent_version, consent_at, created_at, row_mac)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (username, salt, pwd_hash, e_nonce, e_ct, sign_pub, enc_pub,
                     consent_version, now, now, mac))
            except sqlite3.IntegrityError:
                return False
            self.audit(self.pseudonym(username), "REGISTER")
            self.db.commit()
        return True

    def get_user(self, username):
        with self.lock:
            row = self.db.execute(
                "SELECT username, pwd_salt, pwd_hash, email_nonce, email_ct, sign_pub, enc_pub,"
                " consent_version, consent_at, created_at, failed_logins, locked_until, row_mac"
                " FROM users WHERE username=?", (username,)).fetchone()
        if not row:
            return None
        keys = ("username", "pwd_salt", "pwd_hash", "email_nonce", "email_ct", "sign_pub",
                "enc_pub", "consent_version", "consent_at", "created_at", "failed_logins",
                "locked_until", "row_mac")
        return dict(zip(keys, row))

    def user_row_intact(self, user: dict) -> bool:
        expected = self._user_mac(user["username"], user["sign_pub"], user["enc_pub"],
                                  user["email_ct"])
        return hmac.compare_digest(expected, user["row_mac"])

    def decrypt_email(self, user: dict) -> str:
        if not user["email_ct"]:
            return ""
        return cu.aes_decrypt(self.data_key, user["email_nonce"], user["email_ct"],
                              user["username"].encode()).decode()

    def record_login_failure(self, username, max_attempts, lock_seconds) -> None:
        with self.lock:
            self.db.execute("UPDATE users SET failed_logins = failed_logins + 1"
                            " WHERE username=?", (username,))
            row = self.db.execute("SELECT failed_logins FROM users WHERE username=?",
                                  (username,)).fetchone()
            if row and row[0] >= max_attempts:
                self.db.execute("UPDATE users SET locked_until=?, failed_logins=0"
                                " WHERE username=?", (int(time.time()) + lock_seconds, username))
                self.audit(self.pseudonym(username), "ACCOUNT_LOCKED",
                           f"{max_attempts} failed logins")
            else:
                self.audit(self.pseudonym(username), "LOGIN_FAILED")
            self.db.commit()

    def delete_user(self, username) -> None:
        """Right to erasure: remove account, sessions and pending messages."""
        with self.lock:
            self.db.execute("DELETE FROM messages WHERE recipient=? OR sender=?",
                            (username, username))
            self.db.execute("DELETE FROM sessions WHERE username=?", (username,))
            self.db.execute("DELETE FROM users WHERE username=?", (username,))
            self.audit(self.pseudonym(username), "ACCOUNT_DELETED")
            self.db.commit()

    def create_session(self, username, token: str, ttl: int) -> None:
        with self.lock:
            self.db.execute("UPDATE users SET failed_logins=0 WHERE username=?", (username,))
            self.db.execute("INSERT INTO sessions VALUES (?,?,?)",
                            (cu.sha256_hex(token.encode()), username, int(time.time()) + ttl))
            self.audit(self.pseudonym(username), "LOGIN_OK")
            self.db.commit()

    def session_user(self, token: str):
        """Return the username for a live token, or None. Only hashes are stored."""
        if not isinstance(token, str) or len(token) > 100:
            return None
        with self.lock:
            row = self.db.execute("SELECT username, expires_at FROM sessions WHERE token_hash=?",
                                  (cu.sha256_hex(token.encode()),)).fetchone()
        if not row or row[1] < time.time():
            return None
        return row[0]

    def end_session(self, token: str) -> None:
        with self.lock:
            self.db.execute("DELETE FROM sessions WHERE token_hash=?",
                            (cu.sha256_hex(token.encode()),))
            self.db.commit()

    def store_message(self, msg_id, sender, recipient, envelope: dict) -> bool:
        with self.lock:
            try:
                self.db.execute("INSERT INTO messages VALUES (?,?,?,?,?)",
                                (msg_id, sender, recipient, json.dumps(envelope),
                                 int(time.time())))
            except sqlite3.IntegrityError:
                return False      # duplicate msg_id -> replay attempt
            # Log only that a message moved between two pseudonyms, never content.
            self.audit(self.pseudonym(sender), "MESSAGE_STORED",
                       f"to={self.pseudonym(recipient)}")
            self.db.commit()
        return True

    def pending_messages(self, recipient):
        with self.lock:
            rows = self.db.execute("SELECT envelope FROM messages WHERE recipient=?"
                                   " ORDER BY stored_at", (recipient,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def ack_messages(self, recipient, msg_ids) -> int:
        """Delivered messages are deleted from the server straight away."""
        with self.lock:
            n = 0
            for mid in msg_ids:
                n += self.db.execute("DELETE FROM messages WHERE msg_id=? AND recipient=?",
                                     (mid, recipient)).rowcount
            self.db.commit()
        return n

    def add_post(self, post_id, alias, body, escrow: dict) -> None:
        now = int(time.time())
        escrow_json = cu.canonical_json(escrow).decode()
        mac = self._mac("post", post_id, alias, body, now, escrow_json)
        with self.lock:
            self.db.execute("INSERT INTO board_posts VALUES (?,?,?,?,?,?)",
                            (post_id, alias, body, now, escrow_json, mac))
            self.audit("anonymous", "BOARD_POST", f"post={post_id}")
            self.db.commit()

    def list_posts(self, limit=20):
        with self.lock:
            rows = self.db.execute(
                "SELECT post_id, alias, body, created_at, escrow, row_mac FROM board_posts"
                " ORDER BY created_at DESC, rowid DESC LIMIT ?", (limit,)).fetchall()
        posts = []
        for post_id, alias, body, created_at, escrow, mac in rows:
            ok = hmac.compare_digest(
                mac, self._mac("post", post_id, alias, body, created_at, escrow))
            posts.append({"post_id": post_id, "alias": alias, "body": body,
                          "created_at": created_at, "intact": ok})
        return posts

    def get_post_escrow(self, post_id):
        with self.lock:
            row = self.db.execute("SELECT escrow FROM board_posts WHERE post_id=?",
                                  (post_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def purge_expired(self) -> tuple:
        """Delete data that has passed its retention period."""
        now = int(time.time())
        with self.lock:
            m = self.db.execute("DELETE FROM messages WHERE stored_at < ?",
                                (now - MESSAGE_RETENTION_SECONDS,)).rowcount
            p = self.db.execute("DELETE FROM board_posts WHERE created_at < ?",
                                (now - BOARD_RETENTION_SECONDS,)).rowcount
            s = self.db.execute("DELETE FROM sessions WHERE expires_at < ?", (now,)).rowcount
            if m or p:
                self.audit("system", "RETENTION_PURGE", f"messages={m} posts={p}")
            self.db.commit()
        return m, p, s
