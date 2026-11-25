"""Automated tests. Names start with the category: tc01 normal, tc02 exceptional,
tc03 security, tc04 integrity, tc05 privacy (Table 2.2 in the report maps them
to TC-001 to TC-010).

Run:  python -m pytest -v tests
"""

import json
import os
import re
import socket
import ssl
import sqlite3
import threading
import time

import pytest

from ciphertalk import crypto_utils as cu
from ciphertalk import protocol as p
from ciphertalk import auditor
from ciphertalk.client_core import ClientError, KeyChangedError
from ciphertalk.setup_server import make_tls_cert
from conftest import AUDITOR_PASS, PASSWORD, free_port

SECRET_TEXT = "Meet at the library at 3pm, room 4B"


def db(env):
    return sqlite3.connect(env["data"] / "ciphertalk.db")


# helpers: a passive sniffer and an active man-in-the-middle

class Sniffer:
    """Plain TCP relay that records every byte passing through (eavesdropper)."""

    def __init__(self, target_port):
        self.port = free_port()
        self.captured = bytearray()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", self.port))
        self.listener.listen()
        threading.Thread(target=self._run, args=(target_port,), daemon=True).start()

    def _pipe(self, a, b):
        try:
            while True:
                data = a.recv(65536)
                if not data:
                    break
                self.captured.extend(data)
                b.sendall(data)
        except OSError:
            pass

    def _run(self, target_port):
        client, _ = self.listener.accept()
        upstream = socket.create_connection(("127.0.0.1", target_port))
        threading.Thread(target=self._pipe, args=(client, upstream), daemon=True).start()
        self._pipe(upstream, client)


class FakeServer:
    """Attacker presenting their OWN certificate for 'localhost' (MITM)."""

    def __init__(self, tmp):
        os.makedirs(tmp, exist_ok=True)
        make_tls_cert(str(tmp))
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(os.path.join(tmp, "tls_cert.pem"),
                                 os.path.join(tmp, "tls_key.pem"))
        self.port = free_port()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", self.port))
        self.listener.listen()
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        conn, _ = self.listener.accept()
        try:
            self.ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            pass


# TC-01  normal case: register, log in, send and receive a message and a file

def test_tc01_normal_message_and_file(env, tmp_path):
    alice, bob = env["user"]("alice"), env["user"]("bob")
    alice.send_text("bob", SECRET_TEXT)
    doc = tmp_path / "notes.txt"
    doc.write_text("lab results attached")
    alice.send_file("bob", str(doc))

    inbox = bob.fetch_inbox()
    assert [m["status"] for m in inbox] == ["verified", "verified"]
    assert inbox[0]["from"] == "alice" and inbox[0]["text"] == SECRET_TEXT
    with open(inbox[1]["saved_to"]) as fh:
        assert fh.read() == "lab results attached"
    # delivered messages are removed from the server immediately
    assert db(env).execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 0
    assert bob.fetch_inbox() == []


# TC-02  exceptional cases: bad input, wrong password, account lockout

def test_tc02_wrong_password_lockout(env):
    env["user"]("carol")
    attacker = env["client"]("carol")          # same device folder, so keys unlock
    for _ in range(5):
        with pytest.raises(ClientError, match="invalid username or password"):
            attacker._ok(attacker.request({"action": "login", "username": "carol",
                                           "password": "Wrong-guess-99"}))
    # Even the correct password is refused while locked.
    with pytest.raises(ClientError, match="locked"):
        attacker.login("carol", PASSWORD)


def test_tc02_unknown_user_gets_same_error(env):
    c = env["client"]("x")
    resp = c.request({"action": "login", "username": "nobody_here", "password": "Abcdefgh12"})
    assert resp == {"ok": False, "error": "invalid username or password"}


def test_tc02_input_validation(env, tmp_path):
    alice = env["user"]("alice")
    env["user"]("bob")
    with pytest.raises(p.ProtocolError):
        p.check_username("../../admin")
    with pytest.raises(p.ProtocolError):
        p.check_password("short")
    with pytest.raises(p.ProtocolError):
        alice.send_text("bob", "x" * (p.MAX_TEXT_LEN + 1))
    with pytest.raises(p.ProtocolError):
        p.check_filename("../../etc/passwd")
    big = tmp_path / "big.bin"
    big.write_bytes(os.urandom(p.MAX_FILE_BYTES + 1))
    with pytest.raises(ClientError, match="larger than"):
        alice.send_file("bob", str(big))
    with pytest.raises(ClientError, match="no such user"):
        alice.send_text("ghost_user", "hello")
    # terminal escape codes are stripped before display
    assert p.check_text("hi\x1b[2Jthere") == "hi[2Jthere"


def test_tc02_not_logged_in(env):
    c = env["client"]("anon")
    resp = c.request({"action": "fetch", "token": "made-up-token"})
    assert resp["ok"] is False and "not logged in" in resp["error"]


# TC-03  data security: eavesdropping, MITM, TLS version, data at rest

def test_tc03_eavesdropper_sees_only_ciphertext(env):
    env["user"]("bob")
    sniff = Sniffer(env["port"])
    alice = env["client"]("alice", port_override=sniff.port)
    alice.register("alice", PASSWORD, "alice@example.com", consent=True)
    alice.login("alice", PASSWORD)
    alice.send_text("bob", SECRET_TEXT)
    time.sleep(0.3)
    wire = bytes(sniff.captured)
    assert len(wire) > 1000                        # traffic really was captured
    for secret in (SECRET_TEXT, PASSWORD, "alice@example.com", alice.token):
        assert secret.encode() not in wire


def test_tc03_mitm_with_fake_certificate_is_refused(env):
    fake = FakeServer(env["tmp"] / "attacker")
    with pytest.raises(ClientError, match="could not verify the server"):
        env["client"]("victim", port_override=fake.port)


def test_tc03_old_tls_rejected(env):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    raw = socket.create_connection(("127.0.0.1", env["port"]))
    with pytest.raises((ssl.SSLError, OSError)):
        ctx.wrap_socket(raw, server_hostname="localhost").recv(1)


def test_tc03_server_storage_has_no_plaintext(env):
    alice, _bob = env["user"]("alice", "alice@example.com"), env["user"]("bob")
    alice.send_text("bob", SECRET_TEXT)
    raw = (env["data"] / "ciphertalk.db").read_bytes()
    assert SECRET_TEXT.encode() not in raw
    assert b"alice@example.com" not in raw          # email encrypted at rest
    assert PASSWORD.encode() not in raw             # only a scrypt hash
    # tokens are stored hashed, so a DB leak does not leak live sessions
    assert alice.token.encode() not in raw


def test_tc03_private_keys_encrypted_on_device(env):
    alice = env["user"]("alice")
    blob = (env["tmp"] / "alice_device" / "alice" / "identity.json").read_text()
    raw_priv = cu.b64e(cu.raw_private(alice.keys["ed25519"]))
    assert raw_priv not in blob


def test_tc03_cannot_send_as_someone_else(env):
    alice, bob = env["user"]("alice"), env["user"]("bob")
    env_ = alice._build_envelope("bob", "text", {"text": "hi"})
    env_["header"]["sender"] = "bob"               # spoof the sender field
    resp = alice.request({"action": "send", "envelope": env_})
    assert resp["ok"] is False and "does not match" in resp["error"]


# TC-04  data integrity: tampering, replay, key substitution, audit log

def test_tc04_tampered_ciphertext_rejected(env):
    alice, bob = env["user"]("alice"), env["user"]("bob")
    alice.send_text("bob", "pay 100 baht")
    con = db(env)
    msg_id, envelope = con.execute("SELECT msg_id, envelope FROM messages").fetchone()
    e = json.loads(envelope)
    ct = bytearray(cu.b64d(e["box"]["ct"]))
    ct[0] ^= 0x01                                  # flip ONE bit
    e["box"]["ct"] = cu.b64e(bytes(ct))
    con.execute("UPDATE messages SET envelope=? WHERE msg_id=?", (json.dumps(e), msg_id))
    con.commit()
    [m] = bob.fetch_inbox()
    assert m["status"] == "rejected" and "signature" in m["reason"]


def test_tc04_tampered_header_rejected(env):
    alice, bob = env["user"]("alice"), env["user"]("bob")
    alice.send_text("bob", "hello")
    con = db(env)
    msg_id, envelope = con.execute("SELECT msg_id, envelope FROM messages").fetchone()
    e = json.loads(envelope)
    e["header"]["sent_at"] -= 3600                 # back-date the message
    con.execute("UPDATE messages SET envelope=? WHERE msg_id=?", (json.dumps(e), msg_id))
    con.commit()
    [m] = bob.fetch_inbox()
    assert m["status"] == "rejected"


def test_tc04_replay_rejected_by_server_and_client(env):
    alice, bob = env["user"]("alice"), env["user"]("bob")
    env_ = alice._build_envelope("bob", "text", {"text": "transfer approved"})
    assert alice.request({"action": "send", "envelope": env_})["ok"]
    again = alice.request({"action": "send", "envelope": env_})
    assert again["ok"] is False and "replay" in again["error"]
    assert bob.fetch_inbox()[0]["status"] == "verified"
    # an attacker with DB access re-inserts the delivered message
    con = db(env)
    con.execute("INSERT INTO messages VALUES (?,?,?,?,?)",
                (env_["header"]["msg_id"], "alice", "bob", json.dumps(env_), int(time.time())))
    con.commit()
    [m] = bob.fetch_inbox()
    assert m["status"] == "rejected" and "replay" in m["reason"]


def test_tc04_old_timestamp_rejected(env):
    alice, _ = env["user"]("alice"), env["user"]("bob")
    env_ = alice._build_envelope("bob", "text", {"text": "x"})
    env_["header"]["sent_at"] -= 3600
    env_["sig"] = cu.sign(alice.keys["ed25519"],
                          cu.canonical_json({"header": env_["header"], "box": env_["box"]}))
    resp = alice.request({"action": "send", "envelope": env_})
    assert resp["ok"] is False and "timestamp" in resp["error"]


def test_tc04_key_substitution_in_db_detected(env):
    alice, _ = env["user"]("alice"), env["user"]("bob")
    con = db(env)
    con.execute("UPDATE users SET enc_pub=? WHERE username='bob'", (os.urandom(32),))
    con.commit()
    with pytest.raises(ClientError, match="integrity check failed"):
        alice.send_text("bob", "hi")


def test_tc04_key_change_detected_by_pinning(env):
    """Insider who also holds the integrity key re-MACs a fake key: the
    client's pinned copy still catches it."""
    alice, _ = env["user"]("alice"), env["user"]("bob")
    alice.send_text("bob", "first message pins bob's keys")
    store = env["server"].store
    bob = store.get_user("bob")
    fake = os.urandom(32)
    mac = store._user_mac("bob", bob["sign_pub"], fake, bob["email_ct"])
    with store.lock:
        store.db.execute("UPDATE users SET enc_pub=?, row_mac=? WHERE username='bob'",
                         (fake, mac))
        store.db.commit()
    with pytest.raises(KeyChangedError):
        alice.send_text("bob", "second message")


def test_tc04_audit_log_tampering_detected(env):
    env["user"]("alice")
    env["user"]("bob")
    assert env["server"].store.verify_audit_chain()[0]
    con = db(env)
    con.execute("UPDATE audit_log SET action='LOGIN_OK' WHERE action='REGISTER' AND seq=1")
    con.commit()
    ok, msg = env["server"].store.verify_audit_chain()
    assert not ok and "entry 1" in msg
    con.execute("UPDATE audit_log SET action='REGISTER' WHERE seq=1")
    con.execute("DELETE FROM audit_log WHERE seq=2")
    con.commit()
    ok, msg = env["server"].store.verify_audit_chain()
    assert not ok and "missing" in msg


def test_tc04_board_post_tampering_flagged(env):
    alice = env["user"]("alice")
    alice.board_post("The lab printer is broken again")
    con = db(env)
    con.execute("UPDATE board_posts SET body='Everything is fine'")
    con.commit()
    [post] = alice.board_list()
    assert post["intact"] is False


# TC-05  data privacy: pseudonymous logs, minimisation, conditional privacy,
#        data subject rights, retention

def test_tc05_logs_are_pseudonymous(env):
    alice, _ = env["user"]("alice"), env["user"]("bob")
    alice.send_text("bob", SECRET_TEXT)
    rows = db(env).execute("SELECT actor, action, detail FROM audit_log").fetchall()
    text = json.dumps(rows)
    assert "alice" not in text and "bob" not in text and SECRET_TEXT not in text
    assert any(r[1] == "MESSAGE_STORED" for r in rows)


def test_tc05_board_is_anonymous_but_accountable(env, monkeypatch, capsys):
    alice, bob = env["user"]("alice"), env["user"]("bob")
    r1 = alice.board_post("The assignment deadline is too tight")
    r2 = alice.board_post("Second post from the same person")
    posts = bob.board_list()
    assert all("alice" not in json.dumps(post) for post in posts)
    for r in (r1, r2):          # random 32-bit hex alias, nothing from the name
        assert re.fullmatch(r"anon-[0-9a-f]{8}", r["alias"]) and "alice" not in r["alias"]
    assert r1["alias"] != r2["alias"] and r1["post_id"] != r2["post_id"]
    raw = (env["data"] / "ciphertalk.db").read_bytes()
    assert b'"author":"alice"' not in raw           # identity is sealed, not stored

    monkeypatch.setenv("CIPHERTALK_AUDITOR_PASS", AUDITOR_PASS)
    key = str(env["vault"] / "auditor_private.json")

    class A:  # argparse stand-in
        post_id, data = r1["post_id"], str(env["data"])

    a = A()
    a.key, a.reason = key, "short"
    assert auditor.cmd_reveal(a) == 2               # reason too short -> refused
    a.reason = "Report #12: post contains a threat against a staff member"
    assert auditor.cmd_reveal(a) == 0
    assert "written by: alice" in capsys.readouterr().out
    logged = db(env).execute("SELECT detail FROM audit_log WHERE action='IDENTITY_REVEALED'")
    assert "Report #12" in logged.fetchone()[0]


def test_tc05_wrong_auditor_passphrase(env, monkeypatch):
    alice = env["user"]("alice")
    r = alice.board_post("hello board")
    monkeypatch.setenv("CIPHERTALK_AUDITOR_PASS", "not-the-right-one")

    class A:
        post_id, data, key = r["post_id"], str(env["data"]), str(env["vault"] / "auditor_private.json")
        reason = "Testing a wrong passphrase attempt"

    assert auditor.cmd_reveal(A()) == 1


def test_tc05_export_and_delete(env):
    alice, bob = env["user"]("alice", "alice@example.com"), env["user"]("bob")
    bob.send_text("alice", "waiting message")
    data = alice.export_data()
    assert data["email"] == "alice@example.com" and data["messages_waiting_for_you"] == 1
    assert p.mask_email(data["email"]) == "a***e@e******.com"
    with pytest.raises(ClientError, match="password incorrect"):
        alice.delete_account("Wrong-password-1")
    alice.delete_account(PASSWORD)
    con = db(env)
    assert con.execute("SELECT COUNT(*) FROM users WHERE username='alice'").fetchone()[0] == 0
    assert con.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 0
    assert not (env["tmp"] / "alice_device" / "alice").exists()


def test_tc05_email_is_optional(env):
    alice = env["user"]("alice")                 # registered with no email
    assert alice.export_data()["email"] == ""
    row = db(env).execute("SELECT email_ct FROM users WHERE username='alice'").fetchone()
    assert row[0] is None


def test_tc05_retention_purge(env):
    alice, _ = env["user"]("alice"), env["user"]("bob")
    alice.send_text("bob", "old message")
    con = db(env)
    con.execute("UPDATE messages SET stored_at = stored_at - 8*24*3600")
    con.commit()
    m, _p, _s = env["server"].store.purge_expired()
    assert m == 1
    assert con.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 0


def test_registration_requires_consent(env):
    c = env["client"]("dave")
    with pytest.raises(ClientError, match="privacy notice"):
        c.register("dave", PASSWORD, "", consent=False)
    resp = c.request({"action": "register", "username": "dave", "password": PASSWORD,
                      "consent": False})
    assert resp["ok"] is False and "privacy notice" in resp["error"]


# Regression tests for issues found in review

def _wrong_login(env, user, results, i):
    c = env["client"](f"burst{i}")
    results.append(c.request({"action": "login", "username": user,
                              "password": "Wrong-guess-%02d" % i})["error"])


def test_tc02_parallel_login_burst_cannot_beat_lockout(env):
    """30 simultaneous wrong guesses from one IP: at most 5 reach the
    password check for the account, and at most 10 are allowed for the IP."""
    env["user"]("carol")
    results, threads = [], []
    for i in range(30):
        t = threading.Thread(target=_wrong_login, args=(env, "carol", results, i))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    checked = results.count("invalid username or password")
    assert len(results) == 30
    assert 1 <= checked <= 5
    allowed = checked + sum("locked" in r for r in results)
    assert allowed <= 10                 # per-IP budget
    assert sum("from your address" in r for r in results) >= 20


def test_tc02_ip_limit_across_many_usernames(env):
    c = env["client"]("stuffer")
    errors = [c.request({"action": "login", "username": f"guess_{i:02d}",
                         "password": "Abcdefgh12"})["error"] for i in range(11)]
    assert errors[:10] == ["invalid username or password"] * 10
    assert "from your address" in errors[10]


def test_tc02_connection_rate_limit(env):
    c = env["client"]("flood")
    replies = [c.request({"action": "hello"}) for _ in range(31)]
    assert all(r["ok"] for r in replies[:29])
    assert replies[-1] == {"ok": False, "error": "too many requests - slow down"}


def test_tc02_session_expiry(env):
    alice = env["user"]("alice")
    con = db(env)
    con.execute("UPDATE sessions SET expires_at = 0")
    con.commit()
    with pytest.raises(ClientError, match="session expired"):
        alice.fetch_inbox()


def test_tc03_delete_account_is_not_a_password_oracle(env):
    """Guesses through deleteaccount count towards the same lockout."""
    alice = env["user"]("alice")
    for i in range(5):
        with pytest.raises(ClientError, match="password incorrect"):
            alice.delete_account("Wrong-guess-%d" % i)
    with pytest.raises(ClientError, match="locked"):
        alice.delete_account(PASSWORD)
    assert db(env).execute("SELECT COUNT(*) FROM users WHERE username='alice'").fetchone()[0] == 1


def test_tc01_inbox_pagination_with_large_files(env, tmp_path):
    """Three 512 KB files used to exceed the 2 MB frame and jam the inbox."""
    alice, bob = env["user"]("alice"), env["user"]("bob")
    for i in range(3):
        f = tmp_path / f"big{i}.bin"
        f.write_bytes(os.urandom(p.MAX_FILE_BYTES))
        alice.send_file("bob", str(f))
    inbox = bob.fetch_inbox()
    assert [m["status"] for m in inbox] == ["verified"] * 3
    assert db(env).execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 0


def test_tc02_sanitisation_of_text_and_file_names():
    assert p.check_text("a31mbc") == "a31mbc"            # C1 CSI and DEL removed
    assert p.check_text("file‮gnp.exe") == "filegnp.exe"   # bidi override removed
    for bad in ("CON", "nul.txt", "aux", "COM1.log", "a.txt.", "report "):
        with pytest.raises(p.ProtocolError):
            p.check_filename(bad)
    assert p.check_filename("lab_schedule.txt") == "lab_schedule.txt"
