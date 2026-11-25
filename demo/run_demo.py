"""Runs the whole demo (normal use and the attacks) in a fresh demo_run/ folder
and saves the output of each step to demo_output/.

Run:  python demo/run_demo.py
"""

import os
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN = os.path.join(ROOT, "demo_run")
OUT = os.path.join(ROOT, "demo_output")
PY = sys.executable
PW = "Lib-Rary#2026"
ENV = dict(os.environ, PYTHONPATH=ROOT, PYTHONIOENCODING="utf-8",
           CIPHERTALK_AUDITOR_PASS="auditor-offline-key-77")


def run(cmd, stdin_text="", show=None):
    """Run a command in the demo folder and return '$ cmd' + its output."""
    res = subprocess.run(cmd, input=stdin_text, capture_output=True, text=True,
                         cwd=RUN, env=ENV, encoding="utf-8", timeout=120)
    shown = show or " ".join(c if " " not in c else f'"{c}"' for c in cmd[1:])
    return f"$ python {shown}\n{res.stdout}{res.stderr}"


def client(home, script, port=5443):
    cmd = [PY, "-m", "ciphertalk.client", "--home", home, "--port", str(port)]
    return run(cmd, script, show=f"-m ciphertalk.client --home {home}"
               + ("" if port == 5443 else f" --port {port}"))


def save(name, text):
    with open(os.path.join(OUT, name + ".txt"), "w", encoding="utf-8") as fh:
        fh.write(text.rstrip() + "\n")
    print(f"--- {name} ---\n{text}")


def fake_tls_server(port, cert_dir):
    """Attacker's server presenting its own certificate."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(cert_dir, "tls_cert.pem"),
                        os.path.join(cert_dir, "tls_key.pem"))
    s = socket.socket()
    s.bind(("127.0.0.1", port))
    s.listen(1)
    conn, _ = s.accept()
    try:
        ctx.wrap_socket(conn, server_side=True)
    except (ssl.SSLError, OSError):
        pass


def main():
    shutil.rmtree(RUN, ignore_errors=True)
    shutil.rmtree(OUT, ignore_errors=True)
    os.makedirs(RUN)
    os.makedirs(OUT)
    with open(os.path.join(RUN, "lab_schedule.txt"), "w") as fh:
        fh.write("Week 12 lab schedule\nMon 13:00 - crypto lab\nWed 09:00 - pen-test lab\n")

    save("01_setup", run([PY, "-m", "ciphertalk.setup_server"]))

    log = open(os.path.join(OUT, "server_console.txt"), "w", encoding="utf-8")
    server = subprocess.Popen([PY, "-m", "ciphertalk.server"], cwd=RUN, env=ENV,
                              stdout=log, stderr=subprocess.STDOUT, text=True)
    time.sleep(1.5)
    try:
        save("02_register_alice", client("alice_laptop",
             f"register alice\nyes\n{PW}\n{PW}\nalice.w@student.cmkl.ac.th\n"
             f"login alice\n{PW}\nquit\n"))
        save("03_register_bob", client("bob_laptop",
             f"register bob\nyes\n{PW}\n{PW}\n\nlogin bob\n{PW}\nquit\n"))
        save("04_alice_sends", client("alice_laptop",
             f"login alice\n{PW}\nsend bob Hi Bob, the project meeting is at 3pm in room 4B\n"
             "sendfile bob lab_schedule.txt\nfingerprint bob\n"
             "post The lab PCs still have last term's passwords saved in the browser\nquit\n"))
        save("05_bob_inbox", client("bob_laptop",
             f"login bob\n{PW}\nfingerprint\ninbox\nboard\ninbox\nquit\n"))
        # a second, abusive post: the kind of case conditional privacy exists for
        save("05b_threat_post", client("carol_phone",
             f"register carol\nyes\n{PW}\n{PW}\n\nlogin carol\n{PW}\n"
             "post If the lab fee goes up again someone in finance will get hurt\nboard\nquit\n"))

        # eavesdropping through the sniffer
        sniff = subprocess.Popen([PY, os.path.join("..", "demo", "sniff_proxy.py"),
                                  "--listen", "6000", "--target", "5443",
                                  "--look-for", "exam answers", "--secret", PW,
                                  "--look-for", "alice"],
                                 cwd=RUN, env=ENV, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True, encoding="utf-8")
        time.sleep(1)
        talk = client("alice_laptop", f"login alice\n{PW}\n"
                      "send bob The exam answers are in shared folder B\nquit\n", port=6000)
        sniffed = sniff.communicate(timeout=30)[0]
        save("06_eavesdrop", talk + "\n$ python demo/sniff_proxy.py --listen 6000 --target 5443 "
             "--look-for \"exam answers\" --secret <password> --look-for alice\n" + sniffed)
        client("bob_laptop", f"login bob\n{PW}\ninbox\nquit\n")     # clear it

        # MITM with the attacker's own certificate
        att = os.path.join(RUN, "attacker_cert")
        os.makedirs(att)
        sys.path.insert(0, ROOT)
        from ciphertalk.setup_server import make_tls_cert
        make_tls_cert(att)
        threading.Thread(target=fake_tls_server, args=(6001, att), daemon=True).start()
        time.sleep(0.5)
        save("07_mitm", "# attacker runs a fake server on port 6001 with their own certificate\n"
             + client("alice_laptop", "", port=6001))

        # tampering with a stored message
        t = client("alice_laptop", f"login alice\n{PW}\n"
                   "send bob Please transfer 500 baht to account 123-4-56789\nquit\n")
        t += run([PY, os.path.join("..", "demo", "tamper_db.py"), "message"],
                 show="demo/tamper_db.py message")
        t += client("bob_laptop", f"login bob\n{PW}\ninbox\nquit\n")
        save("08_tamper_message", t)

        # replay
        r = client("alice_laptop", f"login alice\n{PW}\nsend bob Approved: you can submit late\nquit\n")
        r += run([PY, os.path.join("..", "demo", "tamper_db.py"), "save"], show="demo/tamper_db.py save")
        r += client("bob_laptop", f"login bob\n{PW}\ninbox\nquit\n")
        r += run([PY, os.path.join("..", "demo", "tamper_db.py"), "replay"], show="demo/tamper_db.py replay")
        r += client("bob_laptop", f"login bob\n{PW}\ninbox\nquit\n")
        save("09_replay", r)

        # key substitution
        k = client("erin_pc", f"register erin\nyes\n{PW}\n{PW}\n\nquit\n")
        k += run([PY, os.path.join("..", "demo", "tamper_db.py"), "key", "erin"],
                 show="demo/tamper_db.py key erin")
        k += client("alice_laptop", f"login alice\n{PW}\nsend erin hello erin\nquit\n")
        save("10_key_swap", k)

        # lockout
        lock_script = "".join("login bob\nwrong-guess-%d\n" % i for i in range(5))
        lock_script += f"login bob\n{PW}\nquit\n"
        save("11_lockout", "# someone at bob's laptop is guessing his password\n"
             + client("bob_laptop", lock_script))

        # privacy rights
        save("12_export_delete", client("dave_pc",
             f"register dave\nyes\n{PW}\n{PW}\ndave.s@gmail.com\nlogin dave\n{PW}\n"
             f"export\ndeleteaccount\nDELETE\n{PW}\nlogin dave\n{PW}\nquit\n"))
        save("13_decline", client("frank_pc", "register frank\nno\nquit\n"))

        # auditor: reveal only the threatening post
        import sqlite3
        con = sqlite3.connect(os.path.join(RUN, "server_data", "ciphertalk.db"))
        post_id = con.execute("SELECT post_id FROM board_posts WHERE body LIKE '%get hurt%'").fetchone()[0]
        con.close()
        a = run([PY, "-m", "ciphertalk.auditor", "verify-log"])
        a += run([PY, "-m", "ciphertalk.auditor", "reveal", post_id, "--reason", "curious"])
        a += run([PY, "-m", "ciphertalk.auditor", "reveal", post_id, "--reason",
                  "Case SA-2026-014: post threatens harm to finance staff, referred by campus security"])
        save("14_auditor", a)
        tr = run([PY, os.path.join("..", "demo", "tamper_db.py"), "logtail"],
                 show="demo/tamper_db.py logtail")
        tr += run([PY, "-m", "ciphertalk.auditor", "verify-log"])
        save("15a_log_truncation", tr)
        lg = run([PY, os.path.join("..", "demo", "tamper_db.py"), "log"], show="demo/tamper_db.py log")
        lg += run([PY, "-m", "ciphertalk.auditor", "verify-log"])
        save("15b_log_tamper", lg)

        dump = subprocess.run([PY, "-c", (
            "import sqlite3;c=sqlite3.connect('server_data/ciphertalk.db');"
            "[print(r) for r in c.execute('SELECT seq,actor,action,detail FROM audit_log ORDER BY seq LIMIT 12')];"
            "print();r=c.execute(\"SELECT username,email_ct,pwd_hash FROM users WHERE username='alice'\").fetchone();"
            "print('username :',r[0]);print('email_ct :',r[1].hex()[:64]+'...');print('pwd_hash :',r[2].hex());"
            "e=c.execute('SELECT escrow FROM board_posts').fetchone()[0];print('escrow   :',e[:90]+'...')")],
            cwd=RUN, env=ENV, capture_output=True, text=True, encoding="utf-8")
        save("16_db_view", "$ sqlite3 server_data/ciphertalk.db   (what an attacker with the DB file sees)\n"
             + dump.stdout + dump.stderr)
    finally:
        server.terminate()
        server.wait()
        log.close()

    tests = subprocess.run([PY, "-m", "pytest", "-v", "-p", "no:cacheprovider", "tests"],
                           cwd=ROOT, env=ENV, capture_output=True, text=True, encoding="utf-8")
    save("17_pytest", "$ python -m pytest -v tests\n" + tests.stdout[-6000:])


if __name__ == "__main__":
    main()
