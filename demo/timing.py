"""Measures send/receive time for a text message and a 512 KB file, and the time
for one login (NFR-14). Uses a temporary server on a random port.

  python demo/timing.py
"""

import json
import os
import statistics
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from ciphertalk import crypto_utils as cu                         # noqa: E402
from ciphertalk.client_core import ClientCore                     # noqa: E402
from ciphertalk.server import CipherTalkServer                    # noqa: E402
from ciphertalk.setup_server import make_auditor_key, make_tls_cert  # noqa: E402

PW = "Timing-pass-2026"


def main():
    tmp = tempfile.mkdtemp(prefix="ct_timing_")
    data = os.path.join(tmp, "server_data")
    os.makedirs(data)
    make_tls_cert(data)
    with open(os.path.join(data, "server_secrets.json"), "w") as fh:
        json.dump({k: cu.b64e(os.urandom(32)) for k in ("data_key", "pseudo_key", "integrity_key")}, fh)
    make_auditor_key(data, tmp, "timing-auditor-pass")
    import contextlib, io
    with contextlib.redirect_stdout(io.StringIO()):
        srv = CipherTalkServer(("127.0.0.1", 0), data)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def user(name):
        c = ClientCore("127.0.0.1", port, os.path.join(data, "tls_cert.pem"), os.path.join(tmp, name))
        c.connect()
        with contextlib.redirect_stdout(io.StringIO()):
            c.register(name, PW, "", consent=True)
            c.login(name, PW)
        return c

    alice, bob = user("alice"), user("bob")
    text_times = []
    for i in range(8):                   # 5 requests per round, 8 rounds < 30 / 10 s
        t = time.perf_counter()
        alice.send_text("bob", f"timing message {i}")
        assert bob.fetch_inbox()[0]["status"] == "verified"
        text_times.append(time.perf_counter() - t)
    time.sleep(10)
    path = os.path.join(tmp, "big.bin")
    with open(path, "wb") as fh:
        fh.write(os.urandom(512 * 1024))
    file_times = []
    for _ in range(4):
        t = time.perf_counter()
        alice.send_file("bob", path)
        assert bob.fetch_inbox()[0]["status"] == "verified"
        file_times.append(time.perf_counter() - t)
    c = ClientCore("127.0.0.1", port, os.path.join(data, "tls_cert.pem"), os.path.join(tmp, "alice"))
    c.connect()
    t = time.perf_counter()
    c.login("alice", PW)
    login = time.perf_counter() - t
    t = time.perf_counter()
    cu.hash_password(PW)
    one_scrypt = time.perf_counter() - t

    print(f"text send -> verified display : median {statistics.median(text_times)*1000:.0f} ms, "
          f"max {max(text_times)*1000:.0f} ms (n={len(text_times)})")
    print(f"512 KB file send -> saved     : median {statistics.median(file_times)*1000:.0f} ms, "
          f"max {max(file_times)*1000:.0f} ms (n={len(file_times)})")
    print(f"login (server scrypt + client key unlock): {login*1000:.0f} ms")
    print(f"one scrypt hash (N=2^15, r=8, p=1)       : {one_scrypt*1000:.0f} ms")
    srv.shutdown()


if __name__ == "__main__":
    main()
