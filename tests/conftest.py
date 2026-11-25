"""Test fixtures: each test gets a new server on a random port in a temp folder."""

import json
import os
import socket
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ciphertalk import crypto_utils as cu                     # noqa: E402
from ciphertalk.client_core import ClientCore                 # noqa: E402
from ciphertalk.server import CipherTalkServer                # noqa: E402
from ciphertalk.setup_server import make_auditor_key, make_tls_cert  # noqa: E402

AUDITOR_PASS = "auditor-test-passphrase-01"
PASSWORD = "Str0ng-pass-123"


@pytest.fixture
def env(tmp_path):
    data = tmp_path / "server_data"
    vault = tmp_path / "auditor_vault"
    data.mkdir()
    vault.mkdir()
    make_tls_cert(str(data))
    with open(data / "server_secrets.json", "w") as fh:
        json.dump({k: cu.b64e(os.urandom(32))
                   for k in ("data_key", "pseudo_key", "integrity_key")}, fh)
    make_auditor_key(str(data), str(vault), AUDITOR_PASS)

    srv = CipherTalkServer(("127.0.0.1", 0), str(data))
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    clients = []

    def make_client(name, port_override=None, cafile=None):
        c = ClientCore("127.0.0.1", port_override or port,
                       cafile or str(data / "tls_cert.pem"), str(tmp_path / f"{name}_device"))
        c.connect()
        clients.append(c)
        return c

    def user(name, email=""):
        """Register + log in a user, return the logged-in client."""
        c = make_client(name)
        c.register(name, PASSWORD, email, consent=True)
        c.login(name, PASSWORD)
        return c

    yield {"server": srv, "port": port, "data": data, "vault": vault, "tmp": tmp_path,
           "client": make_client, "user": user}

    for c in clients:
        c.close()
    srv.shutdown()
    srv.server_close()
    srv.store.db.close()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port
