# CipherTalk

A command-line messenger with end-to-end encryption, plus an anonymous feedback board.
Only an offline auditor can find out who wrote a post, and every reveal needs a written reason.

SEC-201 Data Privacy, Security, and Integrity, CMKL University, Fall 2026.

## Team

- Pattakorn Kiatsupapong
- Ronnapee Bunnag
- Suppawat Rattanalaor

## Install

You need Python 3.11 or newer. Run every command from this folder (the one with `requirements.txt`).

```
pip install -r requirements.txt
```

## Run

Terminal 1 (server). `setup_server` only needs to run once. It asks you to choose an auditor
passphrase (at least 12 characters) and creates `server_cert.pem`, which the clients use.

```
python -m ciphertalk.setup_server
python -m ciphertalk.server
```

The server listens on `127.0.0.1:5443`.

Terminals 2 and 3 (two users). Each `--home` folder works like a separate device.

```
python -m ciphertalk.client --home bob_laptop
python -m ciphertalk.client --home alice_laptop
```

At the prompt, type `help` to see the commands. `register` asks you to accept the privacy
notice, choose a password and (optionally) give an email. A typical run:

```
register bob             (in Bob's terminal, then: login bob)
register alice           (in Alice's terminal, then: login alice)
send bob Hello Bob
sendfile bob notes.txt
post Anonymous feedback here
inbox                    (in Bob's terminal)
board
```

Auditor tool (offline):

```
python -m ciphertalk.auditor verify-log
python -m ciphertalk.auditor reveal <post_id> --reason "Case SA-2026-014: threat to staff"
```

## Tests and demo

```
python -m pytest -v tests        # 33 tests
python demo/run_demo.py          # whole demo including the attacks, output goes to demo_output/
python demo/timing.py            # speed measurements
```

`run_demo.py` uses port 5443, so stop your own server before running it.

## Files

| Path | Contents |
|---|---|
| `ciphertalk/crypto_utils.py` | All cryptography (X25519, HKDF, AES-256-GCM, Ed25519, scrypt, HMAC) |
| `ciphertalk/protocol.py` | Message framing and input validation |
| `ciphertalk/store.py` | SQLite storage, encryption at rest, row MACs, audit log, retention |
| `ciphertalk/server.py` | Server |
| `ciphertalk/client_core.py` | Client logic: keys, key pinning, encrypt, sign, verify, decrypt |
| `ciphertalk/client.py` | Command-line interface |
| `ciphertalk/setup_server.py` | Creates the certificate, server secrets and auditor key |
| `ciphertalk/auditor.py` | Audit log check and identity reveal |
| `tests/` | Automated tests |
| `demo/` | Demo script and the attack tools (`sniff_proxy.py`, `tamper_db.py`) |

The folders created at run time (`server_data/`, `auditor_vault/`, the `--home` folders)
contain keys and secrets, so `.gitignore` keeps them out of the repository.
