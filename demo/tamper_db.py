"""Integrity demo: edits the server database directly, like an attacker with
access to the SQLite file.

  python demo/tamper_db.py message   flip one bit in every stored message
  python demo/tamper_db.py replay    re-insert a copy of the last delivered message
  python demo/tamper_db.py log       disguise ACCOUNT_LOCKED log entries
  python demo/tamper_db.py logtail   delete the newest audit log entry
  python demo/tamper_db.py key bob   replace bob's public encryption key
"""

import base64
import json
import os
import sqlite3
import sys
import time

DB = os.path.join("server_data", "ciphertalk.db")
SAVED = "last_envelope.json"


def main():
    con = sqlite3.connect(DB)
    what = sys.argv[1] if len(sys.argv) > 1 else ""
    if what == "save":
        row = con.execute("SELECT envelope FROM messages ORDER BY stored_at DESC").fetchone()
        with open(SAVED, "w") as fh:
            fh.write(row[0])
        print("[attacker] copied a stored message envelope for later replay")
    elif what == "message":
        rows = con.execute("SELECT msg_id, envelope FROM messages").fetchall()
        for mid, envelope in rows:
            e = json.loads(envelope)
            ct = bytearray(base64.b64decode(e["box"]["ct"]))
            ct[5] ^= 0x01
            e["box"]["ct"] = base64.b64encode(bytes(ct)).decode()
            con.execute("UPDATE messages SET envelope=? WHERE msg_id=?", (json.dumps(e), mid))
        print(f"[attacker] flipped 1 bit of ciphertext in {len(rows)} stored message(s)")
    elif what == "replay":
        with open(SAVED) as fh:
            e = json.loads(fh.read())
        h = e["header"]
        con.execute("INSERT INTO messages VALUES (?,?,?,?,?)",
                    (h["msg_id"], h["sender"], h["recipient"], json.dumps(e), int(time.time())))
        print(f"[attacker] re-inserted already-delivered message {h['msg_id'][:8]}...")
    elif what == "log":
        n = con.execute("UPDATE audit_log SET action='LOGIN_FAILED', detail=''"
                        " WHERE action='ACCOUNT_LOCKED'").rowcount
        print(f"[attacker] disguised {n} ACCOUNT_LOCKED entr{'y' if n == 1 else 'ies'}"
              " as ordinary failed logins to hide a brute-force attack")
    elif what == "logtail":
        seq = con.execute("SELECT MAX(seq) FROM audit_log").fetchone()[0]
        con.execute("DELETE FROM audit_log WHERE seq=?", (seq,))
        print(f"[attacker] deleted the newest audit log entry (#{seq})")
    elif what == "key":
        con.execute("UPDATE users SET enc_pub=? WHERE username=?", (os.urandom(32), sys.argv[2]))
        print(f"[attacker] swapped {sys.argv[2]}'s public key for one the attacker controls")
    else:
        print(__doc__)
        return
    con.commit()


if __name__ == "__main__":
    main()
