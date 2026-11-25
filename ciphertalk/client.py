"""Command-line interface for CipherTalk. The actual work is in client_core.py.

Run:  python -m ciphertalk.client --home alice_laptop
Type 'help' at the prompt to see the commands.
"""

import argparse
import cmd
import datetime
import getpass
import json
import os
import shlex
import sys

from . import protocol as p
from .client_core import ClientCore, ClientError

PRIVACY_NOTICE = """\
--------------------------- CipherTalk privacy notice (v1.0) ---------------------------
What we collect : your username, a salted password hash, your public keys and,
                  ONLY if you choose to give it, an email address (stored encrypted).
Why             : to let you log in and to let other people send you encrypted
                  messages. Email is optional and only used as a contact field.
Messages/files  : end-to-end encrypted on your device. The server cannot read them.
                  They are deleted from the server as soon as they are delivered, or
                  after 7 days if never collected.
Feedback board  : posts are shown under a random alias. Your identity is sealed so
                  that only the appointed auditor can reveal it, and only for a
                  recorded reason (e.g. threats or harassment). Posts expire after 90 days.
Logs            : the server log uses pseudonyms, never your username or content.
Your rights     : 'export' shows all data held about you; 'deleteaccount' erases it.
-----------------------------------------------------------------------------------------"""


def ask_secret(prompt: str) -> str:
    """Hidden input on a real terminal. When input is piped (scripted demos),
    read a line and echo stars so the transcript never shows the secret."""
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    print(prompt, end="", flush=True)
    value = sys.stdin.readline().rstrip("\n")
    print("*" * len(value))
    return value


def ask(prompt: str) -> str:
    print(prompt, end="", flush=True)
    value = sys.stdin.readline().rstrip("\n")
    if not sys.stdin.isatty():
        print(value)          # echo piped input so transcripts read naturally
    return value


def fmt_time(ts: int) -> str:
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


class Shell(cmd.Cmd):
    intro = "CipherTalk secure messenger. Type 'help' for commands, 'quit' to exit."

    def __init__(self, core: ClientCore):
        super().__init__()
        self.core = core
        self.use_rawinput = sys.stdin.isatty()
        self._set_prompt()

    def _set_prompt(self):
        self.prompt = f"ciphertalk({self.core.username or 'guest'})> "

    def onecmd(self, line):
        # One place to turn every error into a friendly message.
        try:
            return super().onecmd(line)
        except (ClientError, p.ProtocolError) as exc:
            print(f"  ! {exc}")
        except ConnectionError:
            print("  ! lost connection to the server")
            return True
        finally:
            self._set_prompt()

    def precmd(self, line):
        if not self.use_rawinput:
            print(line.rstrip("\n"))   # echo piped commands after the prompt
        return line

    def emptyline(self):
        pass

    def default(self, line):
        print(f"  ! unknown command '{line.split()[0]}' - type 'help'")

    def do_privacy(self, _):
        """privacy                  show the privacy notice"""
        print(PRIVACY_NOTICE)

    def do_register(self, arg):
        """register <username>      create a new account on this device"""
        username = arg.strip().lower()
        p.check_username(username)
        print(PRIVACY_NOTICE)
        if ask("Do you accept this notice? (yes/no): ").strip().lower() != "yes":
            print("  Registration cancelled - nothing was stored.")
            return
        pw = ask_secret("Choose a password (10+ chars, not only letters): ")
        if ask_secret("Repeat password: ") != pw:
            print("  ! passwords do not match")
            return
        email = ask("Email (optional, press Enter to skip): ").strip()
        print("  Generating your encryption and signing keys on this device...")
        self.core.register(username, pw, email, consent=True)
        print(f"  Account '{username}' created. You can now 'login {username}'.")

    def do_login(self, arg):
        """login <username>         log in"""
        username = arg.strip().lower()
        pw = ask_secret("Password: ")
        self.core.login(username, pw)
        print(f"  Logged in as {username}. Session expires in 30 minutes.")
        print(f"  Your key fingerprint: {self.core.fingerprint()}")

    def do_logout(self, _):
        """logout                   end the session"""
        self.core.logout()
        print("  Logged out.")

    def do_whoami(self, _):
        """whoami                   show who is logged in"""
        print(f"  {self.core.username or 'not logged in'}")

    def do_send(self, arg):
        """send <user> <message>    send an end-to-end encrypted message"""
        parts = arg.split(maxsplit=1)
        if len(parts) != 2:
            print("  usage: send <user> <message>")
            return
        mid = self.core.send_text(parts[0].lower(), parts[1])
        print(f"  Encrypted, signed and sent (id {mid[:8]}...).")

    def do_sendfile(self, arg):
        """sendfile <user> <path>   send an encrypted file (max 512 KB)"""
        try:
            parts = shlex.split(arg, posix=(os.name != "nt"))
        except ValueError:
            parts = []
        if len(parts) != 2:
            print("  usage: sendfile <user> <path>")
            return
        path = parts[1].strip('"')
        mid = self.core.send_file(parts[0].lower(), path)
        print(f"  File encrypted, signed and sent (id {mid[:8]}...).")

    def do_inbox(self, _):
        """inbox                    fetch, verify and decrypt new messages"""
        msgs = self.core.fetch_inbox()
        if not msgs:
            print("  No new messages.")
            return
        for m in msgs:
            if m["status"] != "verified":
                print(f"  [REJECTED] from {m['from']}: {m['reason']}")
            elif m["kind"] == "text":
                print(f"  [{fmt_time(m['sent_at'])}] {m['from']}: {m['text']}   (signature OK)")
            else:
                print(f"  [{fmt_time(m['sent_at'])}] {m['from']} sent file '{m['filename']}'"
                      f" ({m['size']} bytes, SHA-256 OK) -> {m['saved_to']}")

    def do_fingerprint(self, arg):
        """fingerprint [user]       show a key fingerprint to compare in person"""
        who = arg.strip().lower() or None
        print(f"  {who or self.core.username}: {self.core.fingerprint(who)}")

    def do_post(self, arg):
        """post <text>              post anonymously to the feedback board"""
        r = self.core.board_post(arg)
        print(f"  Posted anonymously as {r['alias']} (post {r['post_id'][:8]}...).")

    def do_board(self, _):
        """board                    read the anonymous feedback board"""
        posts = self.core.board_list()
        if not posts:
            print("  The board is empty.")
        for post in posts:
            flag = "" if post["intact"] else "  [WARNING: post was altered on the server]"
            print(f"  [{fmt_time(post['created_at'])}] {post['alias']}: {post['body']}{flag}")
            print(f"      post id: {post['post_id']}")

    def do_export(self, arg):
        """export                   see all data the server holds about you"""
        data = self.core.export_data()
        shown = dict(data, email=p.mask_email(data["email"]))   # mask on screen
        for k, v in shown.items():
            if k in ("account_created", "consent_given_at"):
                v = fmt_time(v)
            print(f"  {k:26}: {v}")
        path = os.path.join(self.core.home, self.core.username, "my_data_export.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        print(f"  Full copy saved to {path}")

    def do_deleteaccount(self, _):
        """deleteaccount            permanently erase your account and keys"""
        if ask("Type DELETE to confirm: ").strip() != "DELETE":
            print("  Cancelled.")
            return
        pw = ask_secret("Password: ")
        self.core.delete_account(pw)
        print("  Your account, pending messages and local keys have been erased.")

    def do_quit(self, _):
        """quit                     log out and exit"""
        try:
            self.core.logout()
        except Exception:
            pass
        print("  Bye.")
        return True

    do_exit = do_quit
    do_EOF = do_quit


def main():
    ap = argparse.ArgumentParser(description="CipherTalk client")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5443)
    ap.add_argument("--cert", default="server_cert.pem", help="server certificate to trust")
    ap.add_argument("--home", default=".ciphertalk", help="where this device keeps its keys")
    args = ap.parse_args()
    core = ClientCore(args.host, args.port, args.cert, args.home)
    try:
        core.connect()
    except (ClientError, OSError) as exc:
        raise SystemExit(f"Cannot connect: {exc}")
    print(f"Connected to {args.host}:{args.port} over TLS 1.3 (certificate verified).")
    try:
        Shell(core).cmdloop()
    finally:
        core.close()


if __name__ == "__main__":
    main()
