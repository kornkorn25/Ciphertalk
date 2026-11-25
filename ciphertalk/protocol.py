"""Wire format and input validation shared by client and server.

Each request/response is one JSON object sent as a frame:
[4-byte big-endian length][UTF-8 JSON]. MAX_FRAME caps the length so a
client cannot make the server allocate huge buffers.
"""

import json
import re
import struct

PROTOCOL_VERSION = 1

MAX_FRAME = 2 * 1024 * 1024        # 2 MB per frame
MAX_TEXT_LEN = 4000                # characters in a chat message / board post
MAX_FILE_BYTES = 512 * 1024        # 512 KB per shared file
CLOCK_SKEW_SECONDS = 300           # messages older/newer than 5 min are refused

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
FILENAME_RE = re.compile(r"^[A-Za-z0-9._ -]{1,100}$")
HEX32_RE = re.compile(r"^[0-9a-f]{32}$")


class ProtocolError(Exception):
    """Bad framing, oversized data, or a field that fails validation."""


# Framing

def _recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf.extend(chunk)
    return bytes(buf)


def send_frame(sock, obj: dict) -> None:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_FRAME:
        raise ProtocolError("frame too large")
    sock.sendall(struct.pack(">I", len(body)) + body)


def recv_frame(sock) -> dict:
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    if length > MAX_FRAME:
        raise ProtocolError("frame too large")
    try:
        obj = json.loads(_recv_exact(sock, length).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("frame is not valid JSON") from exc
    if not isinstance(obj, dict):
        raise ProtocolError("frame must be a JSON object")
    return obj


# Field validators - used on BOTH sides. The server never trusts the client,
# and the client never trusts what the server hands back.

def check_username(value) -> str:
    if not isinstance(value, str) or not USERNAME_RE.match(value):
        raise ProtocolError("username must be 3-20 chars: a-z, 0-9 or _")
    return value


def check_password(value) -> str:
    if not isinstance(value, str) or not (10 <= len(value) <= 128):
        raise ProtocolError("password must be 10-128 characters")
    if value.isalpha() or value.isdigit():
        raise ProtocolError("password must mix letters with digits or symbols")
    return value


def check_email(value) -> str:
    """Email is optional. Empty string means 'not provided'."""
    if value in (None, ""):
        return ""
    if not isinstance(value, str) or not EMAIL_RE.match(value):
        raise ProtocolError("email address is not valid")
    return value


def check_text(value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProtocolError("message text is empty")
    if len(value) > MAX_TEXT_LEN:
        raise ProtocolError(f"message is longer than {MAX_TEXT_LEN} characters")
    # Strip C0 and C1 control characters (except newline/tab), DEL, and
    # Unicode bidi overrides. These could inject terminal escape sequences or
    # make text display in a different order than it was written.
    return "".join(ch for ch in value if ch in "\n\t" or _printable(ch))


def _printable(ch: str) -> bool:
    o = ord(ch)
    if o < 32 or 0x7F <= o <= 0x9F:
        return False
    return ch not in BIDI_CONTROLS


BIDI_CONTROLS = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f")
WINDOWS_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                    *(f"lpt{i}" for i in range(1, 10))}


def check_filename(value) -> str:
    """Only plain names. Blocks '../../etc/passwd' style path traversal and
    names Windows treats specially (CON, NUL.txt, trailing dots/spaces)."""
    if not isinstance(value, str) or not FILENAME_RE.match(value) or value.startswith("."):
        raise ProtocolError("file name contains characters that are not allowed")
    if value.endswith((".", " ")) or value.split(".")[0].strip().lower() in WINDOWS_RESERVED:
        raise ProtocolError("file name is reserved on Windows")
    return value


def check_msg_id(value) -> str:
    if not isinstance(value, str) or not HEX32_RE.match(value):
        raise ProtocolError("message id must be 32 lowercase hex characters")
    return value


def mask_email(email: str) -> str:
    """'somchai.k@gmail.com' -> 's*******k@g****.com' for display."""
    if not email or "@" not in email:
        return "(none)"
    local, domain = email.split("@", 1)
    name, _, tld = domain.rpartition(".")
    m_local = local[0] + "*" * max(len(local) - 2, 1) + (local[-1] if len(local) > 1 else "")
    m_name = (name[0] + "*" * max(len(name) - 1, 1)) if name else "*"
    return f"{m_local}@{m_name}.{tld}"
