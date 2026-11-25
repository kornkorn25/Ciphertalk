"""Eavesdropping demo: a plain TCP relay between client and server that records
all traffic and checks whether given words appear in it.

  python demo/sniff_proxy.py --listen 6000 --target 5443 --look-for "secret words"
  python -m ciphertalk.client --port 6000 ...
"""

import argparse
import socket
import threading


def pipe(src, dst, store):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            store.extend(data)
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, default=6000)
    ap.add_argument("--target", type=int, default=5443)
    ap.add_argument("--look-for", action="append", default=[])
    ap.add_argument("--secret", action="append", default=[],
                    help="like --look-for, but the value is never printed (passwords)")
    args = ap.parse_args()

    lsock = socket.socket()
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", args.listen))
    lsock.listen(1)
    print(f"[sniffer] relaying 127.0.0.1:{args.listen} -> 127.0.0.1:{args.target}", flush=True)
    client, _ = lsock.accept()
    upstream = socket.create_connection(("127.0.0.1", args.target))
    captured = bytearray()
    t = threading.Thread(target=pipe, args=(client, upstream, captured))
    t.start()
    pipe(upstream, client, captured)
    t.join()

    print(f"[sniffer] captured {len(captured)} bytes")
    print(f"[sniffer] TLS record header of first packet: {captured[:5].hex(' ')}"
          "  (0x16 0x03 = TLS handshake)")
    print("[sniffer] sample of captured bytes:")
    for off in range(0, 96, 16):
        chunk = captured[600 + off:600 + off + 16]
        print("   " + chunk.hex(" ") + "   " + "".join(chr(b) if 32 <= b < 127 else "." for b in chunk))
    for word in args.look_for:
        found = word.encode() in captured
        print(f"[sniffer] searching for {word!r}: {'FOUND' if found else 'not found'}")
    for word in args.secret:
        found = word.encode() in captured
        print(f"[sniffer] searching for the user's password (value hidden): "
              f"{'FOUND' if found else 'not found'}")


if __name__ == "__main__":
    main()
