"""A relay between a miner and the hashmaker that logs every Stratum line, for scripts/p2p_hash_miner.sh.

usage: stratum_log.py LISTEN_HOST:PORT TO_HOST:PORT LOG

Each line is logged as `UP|DN <ms> <the line>`. A miner's pool password is not logged."""
import json
import socket
import sys
import threading
import time

host, port = sys.argv[1].rsplit(":", 1)
to_host, to_port = sys.argv[2].rsplit(":", 1)
out = open(sys.argv[3], "a", buffering=1)


def logged(line: bytes) -> str:
    text = line.decode(errors="replace")
    try:
        v = json.loads(text)
    except ValueError:
        return text
    if v.get("method") == "mining.authorize" and len(v.get("params") or []) > 1:
        v["params"][1] = "(not logged)"
        return json.dumps(v)
    return text


def pump(a: socket.socket, b: socket.socket, tag: str) -> None:
    buf = b""
    try:
        while data := a.recv(65536):
            b.sendall(data)
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                out.write(f"{tag} {int(time.time() * 1000)} {logged(line)}\n")
    except OSError:
        pass
    for s in (a, b):
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


listener = socket.create_server((host, int(port)))
while True:
    miner, _ = listener.accept()
    up = socket.create_connection((to_host, int(to_port)))
    threading.Thread(target=pump, args=(miner, up, "UP"), daemon=True).start()
    threading.Thread(target=pump, args=(up, miner, "DN"), daemon=True).start()
