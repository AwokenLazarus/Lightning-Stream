"""A probe run in a throwaway python container by datum_regtest.py, either in the renter's network namespace
(`--network container:<renter>`, where the Stream Gateway's stratum and API are) or on the app's network
(where they must not be). Standard library only. Prints one JSON line.
    datum_probe.py job HOST STRATUM_PORT API_PORT    a miner's first job, then the API's /xbt/job on it
    datum_probe.py connect HOST PORT                 does a TCP connection open
    datum_probe.py forward PORT HOST HOSTPORT        forward 127.0.0.1:PORT to HOST:HOSTPORT, until stopped (the
                                                     lab's relay on the renter's loopback: its Nostr client takes
                                                     plain ws:// to loopback only)
"""
import json
import math
import socket
import sys
import threading
import time


def pot_of(d):
    """The share's bits past 32 at difficulty d, as the renter reckons them (xbt-hashlink blind::pot_of)."""
    p = round(d * 65536.0 / 65535.0)
    return 0 if p < 1 else int(math.floor(math.log2(p)))


def get(host, port, path):
    s = socket.create_connection((host, port), 5)
    s.settimeout(5)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode())
    out = b""
    while True:
        b = s.recv(65536)
        if not b:
            break
        out += b
    head, _, body = out.partition(b"\r\n\r\n")
    return int(head.split()[1]), body.decode("utf-8", "replace")


def job(host, st, api):
    s = socket.create_connection((host, st), 10)
    s.settimeout(30)
    s.sendall((json.dumps({"id": 1, "method": "mining.subscribe", "params": ["umbrel-datum-probe/0"]}) + "\n"
               + json.dumps({"id": 2, "method": "mining.authorize", "params": ["probe", "x"]}) + "\n").encode())
    f = s.makefile("r")
    d, t0 = 1.0, time.time()
    while time.time() - t0 < 30:
        line = f.readline()
        if not line:
            break
        try:
            v = json.loads(line)
        except ValueError:
            continue
        if v.get("method") == "mining.set_difficulty":
            d = float(v["params"][0])
        elif v.get("method") == "mining.notify":
            p = v["params"]
            pot = pot_of(d)
            code, body = 0, ""
            # the coinbases may still be being written when the notify goes out (the renter retries too)
            for _ in range(10):
                code, body = get(host, api, f"/xbt/job?id={p[0]}&pot={pot}")
                if code != 404:
                    break
                time.sleep(0.3)
            try:
                opened = json.loads(body)
            except ValueError:
                opened = body[:300]
            return {"notify": {"job": p[0], "prevhash": p[1], "coinb1": p[2]}, "difficulty": d, "pot": pot, "code": code, "opened": opened}
    return {"error": "no job within 30 s"}


def connect(host, port):
    try:
        socket.create_connection((host, port), 3).close()
        return {"open": True}
    except OSError as e:
        return {"open": False, "error": f"{type(e).__name__}: {e}"}


def forward(port, host, to):
    def pump(x, y):
        try:
            while True:
                b = x.recv(65536)
                if not b:
                    break
                y.sendall(b)
        except OSError:
            pass
        for z in (x, y):
            try:
                z.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    srv = socket.create_server(("127.0.0.1", port))
    print(json.dumps({"forwarding": port}), flush=True)
    while True:
        a, _ = srv.accept()
        try:
            b = socket.create_connection((host, to), 5)
        except OSError:
            a.close()
            continue
        threading.Thread(target=pump, args=(a, b), daemon=True).start()
        threading.Thread(target=pump, args=(b, a), daemon=True).start()


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[0] == "forward":
        forward(int(a[1]), a[2], int(a[3]))
    try:
        r = job(a[1], int(a[2]), int(a[3])) if a[0] == "job" else connect(a[1], int(a[2]))
    except OSError as e:
        r = {"error": f"{type(e).__name__}: {e}"}
    print(json.dumps(r))
