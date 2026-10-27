"""A TLS front for a gateway on a LAN, for a rehearsal between machines: the gateway listens on
loopback and speaks plain HTTP; this terminates TLS on a LAN address and passes the bytes on.
The hashtaker's wallet pins this certificate (`tickets.seller_tls` with `cert_sha256`). Not for the
internet: a public seller runs a real reverse proxy with a real certificate.

    tls_front.py LISTEN_HOST:PORT TARGET_HOST:PORT CERT KEY
"""
import socket
import ssl
import sys
import threading


def pump(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def serve(conn, ctx, target):
    try:
        t = ctx.wrap_socket(conn, server_side=True)
    except (ssl.SSLError, OSError):
        conn.close()
        return
    try:
        up = socket.create_connection(target, timeout=10)
        up.settimeout(None)
    except OSError:
        t.close()
        return
    threading.Thread(target=pump, args=(t, up), daemon=True).start()
    pump(up, t)


def main():
    listen, target, cert, key = sys.argv[1:5]
    lh, lp = listen.rsplit(":", 1)
    th, tp = target.rsplit(":", 1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    s = socket.create_server((lh, int(lp)))
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c, ctx, (th, int(tp))), daemon=True).start()


if __name__ == "__main__":
    main()
