#!/usr/bin/env python3
"""The hub identity vectors (vectors/hub_identity.json), checked and written by a second
implementation: this file shares no code with the Rust crate (its own secp256k1, zbase32 and
statement reader, standard library only).

    scripts/hub_identity_vectors.py            check every case in the file; exit 1 on a mismatch
    scripts/hub_identity_vectors.py --write    write the `cases` again (the keys below; the
                                               `real_node` and `macaroons` parts are kept as they are:
                                               they were made by a Lightning Fork node on regtest and
                                               cannot be made here)

A case: a statement, a signature, the node id a payer was given, the network and hub key of the
offer, the payer's clock, and whether the payer takes it. The Rust test
(crates/xbt402/tests/hub_identity_vectors.rs) must agree on every one."""
import hashlib
import json
import os
import sys

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vectors", "hub_identity.json")
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
ZB32 = "ybndrfg8ejkmcpqxot1uwisza345h769"
PREFIX = b"Lightning Signed Message:"
HEADER = "xbt-stream-hub v1"
MAX_AHEAD = 31 * 86400
LIFE = 30 * 86400


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    lam = (3 * a[0] * a[0] * pow(2 * a[1], -1, P) if a == b else (b[1] - a[1]) * pow(b[0] - a[0], -1, P)) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def mul(k, pt):
    out = None
    while k:
        if k & 1:
            out = add(out, pt)
        pt = add(pt, pt)
        k >>= 1
    return out


def compressed(pt):
    return (bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")).hex()


def digest(msg: bytes) -> int:
    return int.from_bytes(hashlib.sha256(hashlib.sha256(PREFIX + msg).digest()).digest(), "big")


def zb32_encode(b: bytes) -> str:
    bits = "".join(f"{x:08b}" for x in b)
    bits += "0" * (-len(bits) % 5)
    return "".join(ZB32[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))


def zb32_decode(s: str):
    if (len(s) * 5) % 8 or any(c not in ZB32 for c in s):
        return None
    bits = "".join(f"{ZB32.index(c):05b}" for c in s)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def sign(msg: bytes, key: int, high_s=False, header=31) -> str:
    z = digest(msg)
    k = int.from_bytes(hashlib.sha256(key.to_bytes(32, "big") + z.to_bytes(32, "big")).digest(), "big") % N or 1
    R = mul(k, G)
    r = R[0] % N
    s = (z + r * key) * pow(k, -1, N) % N
    rid = (R[1] & 1) | (2 if R[0] >= N else 0)
    if (s > N // 2) != high_s:
        s, rid = N - s, rid ^ 1
    return zb32_encode(bytes([header + rid]) + r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def recover(msg: bytes, signature: str):
    """The signer's key (compressed, hex), or None."""
    raw = zb32_decode(signature)
    if raw is None or len(raw) != 65 or not 31 <= raw[0] <= 34:
        return None
    rid, r, s = raw[0] - 31, int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:], "big")
    if not (0 < r < N and 0 < s < N):
        return None
    x = r + (N if rid & 2 else 0)
    if x >= P:
        return None
    y = pow((pow(x, 3, P) + 7) % P, (P + 1) // 4, P)
    if (y * y - pow(x, 3, P) - 7) % P:
        return None
    if (y & 1) != (rid & 1):
        y = P - y
    rinv = pow(r, -1, N)
    q = add(mul(s * rinv % N, (x, y)), mul(-digest(msg) * rinv % N, G))
    return compressed(q) if q else None


def is_key(h: str) -> bool:
    if len(h) != 66 or h != h.lower() or h[:2] not in ("02", "03"):
        return False
    try:
        x = int(h[2:], 16)
    except ValueError:
        return False
    y2 = (pow(x, 3, P) + 7) % P
    return x < P and pow(y2, (P - 1) // 2, P) == 1


def read(text: str):
    """(network, payto, until) of a statement, or None."""
    lines = text.split("\n")
    if len(text) > 512 or len(lines) != 4 or lines[0] != HEADER:
        return None
    out = []
    for line, key in zip(lines[1:], ("network", "payto", "until")):
        if not line.startswith(key + "="):
            return None
        out.append(line[len(key) + 1:])
    net, payto, until = out
    if not net or any(not 33 <= ord(c) <= 126 for c in net) or not is_key(payto):
        return None
    if not until.isascii() or not until.isdigit() or len(until) > 12 or (len(until) > 1 and until[0] == "0"):
        return None
    return net, payto, int(until)


def takes(c) -> bool:
    """Whether a payer takes the statement of case `c`."""
    st = read(c["statement"])
    if st is None or not is_key(c["nodeId"]):
        return False
    if recover(c["statement"].encode(), c["signature"]) != c["nodeId"]:
        return False
    return st[0] == c["network"] and st[1] == c["payto"] and c["now"] < st[2] <= c["now"] + MAX_AHEAD


def cases():
    node, other, hub, hub2 = 0x07 * (2**256 // 255) % N, 0x08 * (2**256 // 255) % N, 0x09 * (2**256 // 255) % N, 0x0A * (2**256 // 255) % N
    node_id, other_id, payto, payto2 = (compressed(mul(k, G)) for k in (node, other, hub, hub2))
    net, now = "bip122:3c0c503450c38384109fcb6f351b349c", 1_790_000_000
    until = now + LIFE

    def text(network=net, pay=payto, to=until):
        return f"{HEADER}\nnetwork={network}\npayto={pay}\nuntil={to}"
    t = text()
    s = sign(t.encode(), node)
    out = []

    def case(name, ok, **kw):
        c = {"name": name, "statement": t, "signature": s, "nodeId": node_id, "network": net, "payto": payto, "now": now}
        c.update(kw)
        c["ok"] = ok
        out.append(c)
    case("the node's statement for this hub", True)
    case("its last second", True, now=until - 1)
    case("run out", False, now=until)
    case("run out long ago", False, now=until + 10 * 86400)
    far = text(to=now + MAX_AHEAD + 1)
    case("signed for longer than a payer takes", False, statement=far, signature=sign(far.encode(), node))
    edge = text(to=now + MAX_AHEAD)
    case("signed for the longest a payer takes", True, statement=edge, signature=sign(edge.encode(), node))
    years = text(to=now + 3650 * 86400)
    case("signed for ten years", False, statement=years, signature=sign(years.encode(), node))
    case("one byte of the text changed (until)", False, statement=t[:-1] + ("1" if t[-1] != "1" else "2"))
    case("one byte of the text changed (payto)", False, statement=t.replace(payto, payto[:-1] + ("0" if payto[-1] != "0" else "1")))
    case("one character of the signature changed", False, signature=s[:50] + ("y" if s[50] != "y" else "b") + s[51:])
    case("the signature cut short", False, signature=s[:-1])
    case("a signature in upper case", False, signature=s.upper())
    case("another node was named", False, nodeId=other_id)
    case("another node signed, and the hub claims the first", False, signature=sign(t.encode(), other))
    case("another node signed and is named: it is that node's hub", True, signature=sign(t.encode(), other), nodeId=other_id)
    case("the offer is on another network", False, network="bip122:000000000019d6689c085ae165831e93")
    case("the offer pays another hub key", False, payto=payto2)
    t2 = text(pay=payto2)
    case("the node's statement for its other hub, shown by this one", False, statement=t2, signature=sign(t2.encode(), node))
    nl = t + "\n"
    case("a line break after the last line, signed", False, statement=nl, signature=sign(nl.encode(), node))
    extra = t + "\nuntil=9999999999"
    case("a fifth line, signed", False, statement=extra, signature=sign(extra.encode(), node))
    v2 = t.replace("v1", "v2")
    case("another version, signed", False, statement=v2, signature=sign(v2.encode(), node))
    up = t.replace(payto, payto.upper())
    case("the hub key in upper case, signed", False, statement=up, signature=sign(up.encode(), node))
    zero = text(to="0" + str(until))
    case("until with a leading zero, signed", False, statement=zero, signature=sign(zero.encode(), node))
    case("a node id in upper case", False, nodeId=node_id.upper())
    case("a Bitcoin-message header byte (27) in place of 31", False, signature=sign(t.encode(), node, header=27))
    case("the high-s form of the same signature: the same key signed it", True, signature=sign(t.encode(), node, high_s=True))
    return out


def main():
    doc = json.load(open(PATH)) if os.path.exists(PATH) else {}
    if "--write" in sys.argv:
        doc["cases"] = cases()
        with open(PATH, "w") as f:
            json.dump(doc, f, indent=1)
            f.write("\n")
    bad = [c["name"] for c in doc["cases"] if takes(c) != c["ok"]]
    real = doc["real_node"]
    for msg, sig in ((real["statement"], real["signature"]), (real["plain"]["message"], real["plain"]["signature"])):
        if recover(msg.encode(), sig) != real["nodeId"]:
            bad.append("the real node's signature over " + msg[:20])
    c = {"statement": real["statement"], "signature": real["signature"], "nodeId": real["nodeId"], "network": real["network"],
         "payto": real["payto"], "now": real["until"] - 86400}
    if not takes(c) or takes(dict(c, now=real["until"])):
        bad.append("the real node's statement")
    print(f"hub identity vectors: {len(doc['cases'])} cases and the real node's, {'OK' if not bad else 'MISMATCH ' + json.dumps(bad)}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
