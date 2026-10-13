#!/usr/bin/env python3
"""The lottery draw of docs/TICKETS.md, section 9, written a second time: the reference that
`vectors/lottery_vectors.json` was made with and that the lab driver (drive.py) plays buyer and
seller with. Standard library only, no node involved.

    c[n]  = the seller's seed;  c[i-1] = sha256(c[i]);  c[0] is the anchor
    piece = sha256("lottery/0/piece" | seq:8 | req:32 | kind:1 | k:8 | amount_msat:8 | win_msat:8)
    d     = sha256("lottery/0/draw" | len(session):1 | session | i:8 | c[i]:32 | b:32 | piece:32)
    win   = uint64(d[0..8]) < floor(2^64 * amount_msat / win_msat)

Integers are big-endian. The Rust side is crates/xbt402/src/lottery.rs, whose test
`the_vectors_file_is_what_this_module_computes` reads the same file.

    draw.py check [file]      recompute every vector of the file (default: the one in the tree)
    draw.py vectors           print the vectors file, from fixed inputs
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
from typing import Any

DRAW_TAG = b"lottery/0/draw"
PIECE_TAG = b"lottery/0/piece"
KINDS = {"request": 0, "bytes": 1, "second": 2}
MAX_REVEAL_STEPS = 4096
RECEIPT_TAG = "xbt402/lottery-receipt/v0"
RECEIPT_FIELDS = ("scheme", "session", "seq", "drawn", "servedMsat", "wonMsat", "paidMsat", "charged", "req", "status", "bodyHash")
VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "vectors", "lottery_vectors.json")


def sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def hash_down(v: bytes, steps: int) -> bytes:
    for _ in range(steps):
        v = sha(v)
    return v


def threshold(amount_msat: int, win_msat: int) -> int:
    """The win test's limit. A piece priced at a win or more is not a draw."""
    if not 0 < amount_msat < win_msat:
        raise ValueError("a draw is for a price above nothing and below one win")
    return (amount_msat << 64) // win_msat


def piece_digest(seq: int, req: bytes, kind: str, k: int, amount_msat: int, win_msat: int) -> bytes:
    assert len(req) == 32
    return sha(PIECE_TAG + seq.to_bytes(8, "big") + req + bytes([KINDS[kind]]) + k.to_bytes(8, "big") + amount_msat.to_bytes(8, "big") + win_msat.to_bytes(8, "big"))


def draw_digest(session: str, draw: int, chain_value: bytes, value: bytes, piece: bytes) -> bytes:
    s = session.encode()
    assert 0 < len(s) <= 64 and len(chain_value) == len(value) == len(piece) == 32
    return sha(DRAW_TAG + bytes([len(s)]) + s + draw.to_bytes(8, "big") + chain_value + value + piece)


def wins(d: bytes, amount_msat: int, win_msat: int) -> bool:
    return int.from_bytes(d[:8], "big") < threshold(amount_msat, win_msat)


class Chain:
    """The seller's chain, whole in memory: c[0..n]."""

    def __init__(self, n: int, seed: bytes | None = None) -> None:
        self.n = n
        self.seed = seed or os.urandom(32)
        vals = [self.seed]
        for _ in range(n):
            vals.append(sha(vals[-1]))
        self.c = vals[::-1]
        self.anchor = self.c[0]

    def value(self, i: int) -> bytes:
        if not 1 <= i <= self.n:
            raise IndexError(i)
        return self.c[i]


class BuyerView:
    """The buyer's side: the last chain value it checked and its index."""

    def __init__(self, anchor: bytes) -> None:
        self.last, self.at = anchor, 0

    def accept(self, reveal: bytes, drawn: int) -> list[bytes] | None:
        """c[at+1..drawn] if `reveal` is c[drawn], else None."""
        steps = drawn - self.at
        if steps < 1 or steps > MAX_REVEAL_STEPS:
            return None
        vals = [reveal]
        for _ in range(steps - 1):
            vals.append(sha(vals[-1]))
        if sha(vals[-1]) != self.last:
            return None
        self.last, self.at = reveal, drawn
        return vals[::-1]


def request_auth(key: bytes, session: str, seq: int, req: str) -> str:
    return hmac.new(key, "|".join(("lottery/auth", session, str(seq), req)).encode(), hashlib.sha256).hexdigest()


def py_str(v: Any) -> str:
    return "" if v is None else str(v)


def receipt_message(r: dict[str, Any]) -> bytes:
    t = sha(RECEIPT_TAG.encode())
    h = hashlib.sha256(t + t)
    for k in RECEIPT_FIELDS:
        x = py_str(r.get(k)).encode()
        h.update(len(x).to_bytes(8, "little") + x)
    return h.digest()


def luck_cap_msat(expect_msat: int, win_msat: int, z_tenths: int = 31) -> int:
    import math

    return expect_msat + math.isqrt(expect_msat * win_msat) * z_tenths // 10 + win_msat


def make_vectors() -> dict[str, Any]:
    def fixed(label: str) -> bytes:
        return sha(("lottery vectors: " + label).encode())

    chains = []
    for label, n, picks in (("chain a", 5, (1, 2, 5)), ("chain b", 1024, (1, 1023, 1024)), ("chain c", 2500, (1, 1024, 1025, 2047, 2048, 2500))):
        ch = Chain(n, fixed(label))
        chains.append({"seed": ch.seed.hex(), "len": n, "anchor": ch.anchor.hex(), "values": {str(i): ch.value(i).hex() for i in picks}})
    thresholds = [{"amountMsat": str(a), "winMsat": str(w), "threshold": str(threshold(a, w))}
                  for a, w in ((1, 2), (100, 64_000), (2_000, 64_000), (24_000, 64_000), (1, 1_000_000), (999_999, 1_000_000), (1, 3), (2**64 - 2, 2**64 - 1))]
    ch = Chain(64, fixed("draws"))
    draws = []
    i = 0
    # at each price, three draws that win and three that lose: the value of each is the first of a fixed
    # series that gives the wanted result
    for amount, win in ((100, 64_000), (16_000, 64_000), (48_000, 64_000), (999, 1_000)):
        for want in (True, False, True, False, True, False):
            i += 1
            kind = ("request", "bytes", "second")[i % 3]
            seq, k = i // 4, i % 5
            req = fixed(f"req {seq}")
            p = piece_digest(seq, req, kind, k, amount, win)
            t = 0
            while True:
                value = fixed(f"value {i}.{t}")
                d = draw_digest("vec-session", i, ch.value(i), value, p)
                if wins(d, amount, win) == want:
                    break
                t += 1
            draws.append({"session": "vec-session", "draw": i, "chainValue": ch.value(i).hex(), "value": value.hex(), "seq": seq, "kind": kind, "k": k,
                          "req": req.hex(), "amountMsat": str(amount), "winMsat": str(win), "piece": p.hex(), "d": d.hex(), "win": want})
    key, req = fixed("key"), fixed("req").hex()
    receipt = {"scheme": "lottery", "session": "vec-session", "seq": 7, "drawn": 12, "servedMsat": "1200", "wonMsat": "64000", "paidMsat": "64000",
               "charged": "100", "req": req, "status": 200, "bodyHash": fixed("body").hex()}
    return {"about": "Test vectors of the lottery draw (docs/TICKETS.md, section 9). Made by scripts/lottery/draw.py from fixed inputs; "
                     "checked by that script and by crates/xbt402/src/lottery.rs.",
            "chains": chains, "thresholds": thresholds, "draws": draws,
            "auth": {"key": key.hex(), "session": "vec-session", "seq": 7, "req": req, "auth": request_auth(key, "vec-session", 7, req)},
            "receipt": {"fields": receipt, "message": receipt_message(receipt).hex()}}


def check(path: str) -> int:
    with open(path, encoding="utf-8") as f:
        v = json.load(f)
    n = 0
    for c in v["chains"]:
        ch = Chain(c["len"], bytes.fromhex(c["seed"]))
        assert ch.anchor.hex() == c["anchor"], "anchor"
        for i, want in c["values"].items():
            assert ch.value(int(i)).hex() == want, f"c[{i}]"
            view = BuyerView(ch.anchor)
            assert view.accept(ch.value(int(i)), int(i)) is not None or int(i) > MAX_REVEAL_STEPS
            n += 1
    for t in v["thresholds"]:
        assert str(threshold(int(t["amountMsat"]), int(t["winMsat"]))) == t["threshold"], t
        n += 1
    for d in v["draws"]:
        a, w = int(d["amountMsat"]), int(d["winMsat"])
        p = piece_digest(d["seq"], bytes.fromhex(d["req"]), d["kind"], d["k"], a, w)
        assert p.hex() == d["piece"], "piece"
        dg = draw_digest(d["session"], d["draw"], bytes.fromhex(d["chainValue"]), bytes.fromhex(d["value"]), p)
        assert dg.hex() == d["d"] and wins(dg, a, w) == d["win"], "draw"
        n += 1
    a = v["auth"]
    assert request_auth(bytes.fromhex(a["key"]), a["session"], a["seq"], a["req"]) == a["auth"], "auth"
    assert receipt_message(v["receipt"]["fields"]).hex() == v["receipt"]["message"], "receipt"
    assert v == make_vectors(), "the file is not what make_vectors() gives"
    print(f"lottery vectors: {n + 2} checked, OK")
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    if cmd == "vectors":
        print(json.dumps(make_vectors(), indent=1))
    elif cmd == "check":
        sys.exit(check(sys.argv[2] if len(sys.argv) > 2 else VECTORS))
    else:
        sys.exit(__doc__)
