#!/usr/bin/env python3
"""AGP-048 rail=ln on regtest: the Rust signer and MCP pay XBT Lightning invoices through a Lightning
Fork node (lf1) under B2's policy, against lightning-fork-lab (Knots BLAKE2b regtest, lf1, lf2, and a
stock lnd on a SHA-256 regtest). Run by scripts/ln_rail_regtest.sh, which brings the lab up.

  S1  ln_status through the MCP: the only channel is taproot -> not ready
  S2  ln_pay with only a taproot channel -> ln_no_safe_channel, no HTLC
  S3  a unified anchors channel opened from a post-split coin; ln_pay within budget -> SUCCEEDED
  S4  over the daily budget -> denied before any HTLC
  S5  over the human threshold -> needs_human; the human's ed25519 approval (not an MCP tool); paid
  S6  a stock lnd invoice (no feature bit 512) -> refused
  S7  a second signer whose LN node is the stock lnd on the SHA-256 chain -> refused (ln_chain)
  S8  the signature log and the audit log hold every payment and refusal; the ledger is exact
  S9  the MCP surface: 12 tools with XBT_MCP_LN=1, approve is not a tool

Environment: LAB (the lab checkout), OUT (report dir), BIN (the release binaries), RUN (scratch dir).
"""
import hashlib
import json
import os
import socket
import subprocess
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

LAB, OUT, BIN, RUN = (os.environ[k] for k in ("LAB", "OUT", "BIN", "RUN"))
SPLIT = 125  # the regtest stand-in for mainnet's 961,632
REPORT = {"checks": [], "scenarios": {}}
FAILED = []


def check(name, ok, detail=None):
    REPORT["checks"].append({"check": name, "ok": bool(ok), "detail": detail})
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  {json.dumps(detail)[:600]}"), flush=True)
    if not ok:
        FAILED.append(name)


def dc(*args, check_rc=True):
    r = subprocess.run(["docker", "compose", *args], cwd=LAB, capture_output=True, text=True)
    if check_rc and r.returncode != 0:
        raise RuntimeError(f"docker compose {' '.join(args)}: {r.stderr.strip()[:400]}")
    return r.stdout.strip()


def b2b(*a):
    return dc("exec", "-T", "knots-b2b", "bitcoin-cli", "-datadir=/data", "-rpcuser=lab", "-rpcpassword=lab", *a)


def ln(svc, *a):
    out = dc("exec", "-T", svc, "lncli", "--network=regtest", "--rpcserver=127.0.0.1:10009", *a)
    return json.loads(out) if out.startswith(("{", "[")) else out


def mine(n):
    addr = b2b("-rpcwallet=lab", "getnewaddress")
    b2b("-rpcwallet=lab", "generatetoaddress", str(n), addr)
    return int(b2b("getblockcount"))


def wait(what, secs, fn):
    end = time.time() + secs
    while time.time() < end:
        try:
            if fn():
                return
        except Exception:
            pass
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for {what}")


def synced(svc, height=None):
    i = ln(svc, "getinfo")
    return i.get("synced_to_chain") and (height is None or int(i["block_height"]) >= height)


def rpc_sock(path, method, params=None, timeout=120):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(path)
    s.sendall((json.dumps({"id": 1, "method": method, "params": params or {}}) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        c = s.recv(65536)
        if not c:
            break
        buf += c
    s.close()
    r = json.loads(buf)
    if r.get("error"):
        raise RuntimeError(f"signer {method}: {r['error']}")
    return r["result"]


class Mcp:
    """xbt-wallet-mcp over stdio."""

    def __init__(self, env):
        self.p = subprocess.Popen([f"{BIN}/xbt-wallet-mcp", "--stdio"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=open(f"{RUN}/mcp.log", "a"), text=True, env=env)
        self.n = 0
        self.req("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "agp048", "version": "1"}})
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        self.p.stdin.flush()

    def req(self, method, params):
        self.n += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params}) + "\n")
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def tool(self, name, args):
        r = self.req("tools/call", {"name": name, "arguments": args})["result"]
        text = r["content"][0]["text"]
        return json.loads(text) if not r.get("isError") else {"isError": True, "text": text}

    def close(self):
        self.p.stdin.close()
        self.p.wait(10)


def start_signer(root, sock, extra_env, log):
    env = dict(os.environ, **extra_env, B2_SIGNER_SOCK=sock, B2_RPCHOST="127.0.0.1", B2_RPCPORT="34681",
               B2_RPCCOOKIE=f"{RUN}/rpc.cookie", B2_WALLET="agent", B2_HOT_KEYFILE=f"{RUN}/keys/{os.path.basename(root)}.key",
               B2_WATCH_INTERVAL="5")
    p = subprocess.Popen([f"{BIN}/xbt-signer", "--root", root], env=env, stdout=open(log, "a"), stderr=subprocess.STDOUT)
    wait(f"signer {root}", 60, lambda: os.path.exists(sock) and rpc_sock(sock, "health")["ok"])
    return p


def policy(human_pub, allow):
    return {"allowlist": allow, "max_per_tx_sats": 50_000, "daily_budget_sats": 30_000, "weekly_budget_sats": 100_000,
            "per_counterparty_cap_sats": 100_000, "velocity_max": 20, "velocity_window_s": 3600, "human_threshold_sats": 20_000,
            "split_window_s": 0, "human_pubkey": human_pub, "regtest_mine": False, "anchor_interval_s": 3600,
            "ln": {"enabled": True, "split_height": SPLIT, "max_fee_base_sats": 10, "max_fee_ppm": 5000, "timeout_s": 60}}


def fetch(svc, src, dst):
    dc("cp", f"{svc}:{src}", dst)
    os.chmod(dst, 0o600)


def bake(svc, dst):
    ln(svc, "bakemacaroon", "--save_to=/tmp/rail.macaroon", "info:read", "offchain:read", "offchain:write", "onchain:read")
    fetch(svc, "/tmp/rail.macaroon", dst)


def open_channel(*args):
    """lncli openchannel, retried: right after a connect or a new block the peer can answer
    "funding failed due to internal error" (the lab's own scenarios retry too)."""
    tip = int(b2b("getblockcount"))
    wait("lf1/lf2 at the tip", 60, lambda: synced("lf1", tip) and synced("lf2", tip))
    for i in range(6):
        try:
            return ln("lf1", "openchannel", *args)
        except RuntimeError as e:
            if i == 5:
                raise
            print(f"openchannel retry {i + 1}: {str(e)[-120:]}", flush=True)
            time.sleep(5)


def payments(svc):
    return {p["payment_hash"]: p for p in ln(svc, "listpayments", "--include_incomplete").get("payments", [])}


def outpoint_of(svc, sats):
    for u in ln(svc, "listunspent", "--min_confs=1")["utxos"]:
        if int(u["amount_sat"]) == sats:
            return u["outpoint"], int(u["confirmations"])
    raise RuntimeError(f"{svc}: no {sats}-sat coin")


def main():
    os.makedirs(f"{RUN}/keys", exist_ok=True)
    with open(f"{RUN}/rpc.cookie", "w") as f:
        f.write("lab:lab")

    # --- the chain: activation at 20, coins below and above the split --------------------------------
    h = int(b2b("getblockcount"))
    if h < 120:
        mine(120 - h)
    b2b("createwallet", "agent") if "agent" not in b2b("listwallets") else None
    wait("lf1/lf2 synced", 120, lambda: synced("lf1", 120) and synced("lf2", 120))
    wait("lnd-sha synced", 120, lambda: synced("lnd-sha"))
    lf2_pub, sha_pub = ln("lf2", "getinfo")["identity_pubkey"], ln("lnd-sha", "getinfo")["identity_pubkey"]
    lf1_pub = ln("lf1", "getinfo")["identity_pubkey"]
    addr = ln("lf1", "newaddress", "p2wkh")["address"]
    b2b("-rpcwallet=lab", "sendtoaddress", addr, "0.5")
    # a second pre-split coin that stays in lf1's wallet: ln_status must report it
    b2b("-rpcwallet=lab", "sendtoaddress", ln("lf1", "newaddress", "p2wkh")["address"], "0.2")
    hA = mine(1)
    mine(130 - hA)
    addr = ln("lf1", "newaddress", "p2wkh")["address"]
    b2b("-rpcwallet=lab", "sendtoaddress", addr, "1.0")
    hB = mine(1)
    tip = mine(1)
    wait("lf1 sees both coins", 60, lambda: synced("lf1", tip) and len(ln("lf1", "listunspent", "--min_confs=1")["utxos"]) >= 3)
    coinA, _ = outpoint_of("lf1", 50_000_000)
    coinB, _ = outpoint_of("lf1", 100_000_000)
    REPORT["chain"] = {"activation": 20, "split_height": SPLIT, "coin_a_height": hA, "coin_b_height": hB, "lf1": lf1_pub, "lf2": lf2_pub,
                       "lnd_sha": sha_pub, "anchor_101": b2b("getblockhash", "101")}
    print(f"chain: coin A (pre-split) at {hA}, coin B at {hB}, split {SPLIT}", flush=True)

    # --- a taproot channel only (from coin A: the operator's choice; this wallet opens none) -------------
    ln("lf1", "connect", f"{lf2_pub}@lf2:9735")
    tap = open_channel(f"--node_key={lf2_pub}", "--local_amt=400000", "--channel_type=taproot", "--private",
             f"--utxo={coinA}")
    mine(6)
    wait("taproot channel active", 90, lambda: len(ln("lf1", "listchannels", "--active_only")["channels"]) == 1)
    REPORT["taproot_channel"] = tap

    # --- the signer (the agent's) and the MCP ---------------------------------------------------------
    human = Ed25519PrivateKey.generate()
    human_pub = human.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    bake("lf1", f"{RUN}/lf1.macaroon")
    fetch("lf1", "/root/.lnd/tls.cert", f"{RUN}/lf1.tls.cert")
    root = f"{RUN}/wallet"
    os.makedirs(f"{root}/.run", exist_ok=True)
    with open(f"{root}/policy.json", "w") as f:
        json.dump(policy(human_pub, [f"ln:{lf2_pub}", f"ln:{sha_pub}"]), f, indent=2)
    sock = f"{RUN}/signer.sock"
    ln_env = {"B2_LN_REST": "https://127.0.0.1:34691", "B2_LN_MACAROON": f"{RUN}/lf1.macaroon", "B2_LN_TLS_CERT": f"{RUN}/lf1.tls.cert"}
    procs = [start_signer(root, sock, ln_env, f"{RUN}/signer.log")]
    menv = {k: v for k, v in os.environ.items() if not k.startswith("B2_LN")}
    mcp = Mcp(dict(menv, B2_SIGNER_SOCK=sock, XBT_MCP_LN="1"))
    try:
        run(mcp, sock, human, lf2_pub, sha_pub, coinB, procs)
    finally:
        mcp.close()
        for p in procs:
            p.terminate()
            p.wait(10)


def run(mcp, sock, human, lf2_pub, sha_pub, coinB, procs):
    dest = f"ln:{lf2_pub}"

    # S1 / S2: only a taproot channel
    st = mcp.tool("ln_status", {})
    REPORT["scenarios"]["S1_status_taproot_only"] = st
    check("S1 ln_status: chain check ok against our Knots node", st.get("chain_check", {}).get("ok") is True, st.get("chain_check"))
    check("S1 ln_status: the taproot channel is refused, rail not ready",
          st.get("ready") is False and st["channels"][0]["usable"] is False and "taproot" in st["channels"][0]["refused"], st.get("channels"))
    check("S1 ln_status: coin A's remainder (below the split) is reported", len(st.get("presplit_utxos", [])) >= 1, st.get("presplit_utxos"))
    inv1 = ln("lf2", "addinvoice", "--amt=1000", "--memo=coffee")
    r = mcp.tool("ln_pay", {"invoice": inv1["payment_request"], "max_sats": 1100})
    REPORT["scenarios"]["S2_taproot_only"] = r
    h1 = inv1["r_hash"]
    check("S2 taproot-only: refused ln_no_safe_channel", r.get("rule") == "ln_no_safe_channel", r)
    check("S2 no HTLC left lf1", h1 not in payments("lf1"), None)

    # S3: a unified anchors channel from the post-split coin B; pay within budget
    uni = open_channel(f"--node_key={lf2_pub}", "--local_amt=1000000", f"--utxo={coinB}")
    mine(6)
    wait("both channels active", 90, lambda: len(ln("lf1", "listchannels", "--active_only")["channels"]) == 2)
    chans = ln("lf1", "listchannels")["channels"]
    unified = [c for c in chans if c.get("unified_sigs")]
    REPORT["channels"] = [{k: c.get(k) for k in ("scid", "scid_str", "chan_id", "commitment_type", "unified_sigs", "capacity", "private")} for c in chans]
    check("S3 lf1 has one unified anchors channel and one taproot", len(unified) == 1 and "TAPROOT" not in unified[0]["commitment_type"], REPORT["channels"])
    time.sleep(3)
    r = mcp.tool("ln_pay", {"invoice": inv1["payment_request"], "max_sats": 1100, "description": "coffee"})
    for _ in range(5):  # a channel just active can fail its first try while channel_updates settle
        if r.get("rule") != "ln_payment_failed":
            break
        time.sleep(3)
        r = mcp.tool("ln_pay", {"invoice": inv1["payment_request"], "max_sats": 1100, "description": "coffee"})
    REPORT["scenarios"]["S3_within_budget"] = r
    check("S3 within budget: SUCCEEDED through the MCP", r.get("verdict") == "allow" and r.get("status") == "SUCCEEDED", r)
    pre = r.get("preimage", "")
    check("S3 sha256(preimage) is the payment hash", hashlib.sha256(bytes.fromhex(pre or "00")).hexdigest() == h1, pre)
    check("S3 lf2's invoice is SETTLED", ln("lf2", "lookupinvoice", h1)["state"] == "SETTLED", None)
    p1 = payments("lf1").get(h1, {})
    first_hops = {h["route"]["hops"][0]["chan_id"] for h in p1.get("htlcs", []) if h.get("status") == "SUCCEEDED"}
    # lncli prints chan_id as the 32-byte channel id and the numeric SCID as scid (REST's chan_id)
    check("S3 the HTLC left through the unified channel only", first_hops == {unified[0].get("scid", unified[0]["chan_id"])},
          {"hops": list(first_hops), "unified_scid": unified[0].get("scid")})
    charged1 = r.get("charged_sats", 0)

    # S4: over the daily budget (30,000): denied before any HTLC
    inv4 = ln("lf2", "addinvoice", "--amt=29500")
    r = mcp.tool("ln_pay", {"invoice": inv4["payment_request"], "max_sats": 40_000})
    REPORT["scenarios"]["S4_over_budget"] = r
    check("S4 over budget: denied daily_budget", r.get("verdict") == "deny" and r.get("rule") == "daily_budget", r)
    check("S4 no HTLC for it on lf1", inv4["r_hash"] not in payments("lf1"), None)

    # S5: over the human threshold (20,000): needs_human, the human approves on the signer socket
    inv5 = ln("lf2", "addinvoice", "--amt=21000")
    r = mcp.tool("ln_pay", {"invoice": inv5["payment_request"], "max_sats": 22_000})
    REPORT["scenarios"]["S5_needs_human"] = r
    check("S5 over threshold: needs_human", r.get("verdict") == "needs_human" and r.get("approval_token"), r)
    check("S5 nothing sent before the human", inv5["r_hash"] not in payments("lf1"), None)
    no_tool = mcp.tool("approve", {"token": r.get("approval_token")})
    check("S5 approve is not an MCP tool", no_tool.get("isError") and "Unknown tool" in no_tool.get("text", ""), no_tool)
    tok, exp, amt = r["approval_token"], int(r["approval_expires"]), int(r["amount_sats"])
    msg = b"\n".join([b"xbt-agentwallet-approve-v1", tok.encode(), dest.encode(), str(amt).encode(), str(exp).encode()])
    sig = human.sign(msg).hex()
    a = rpc_sock(sock, "approve", {"token": tok, "dest": dest, "amount_sats": amt, "expiry": exp, "signature": sig})
    REPORT["scenarios"]["S5_approve"] = a
    check("S5 the human's signature grants it", a.get("granted") is True and a.get("rail") == "ln", a)
    r = mcp.tool("ln_pay", {"invoice": inv5["payment_request"], "max_sats": 22_000})
    REPORT["scenarios"]["S5_paid"] = r
    check("S5 then paid under the approval", r.get("status") == "SUCCEEDED" and r.get("approved") is True, r)
    check("S5 lf2's invoice is SETTLED", ln("lf2", "lookupinvoice", inv5["r_hash"])["state"] == "SETTLED", None)
    charged5 = r.get("charged_sats", 0)

    # S6: an invoice without bit 512 (stock lnd on the SHA-256 regtest)
    inv6 = ln("lnd-sha", "addinvoice", "--amt=100")
    feats6 = sorted(int(k) for k in ln("lnd-sha", "decodepayreq", inv6["payment_request"]).get("features", {}))
    feats1 = sorted(int(k) for k in ln("lf1", "decodepayreq", inv1["payment_request"]).get("features", {}))
    r = mcp.tool("ln_pay", {"invoice": inv6["payment_request"], "max_sats": 1000})
    REPORT["scenarios"]["S6_no_512"] = {"result": r, "sha_invoice_features": feats6, "xbt_invoice_features": feats1}
    check("S6 the XBT invoice carries 512, the SHA-256 one does not", 512 in feats1 and 512 not in feats6, {"xbt": feats1, "sha": feats6})
    check("S6 no bit 512: refused ln_feature_512", r.get("rule") == "ln_feature_512", r)

    # S7: a signer whose LN node is the stock lnd on the SHA-256 chain
    bake("lnd-sha", f"{RUN}/sha.macaroon")
    fetch("lnd-sha", "/root/.lnd/tls.cert", f"{RUN}/sha.tls.cert")
    root2 = f"{RUN}/wallet-wrong"
    os.makedirs(f"{root2}/.run", exist_ok=True)
    with open(f"{root2}/policy.json", "w") as f:
        json.dump(policy(human.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex(),
                         [f"ln:{lf2_pub}", f"ln:{sha_pub}"]), f)
    sock2 = f"{RUN}/signer-wrong.sock"
    procs.append(start_signer(root2, sock2, {"B2_LN_REST": "https://127.0.0.1:34693", "B2_LN_MACAROON": f"{RUN}/sha.macaroon",
                                             "B2_LN_TLS_CERT": f"{RUN}/sha.tls.cert"}, f"{RUN}/signer-wrong.log"))
    inv7 = ln("lf2", "addinvoice", "--amt=500")
    st7 = rpc_sock(sock2, "ln_status")
    r = rpc_sock(sock2, "ln_pay", {"invoice": inv7["payment_request"], "max_sats": 1000})
    REPORT["scenarios"]["S7_wrong_chain"] = {"status": st7, "pay": r}
    check("S7 wrong-chain backend: ln_status chain check fails", st7.get("chain_check", {}).get("ok") is False, st7.get("chain_check"))
    check("S7 wrong-chain backend: ln_pay refused ln_chain", r.get("rule") == "ln_chain", r)
    check("S7 nothing sent by either node", inv7["r_hash"] not in payments("lnd-sha") and inv7["r_hash"] not in payments("lf1"), None)
    # a pinned certificate that is not the node's: refused at TLS
    procs[-1].terminate()
    procs[-1].wait(10)
    os.remove(sock2) if os.path.exists(sock2) else None
    procs.append(start_signer(root2, sock2, {"B2_LN_REST": "https://127.0.0.1:34691", "B2_LN_MACAROON": f"{RUN}/lf1.macaroon",
                                             "B2_LN_TLS_CERT": f"{RUN}/sha.tls.cert"}, f"{RUN}/signer-wrong.log"))
    r = rpc_sock(sock2, "ln_pay", {"invoice": inv7["payment_request"], "max_sats": 1000})
    REPORT["scenarios"]["S7_wrong_cert"] = r
    check("S7 lf1 behind a certificate that is not the pinned one: refused", r.get("verdict") == "deny" and r.get("rule") in ("ln_backend", "ln_chain"), r)

    # S8: the logs and the ledger
    sigs = rpc_sock(sock, "signatures", {"limit": 1000})
    lnsigs = [s for s in sigs["signatures"] if s["kind"] == "ln_payment"]
    REPORT["scenarios"]["S8_signature_log"] = {"chain_ok": sigs["chain_ok"], "ln_payment": lnsigs}
    check("S8 signature log: one ln_payment per settled payment, sig_sha256 = payment hash",
          sorted(s["sig_sha256"] for s in lnsigs) == sorted([h1, inv5["r_hash"]]), lnsigs)
    check("S8 signature log chain intact", sigs["chain_ok"] is True, sigs.get("chain"))
    check("S8 the approved one is logged under the human's rule",
          any(s["sig_sha256"] == inv5["r_hash"] and s["rule"] == "human:approval_signature" for s in lnsigs), lnsigs)
    ev = rpc_sock(sock, "history", {"limit": 1000})["events"]
    kinds = {}
    for e in ev:
        kinds[e["type"]] = kinds.get(e["type"], 0) + 1
    REPORT["scenarios"]["S8_audit_counts"] = kinds
    check("S8 audit log: 2 settled, refusals and decisions recorded",
          kinds.get("ln_settled") == 2 and kinds.get("ln_refused", 0) >= 2 and kinds.get("decision", 0) >= 3, kinds)
    with open(f"{RUN}/wallet/.run/ledger.json") as f:
        led = json.load(f)["payments"]
    net = sum(p["amount_sats"] for p in led if p["dest"] == dest)
    check("S8 the ledger holds exactly what was charged", net == charged1 + charged5, {"ledger": net, "charged": charged1 + charged5})
    q = rpc_sock(sock, "ln_status")
    REPORT["scenarios"]["S8_final_status"] = q
    check("S8 final ln_status ready, nothing in flight", q.get("ready") is True and q.get("in_flight") == 0, {k: q.get(k) for k in ("ready", "in_flight")})

    # S9: the MCP surface
    names = [t["name"] for t in mcp.req("tools/list", {})["result"]["tools"]]
    REPORT["scenarios"]["S9_tools"] = names
    check("S9 12 tools with XBT_MCP_LN=1 (B2's 10 + ln_pay, ln_status)", len(names) == 12 and names[-2:] == ["ln_pay", "ln_status"], names)
    mcp_plain = Mcp({k: v for k, v in os.environ.items() if not k.startswith(("B2_LN", "XBT_MCP_LN"))} | {"B2_SIGNER_SOCK": sock})
    plain = [t["name"] for t in mcp_plain.req("tools/list", {})["result"]["tools"]]
    hidden = mcp_plain.tool("ln_pay", {"invoice": "x", "max_sats": 1})
    mcp_plain.close()
    check("S9 without XBT_MCP_LN: B2's exact 10, ln_pay unknown", len(plain) == 10 and hidden.get("isError"), {"tools": plain, "ln_pay": hidden})


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # a harness failure is a failure
        check("harness", False, repr(e))
    REPORT["ok"] = not FAILED
    REPORT["failed"] = FAILED
    os.makedirs(OUT, exist_ok=True)
    with open(f"{OUT}/ln_rail_regtest.json", "w") as f:
        json.dump(REPORT, f, indent=2, sort_keys=True)
    print(f"\n{len(REPORT['checks']) - len(FAILED)}/{len(REPORT['checks'])} checks passed; report {OUT}/ln_rail_regtest.json")
    sys.exit(1 if FAILED else 0)
