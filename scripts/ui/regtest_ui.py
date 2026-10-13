#!/usr/bin/env python3
"""AGP-039 regtest driver (stdlib only; run by regtest_ui.sh).

1. Fund the signer's hot key from the node wallet (one block).
2. An agent calls `pay` through the MCP over HTTP for an amount at the human threshold; the wallet
   answers needs_human and nothing is sent.
3. The human logs in to the UI, finds it on the Approvals page, signs the message the page shows with
   the device key (`xbt-wallet-ui sign`), and submits the approval in the UI: the payment is made.
4. The payment is confirmed on chain; a payment under the threshold needs no human.
5. A second over-threshold payment is denied in the UI, signed like the approval (AGP-063 W3: an
   unsigned deny is refused).
6. The human sweeps part of the hot key in the UI; the UI shows the signature log intact and
   anchored, and no channel: this wallet has none. The MCP lists no channel tool.

Until 2026-10 the payment of steps 2 to 4 was an `xbt402_pay` over the on-chain channel, which was
removed. An agent paying a seller's 402 through the MCP is proven on Lightning by
scripts/ticket_e2e_regtest.sh.
"""
import argparse
import http.client
import json
import re
import socket
import subprocess
import sys
import time
import urllib.parse

A = argparse.ArgumentParser()
for k in ["out", "sock", "mcp", "mcp-token", "ui", "ui-password-file", "human-key", "sign-bin", "payee", "cli"]:
    A.add_argument("--" + k, required=True)
a = A.parse_args()
RESULTS = []


def check(name, ok, detail=None):
    RESULTS.append({"check": name, "ok": bool(ok), "detail": detail})
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  {detail}"), flush=True)
    return ok


def signer(method, **params):
    s = socket.socket(socket.AF_UNIX)
    s.connect(a.sock)
    s.sendall((json.dumps({"id": 1, "method": method, "params": params}) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        c = s.recv(65536)
        if not c:
            break
        buf += c
    r = json.loads(buf)
    if r.get("error"):
        raise RuntimeError(r["error"])
    return r["result"]


def cli(*args):
    return subprocess.check_output(a.cli.split() + list(args), text=True).strip()


class Mcp:
    def __init__(self, url, token):
        u = urllib.parse.urlparse(url)
        self.host, self.port, self.path, self.token, self.sid = u.hostname, u.port, u.path, token, None

    def post(self, msg, timeout=300):
        c = http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Authorization": f"Bearer {self.token}"}
        if self.sid:
            h["Mcp-Session-Id"] = self.sid
        c.request("POST", self.path, json.dumps(msg), h)
        r = c.getresponse()
        body = r.read().decode()
        if r.getheader("Mcp-Session-Id"):
            self.sid = r.getheader("Mcp-Session-Id")
        return r.status, (json.loads(body) if body else None)

    def start(self):
        st, r = self.post({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "agp039-regtest-agent", "version": "1"}}})
        self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return r

    def tool(self, name, args, id_=1):
        st, r = self.post({"jsonrpc": "2.0", "id": id_, "method": "tools/call", "params": {"name": name, "arguments": args}})
        text = r["result"]["content"][0]["text"]
        try:
            return json.loads(text)
        except ValueError:
            return {"raw": text}


class Ui:
    def __init__(self, base):
        u = urllib.parse.urlparse(base)
        self.host, self.port, self.cookie = u.hostname, u.port, ""

    def req(self, method, path, form=None):
        c = http.client.HTTPConnection(self.host, self.port, timeout=60)
        h = {"Cookie": self.cookie} if self.cookie else {}
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            h["Content-Type"] = "application/x-www-form-urlencoded"
        c.request(method, path, body, h)
        r = c.getresponse()
        sc = r.getheader("Set-Cookie")
        if sc:
            self.cookie = sc.split(";")[0]
        return r.status, r.getheader("Location") or "", r.read().decode()

    def get(self, path):
        return self.req("GET", path)[2]

    def post(self, page, path, form):
        csrf = field(self.get(page), "csrf")
        st, loc, _ = self.req("POST", path, dict(form, csrf=csrf))
        return self.flash(loc.lstrip("."))

    def flash(self, path):
        m = re.search(r'class="flash[^"]*"[^>]*>(.*?)</div>', self.get(path), re.S)
        return unescape(m.group(1)) if m else ""


def unescape(s):
    return s.replace("&quot;", '"').replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")


def field(html, name):
    m = re.search(r'name="%s" value="([^"]*)"' % re.escape(name), html)
    return unescape(m.group(1)) if m else None


t0 = time.time()
# 1. fund the hot key
hot = signer("hot_address")["hot_address"]
txid = cli("-rpcwallet=w", "sendtoaddress", hot, "0.002")
cli("generatetoaddress", "1", cli("-rpcwallet=w", "getnewaddress"))
signer("notice_hot_txid", txid=txid)
check("hot key funded with 200,000 sats", signer("hot_address")["hot_sats"] == 200_000, signer("hot_address"))

# 2. the agent asks for a payment at the human threshold
agent = Mcp(a.mcp, a.mcp_token)
init = agent.start()
check("MCP initialized (streamable HTTP, bearer token)", init and init.get("result", {}).get("serverInfo", {}).get("name") == "xbt-agent-wallet", init)
st, listed = agent.post({"jsonrpc": "2.0", "id": 90, "method": "tools/list"})
names = [t["name"] for t in listed["result"]["tools"]]
check("the MCP lists the six tools every wallet has, and none of the removed on-chain channel",
      names == ["balance", "quote_payment", "pay", "history", "channels", "xbt402_pay"], names)
PAYEE = a.payee
r = agent.tool("pay", {"to": PAYEE, "amount_xbt": 0.00001, "memo": "invoice 7"})
check("a payment at the threshold needs the human: nothing is sent", r.get("verdict") == "needs_human" and r.get("approval_token"), r)
received = lambda: int(round(float(cli("-rpcwallet=w", "getreceivedbyaddress", PAYEE, "0")) * 1e8))
check("the payee has received nothing yet", received() == 0, received())

# 3. the human, in the UI
ui = Ui(a.ui)
pw = open(a.ui_password_file).read()
st, loc, _ = ui.req("POST", "/login", {"password": pw})
check("logged in to the UI", st == 303 and loc == "./", (st, loc))
page = ui.get("/approvals")
check("the waiting payment is on the Approvals page with its payee, memo and amount", PAYEE in page and "invoice 7" in page and "1,000 sats" in page)
token, dest, amount, expiry = field(page, "token"), field(page, "dest"), field(page, "amount_sats"), field(page, "expiry")
check("the page's token is the one the agent was given", token == r.get("approval_token"), token)
msg_hex = re.search(r'<pre class="hex">([0-9a-f]+)</pre>', page).group(1)
expect = "\n".join(["xbt-agentwallet-approve-v1", token, dest, amount, expiry]).encode().hex()
check("the message shown for the device is (token, dest, amount, expiry)", msg_hex == expect)
sig = subprocess.check_output([a.sign_bin, "sign", "--key", a.human_key, "--message-hex", msg_hex], text=True).strip()
f = ui.post("/approvals", "/approve", {"token": token, "dest": dest, "amount_sats": amount, "expiry": expiry, "signature": "", "signature_ext": sig})
check("approved in the UI: the payment is made at once", f.startswith("Approved and paid: 1000 sats to") and "onchain" in f, f)

# 4. on chain
pay_tx = re.search(r"onchain ([0-9a-f]{64})", f)
pay_tx = pay_tx.group(1) if pay_tx else None
cli("generatetoaddress", "1", cli("-rpcwallet=w", "getnewaddress"))
conf = int(json.loads(cli("-rpcwallet=w", "gettransaction", pay_tx)).get("confirmations", 0)) if pay_tx else 0
check("the payment is confirmed on chain and the payee received 1,000 sats", conf >= 1 and received() == 1000, (pay_tx, conf, received()))
check("the token is used", signer("approval_status", token=token)["state"] == "used")
under = agent.tool("pay", {"to": PAYEE, "amount_xbt": 0.000005, "memo": "small"}, id_=2)
check("a payment under the threshold pays without a human", under.get("verdict") == "allow" and under.get("rail") == "onchain" and under.get("txid"), under)

# 5. a second over-threshold payment, denied in the UI
r2 = agent.tool("pay", {"to": PAYEE, "amount_xbt": 0.00002, "memo": "not this one"}, id_=3)
t2 = r2.get("approval_token")
page = ui.get("/approvals")
check("the second payment waits on the Approvals page", t2 and t2 in page, r2)
f = ui.post("/approvals", "/deny", {"token": t2, "reason": "unsigned"})
check("an unsigned deny is refused (AGP-063 W3): the payment still waits", signer("approval_status", token=t2)["state"] == "pending", f)
form = re.search(r'<form method="post" action="\./deny"(.*?)</form>', page, re.S).group(1)
d_exp = field(form, "expiry")
d_hex = re.search(r'<pre class="hex">([0-9a-f]+)</pre>', form).group(1)
check("the deny message shown for the device is (token, expiry)", d_hex == "\n".join(["xbt-agentwallet-deny-v1", t2, d_exp]).encode().hex())
d_sig = subprocess.check_output([a.sign_bin, "sign", "--key", a.human_key, "--message-hex", d_hex], text=True).strip()
f = ui.post("/approvals", "/deny", {"token": t2, "reason": "not this one", "expiry": d_exp, "signature": "", "signature_ext": d_sig})
check("denied in the UI", f == "Denied." and signer("approval_status", token=t2)["state"] == "denied", f)
check("the denied payment was not made", received() == 1500, received())

# 6. the hot key swept in the UI, the signature log, and no channel
s_exp = str(int(time.time()) + 600)
s_hex = "\n".join(["xbt-agentwallet-hot-sweep-v1", hot, PAYEE, "50000", s_exp]).encode().hex()
s_sig = subprocess.check_output([a.sign_bin, "sign", "--key", a.human_key, "--message-hex", s_hex], text=True).strip()
f = ui.post("/keys", "/sweep", {"to": PAYEE, "amount_sats": "50000", "expiry": s_exp, "signature": "", "signature_ext": s_sig})
check("the human sweeps 50,000 sats of the hot key in the UI", f.startswith("Swept 50000 sats to"), f)
cli("generatetoaddress", "1", cli("-rpcwallet=w", "getnewaddress"))
check("the swept coins arrived", received() == 51500, received())
chans = ui.get("/channels")
check("the UI's Channels page says the wallet has no on-chain channel", "No channels." in chans and "no longer has an on-chain channel" in chans)
c = agent.tool("channels", {}, id_=4)
check("the channels tool lists none", c.get("channels") == [] and not c.get("legacy_channels"), c)
gone = agent.post({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "close_channel", "arguments": {"counterparty": "x"}}})[1]
check("close_channel is no tool", gone.get("result", {}).get("isError") is True or "error" in gone, gone)
sigs = ui.get("/signatures")
check("the UI shows the signature log intact and anchored, with the sweep", "chain intact, matches the anchor" in sigs and "human:sweep_signature" in sigs)
ov = ui.get("/")
check("the overview renders with the real node", "Recent activity" in ov and "regtest" in ov)
for p in ["approvals", "channels", "signatures", "keys", "policy", "setup"]:
    open(f"{a.out}/{p}.html", "w").write(ui.get("/" + p))
open(f"{a.out}/overview.html", "w").write(ov)

ok = all(x["ok"] for x in RESULTS)
summary = {"ok": ok, "checks": RESULTS, "total_s": round(time.time() - t0, 1), "payment_txid": pay_tx, "payee": PAYEE}
json.dump(summary, open(f"{a.out}/results.json", "w"), indent=2)
print(f"regtest_ui: {sum(x['ok'] for x in RESULTS)}/{len(RESULTS)} checks passed")
sys.exit(0 if ok else 1)
