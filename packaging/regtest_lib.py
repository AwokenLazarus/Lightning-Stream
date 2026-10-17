"""Helpers shared by the package regtest drivers (Umbrel, StartOS-shaped, the container test; stdlib only).

Checks are recorded as PASS/FAIL rows (results.json). HTTP, the MCP over streamable HTTP, a UI browser (cookie,
CSRF, the signed-form flow with `xbt-wallet-ui sign`), a small reverse proxy that plays the box's proxy
(Umbrel app_proxy, StartOS) by adding X-Forwarded-*, and the paid buy over stream tickets: the owner sets up
a packaged gateway and a packaged wallet on their setup pages, and an agent pays the gateway through the
wallet's MCP (`paid_buy`; the Lightning side is packaging/ln_lab.py).
"""
import http.client as http_client
import http.server as http_server
import json
import os
import re
import socketserver
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = []
LOG = None


# Which images the regtest drivers run: "local" (default) the tree's own build, <image>:<version> as
# scripts/oci_build.sh --load tags it; "pinned" the published images exactly as the packages name them
# (packaging/images.lock, pulled by digest).
TEST_IMAGES = os.environ.get("XBT_TEST_IMAGES", "local")
PINNED = re.compile(r"^[a-z0-9.:/-]+/(xbt-[a-z0-9-]+):([0-9]+\.[0-9]+\.[0-9]+)-[0-9a-f]{12}@sha256:[0-9a-f]{64}$")


def test_image(ref):
    """The image a driver runs for a package's reference: the local build's tag unless XBT_TEST_IMAGES=pinned."""
    if TEST_IMAGES not in ("local", "pinned"):
        raise SystemExit(f"XBT_TEST_IMAGES={TEST_IMAGES!r}: local or pinned")
    m = PINNED.match(ref)
    return f"{m.group(1)}:{m.group(2)}" if m and TEST_IMAGES == "local" else ref


def image_of(name):
    """The image a driver runs for one of the agentpay images, by name (packaging/images.lock)."""
    with open(os.path.join(ROOT, "packaging", "images.lock")) as f:
        for line in f:
            parts = line.split()
            if len(parts) == 2 and parts[0] == name:
                return test_image(parts[1])
    raise SystemExit(f"packaging/images.lock has no {name}")


def test_compose(path):
    """Rewrite an installed copy of a compose file to the images test_image() picks (the store is untouched)."""
    with open(path) as f:
        text = f.read()
    new = re.sub(r"(?m)^(    image: )(\S+)$", lambda m: m.group(1) + test_image(m.group(2)), text)
    if new != text:
        with open(path, "w") as f:
            f.write(new)


def open_log(path):
    global LOG
    LOG = open(path, "a")


def log(*a):
    s = " ".join(str(x) for x in a)
    print(s, flush=True)
    if LOG:
        LOG.write(s + "\n")
        LOG.flush()


def check(group, name, ok, detail=None):
    RESULTS.append({"group": group, "check": name, "ok": bool(ok), "detail": detail})
    log(f"  [{'PASS' if ok else 'FAIL'}] {group}: {name}" + ("" if ok else f"  -- {json.dumps(detail, default=str)[:700]}"))
    return ok


def sh(*argv, check_rc=True, input=None, timeout=600, env=None, cwd=None):
    r = subprocess.run([str(a) for a in argv], capture_output=True, text=True, input=input, timeout=timeout, env=env, cwd=cwd)
    if LOG:
        LOG.write(f"$ {' '.join(str(a) for a in argv)[:600]}\n{r.stdout[-3000:]}{r.stderr[-3000:]}\n")
    if check_rc and r.returncode != 0:
        raise RuntimeError(f"{' '.join(str(a) for a in argv[:5])}... rc={r.returncode}: {(r.stderr or r.stdout).strip()[-800:]}")
    return r


def docker(*a, **kw):
    return sh("docker", *a, **kw)


def wait_until(fn, timeout, what, every=1.0):
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        try:
            last = fn()
            if last:
                return last
        except Exception as e:  # noqa: BLE001
            last = e
        time.sleep(every)
    raise RuntimeError(f"timed out after {timeout}s waiting for {what} (last: {last})")


def http(method, url, body=None, headers=None, timeout=240):
    req = urllib.request.Request(url, method=method, data=body, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def status(url, headers=None):
    try:
        return http("GET", url, headers=headers, timeout=10)[0]
    except Exception:  # noqa: BLE001
        return 0


def root_helper(mount_src, script, ro=True):
    """A root debian container on a host path or volume (the auditor's view: the images have no shell)."""
    return docker("run", "--rm", "--network", "none", "-v", f"{mount_src}:/d" + (":ro" if ro else ""), "debian:bookworm-slim", "sh", "-c", script)


class Mcp:
    def __init__(self, base, token, path="/mcp"):
        self.url, self.token, self.sid, self.n = base.rstrip("/") + path, token, None, 0

    def post(self, msg):
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        if self.sid:
            h["Mcp-Session-Id"] = self.sid
        code, hdrs, body = http("POST", self.url, json.dumps(msg).encode(), h)
        self.sid = self.sid or next((v for k, v in hdrs.items() if k.lower() == "mcp-session-id"), None)
        return code, json.loads(body) if body.strip().startswith("{") else body

    def start(self):
        self.sid = None
        code, r = self.post({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                             "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "agp040", "version": "1"}}})
        self.post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return code, r

    def tool(self, name, **args):
        self.n += 1
        code, r = self.post({"jsonrpc": "2.0", "id": self.n, "method": "tools/call", "params": {"name": name, "arguments": args}})
        if code != 200 or not isinstance(r, dict) or "result" not in r:
            raise RuntimeError(f"tools/call {name}: HTTP {code} {r}")
        text = r["result"]["content"][0]["text"]
        if r["result"].get("isError"):
            raise RuntimeError(f"{name}: {text}")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"_text": text}


def agent_rotation_attempts(base, tokens):
    """AGP-042: everything an agent holding a token could try in order to rotate it through the MCP. Returns
    [(what, status, headers, body)]. The MCP has no rotation endpoint, so none of these may succeed."""
    out = []
    for t in tokens:
        h = {"Authorization": f"Bearer {t}", "X-XBT-Rotate": "owner", "Content-Type": "application/json"}
        for method, path in (("POST", "/rotate-token"), ("POST", "/mcp/rotate-token"), ("GET", "/rotate-token"), ("PUT", "/mcp")):
            st, hd, body = http(method, base.rstrip("/") + path, b"{}", h, timeout=20)
            out.append((f"{method} {path} ({t[:6]}..)", st, hd, body))
    return out


def leaks(responses, secret):
    """The responses (what, status, headers, body) whose headers or body contain `secret`."""
    return [r[0] for r in responses if secret and (secret in r[3] or secret in json.dumps(r[2]))]


def unescape(s):
    return s.replace("&quot;", '"').replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")


def field(html, name):
    m = re.search(r'name="%s" value="([^"]*)"' % re.escape(name), html)
    return unescape(m.group(1)) if m else None


class Ui:
    """A browser without JS: one cookie, no redirects followed."""

    def __init__(self, base, headers=None):
        u = urllib.parse.urlparse(base)
        self.host, self.port, self.prefix = u.hostname, u.port, u.path.rstrip("/")
        self.cookie, self.headers, self.last_set_cookie = "", headers or {}, ""

    def req(self, method, path, form=None):
        c = http_client.HTTPConnection(self.host, self.port, timeout=120)
        h = dict(self.headers)
        if self.cookie:
            h["Cookie"] = self.cookie
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            h["Content-Type"] = "application/x-www-form-urlencoded"
        c.request(method, self.prefix + path, body, h)
        r = c.getresponse()
        sc = r.getheader("Set-Cookie")
        if sc:
            self.last_set_cookie = sc
            self.cookie = sc.split(";")[0]
        return r.status, r.getheader("Location") or "", r.read().decode()

    def get(self, path):
        return self.req("GET", path)[2]

    def login(self, password):
        st, loc, body = self.req("POST", "/login", {"password": password})
        return st, loc

    def flash(self, path):
        m = re.search(r'class="flash[^"]*"[^>]*>(.*?)</div>', self.get(path), re.S)
        return unescape(m.group(1)) if m else ""

    def post(self, page, path, form):
        csrf = field(self.get(page), "csrf")
        st, loc, body = self.req("POST", path, dict(form, csrf=csrf))
        return st, loc, body


def sign(sign_bin, key_file, message_hex):
    return sh(sign_bin, "sign", "--key", key_file, "--message-hex", message_hex).stdout.strip()


def owner_setup(ui, sign_bin, key_file, policy, code=""):
    """The owner's first run in the UI, no terminal: enrol the approval key with the signer's one-time
    code (the app's log shows it), then sign a policy (the "sign on another device" path; the in-browser
    path is covered by xbt-wallet-ui's browser test). Returns (public key, enrolled flash, applied flash)."""
    pub = sh(sign_bin, "pubkey", "--key", key_file).stdout.strip()
    ui.post("/setup", "/human-key-enroll", {"pubkey": pub, "code": code})
    f1 = ui.flash("/setup")
    return pub, f1, sign_policy(ui, sign_bin, key_file, policy)


def sign_policy(ui, sign_bin, key_file, policy):
    """A policy change in the UI, signed on another device. Returns the flash after it is applied."""
    csrf = field(ui.get("/policy"), "csrf")
    st, _, page = ui.req("POST", "/policy", {"csrf": csrf, "mode": "json", "json": json.dumps(policy)})
    hx = re.search(r'<pre class="hex">([0-9a-f]+)</pre>', page)
    if not hx:
        raise RuntimeError(f"policy preview without a message to sign: {st} {page[-1500:]}")
    form = {k: field(page, k) for k in ("text", "prev_sha256", "expiry")}
    if form["text"] is None:
        m = re.search(r'<textarea[^>]*name="text"[^>]*>(.*?)</textarea>', page, re.S)
        form["text"] = unescape(m.group(1)) if m else ""
    form["signature_ext"] = sign(sign_bin, key_file, hx.group(1))
    form["csrf"] = field(page, "csrf")
    ui.req("POST", "/policy-apply", form)
    return ui.flash("/policy")


class ProxyHandler(http_server.BaseHTTPRequestHandler):
    upstream = None  # (host, port)
    forwarded = {}

    def _go(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else None
        c = http_client.HTTPConnection(*self.upstream, timeout=300)
        h = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection")}
        h.update({"Host": self.headers.get("Host", ""), "X-Forwarded-For": self.client_address[0], **self.forwarded})
        c.request(self.command, self.path, body, h)
        r = c.getresponse()
        data = r.read()
        self.send_response(r.status)
        for k, v in r.getheaders():
            if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_DELETE = _go

    def log_message(self, *a):
        pass


def start_proxy(listen_port, upstream_port, forwarded):
    """The box's reverse proxy (app_proxy / StartOS): 127.0.0.1:listen -> 127.0.0.1:upstream, adding X-Forwarded-*."""
    h = type("H", (ProxyHandler,), {"upstream": ("127.0.0.1", upstream_port), "forwarded": forwarded})
    srv = type("S", (socketserver.ThreadingTCPServer,), {"allow_reuse_address": True})(("127.0.0.1", listen_port), h)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


POLICY_BASE = {"max_per_tx_sats": 1000, "daily_budget_sats": 20000, "weekly_budget_sats": 50000, "per_counterparty_cap_sats": 9400,
               "velocity_max": 50, "velocity_window_s": 3600, "human_threshold_sats": 5000, "hot_balance_cap_sats": 100000, "split_window_s": 0,
               "regtest_mine": False, "anchor_required": True, "anchor_interval_s": 5}

# what the wallet's MCP lists with no rail's own tools turned on
BASE_TOOLS = ["balance", "quote_payment", "pay", "history", "channels", "xbt402_pay"]
# the packages turn the Lightning rail's and the tickets' own tools on (XBT_MCP_LN, XBT_MCP_TICKETS)
PACKAGE_TOOLS = BASE_TOOLS + ["ln_pay", "ln_status", "ticket_status", "ticket_stop"]


def agent_and_custody(group, agent, ui, sign_bin, key_file, chain, sc, tools="base"):
    """The wallet's own surface, through the agent's MCP and the owner's UI: the tool list, the balance, a
    payment quoted under the owner's policy, and custody of the hot key (coins received and counted, then
    swept out by the owner with a signature made on another device). The paid buy is `paid_buy`.
    `sc(method, params)` calls the signer's socket. Returns the facts a later restart or restore is
    compared with."""
    ha = sc("hot_address")
    txid = chain.cli("sendtoaddress", ha["hot_address"], "0.0005", wallet=getattr(chain, "faucet_wallet", "faucet"))
    chain.mine(1)
    sc("notice_hot_txid", {"txid": txid})
    check(group, "the hot key received 50,000 sat and the wallet counts them", sc("hot_address").get("hot_sats") == 50000, sc("hot_address"))
    code, listed = agent.post({"jsonrpc": "2.0", "id": 9000, "method": "tools/list"})
    names = [t.get("name") for t in listed.get("result", {}).get("tools", [])] if isinstance(listed, dict) else listed
    want = PACKAGE_TOOLS if tools == "package" else BASE_TOOLS
    check(group, f"the agent's tools: the six every wallet has{', the rail and ticket tools' if tools == 'package' else ''}, and none of the "
                 "removed on-chain channel", names == want, names)
    bal = agent.tool("balance")
    check(group, "the agent reads the balance: the hot key's coins, no channel", bal.get("hot", {}).get("hot_sats") == 50000 and bal.get("channels") == []
          and not bal.get("legacy_channels"), bal)
    q = agent.tool("quote_payment", to=chain.faucet, amount_xbt=0.00001)
    check(group, "a payment the agent asks about is judged by the owner's policy (allowed: on the allowlist, under every limit)", q.get("verdict") == "allow", q)
    exp = str(int(time.time()) + 600)
    msg = "\n".join(["xbt-agentwallet-hot-sweep-v1", ha["hot_address"], chain.faucet, "20000", exp]).encode().hex()
    st, loc, _ = ui.post("/keys", "/sweep", {"to": chain.faucet, "amount_sats": "20000", "expiry": exp, "signature": "", "signature_ext": sign(sign_bin, key_file, msg)})
    f = ui.flash(loc.lstrip(".")) if loc else ""
    chain.mine(1)
    left = sc("hot_address").get("hot_sats")
    check(group, "the owner sweeps 20,000 sat of the hot key in the UI, signed on another device", f.startswith("Swept 20000 sats to") and 29000 <= left < 30000, [f, left])
    return {"hot_address": ha["hot_address"], "hot_sats": left, "channels": agent.tool("channels").get("channels")}


class Chain:
    """bitcoin-cli in the node container; the faucet; the AGP-017 maturity window mined past."""

    def __init__(self, container, rpc_user, rpc_pass):
        self.c, self.u, self.p = container, rpc_user, rpc_pass
        self.faucet = None

    def cli(self, *a, wallet=None):
        args = ["docker", "exec", self.c, "bitcoin-cli", "-regtest", "-datadir=/data", "-rpcport=8332", f"-rpcuser={self.u}", f"-rpcpassword={self.p}"]
        if wallet:
            args.append(f"-rpcwallet={wallet}")
        out = sh(*args, *[str(x) for x in a]).stdout.strip()
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return out

    def mine(self, n=1):
        return self.cli("generatetoaddress", n, self.faucet)

    def bootstrap(self):
        self.cli("createwallet", "faucet")
        self.faucet = self.cli("getnewaddress", wallet="faucet")
        self.mine(120)
        desc = self.cli("getdescriptorinfo", "raw(51)")["descriptor"]
        while self.cli("getblockcount") < 6720:
            self.cli("generatetodescriptor", min(1000, 6720 - self.cli("getblockcount")), desc)


def write_results(out):
    with open(os.path.join(out, "results.json"), "w") as f:
        json.dump(RESULTS, f, indent=1, default=str)
    n_ok = sum(r["ok"] for r in RESULTS)
    log(f"== {n_ok}/{len(RESULTS)} checks passed")
    return bool(RESULTS) and n_ok == len(RESULTS)


# --- the paid buy over stream tickets -------------------------------------------------------------------


def gateway_owner_setup(gui, facts, public_url, price_msat=2500):
    """The gateway's owner on its page, no terminal: the service, the origin buyers use, a price per
    request, the test chain's network id, and the two macaroons baked in the node's dashboard."""
    form = {"upstream": facts["upstream"], "price_msat": str(price_msat), "unit": "request", "public_url": public_url, "proxies": "",
            "chain": "regtest", "network": facts["network"], "mainnet_ack": "", "max_sessions": "30", "sessions_per_address": "2",
            "max_held_tickets": "15", "invoices_macaroon": facts["invoices_macaroon"], "info_macaroon": facts["info_macaroon"]}
    st, loc, body = gui.post("/", "/gateway", form)
    return st, (gui.flash("/") if st == 303 else unescape(re.sub(r"<[^>]+>", " ", body))[-600:])


def ticket_policy(origin, seller_pubkey, split):
    """The owner's policy for the paid buy: the gateway's origin tied to its node, the rail and tickets on."""
    return dict(POLICY_BASE, allowlist=[origin], counterparties={origin: {"ln_node": seller_pubkey}}, max_per_tx_sats=5000,
                per_counterparty_cap_sats=20000, human_threshold_sats=10000, ln={"enabled": True, "split_height": split},
                tickets={"enabled": True, "tasks": {"default": {"budget_sats": 20000}}})


def paid_buy(group, agent, ui, gui, sign_bin, key_file, lab, sc, gateway_up, origin):
    """The owner sets up both packages on their pages, then the agent buys a priced page from the
    gateway with one `xbt402_pay` call through the wallet's MCP, paid with a stream ticket over lf1 ->
    lf2. `sc(method, params)` calls the signer's socket; `gateway_up()` is the gateway's health as
    its container reports it. Returns the facts a restart is compared with."""
    from ln_lab import PAGE  # noqa: PLC0415
    f = lab.facts
    st, flash = gateway_owner_setup(gui, f, origin)
    check(group, "gateway page: the owner's config (service, origin, price, network, two narrow macaroons) is checked by the gateway's parser and saved",
          st == 303 and "Saved" in flash, [st, flash])
    t0 = time.time()
    wait_until(gateway_up, 120, "the gateway healthy from the config the page wrote", every=2)
    check(group, f"the gateway started from that config ({time.time() - t0:.0f} s; xbt-supervise waited for the file) and answers its health check", True)
    applied = sign_policy(ui, sign_bin, key_file, ticket_policy(origin, f["lf2_pubkey"], f["split"]))
    check(group, "the owner signs a policy that allows the gateway (its origin tied to the seller's node id) with the rail and tickets on",
          "applied" in applied.lower(), applied)
    # a setting that waits for a signer restart is taken when the rail macaroon below restarts it
    st, loc, _ = ui.post("/lightning", "/lightning", {"action": "save", "macaroon": f["rail_macaroon"]})
    flash = ui.flash("/lightning")
    check(group, "Lightning page: the rail macaroon (the four permissions the rail needs, nothing more) is stored", "saved" in flash.lower(), flash)
    t0 = time.time()
    last = {}

    def rail_ready():
        last.update(sc("ln_status"))
        return last if last.get("ready") is True else None
    try:
        st_ln = wait_until(rail_ready, 180, "the rail ready", every=3)
    except RuntimeError:
        st_ln = last
    check(group, f"the signer restarted with it ({time.time() - t0:.0f} s; xbt-supervise saw the file) and the rail is ready: chain verified, "
                 "the channel's funding proven", st_ln.get("ready") is True, {k: st_ln.get(k) for k in ("ready", "warnings", "backend")})
    before_settled = len(lab.seller_settled())
    r = agent.tool("xbt402_pay", url=f"{origin}/small.txt", max_sats=10)
    body = str((r.get("untrusted_provider_response") or {}).get("body", ""))
    check(group, "the agent's one xbt402_pay call buys the priced page through the packaged wallet: a stream ticket over lf1 -> lf2, "
                 "2,500 msat used, the seller's receipt signs the body",
          r.get("verdict") == "allow" and r.get("rail") == "ticket" and r.get("status") == 200 and body == PAGE and r.get("tickets_released") == 1
          and r.get("price_msat") == "2500" and r.get("receipt") == {"signed": True, "body": "as signed"},
          {k: r.get(k) for k in ("verdict", "rail", "status", "tickets_released", "price_msat", "balance_msat", "receipt", "reason", "rails_passed_over")})
    settled = wait_until(lambda: (lambda x: x if len(x) > before_settled else None)(lab.seller_settled()), 30, "the seller's node settled the ticket")
    t_settled = settled[-1]
    h = bytes_hex(t_settled.get("r_hash"))
    # the seller settles first; the buyer's node marks the payment a moment later, when the HTLC is settled back to it
    try:
        mine = wait_until(lambda: (lambda m: m if m and m[0].get("status") == "SUCCEEDED" else None)(
            [p for p in lab.buyer_payments() if p.get("payment_hash") == h]), 30, "the buyer's payment SUCCEEDED")
    except RuntimeError:
        mine = [p for p in lab.buyer_payments() if p.get("payment_hash") == h]
    check(group, "the seller's node settled one ticket of 1,000 sat, and the buyer's node paid it: the same hash, SUCCEEDED, 1,000 sat",
          int(t_settled.get("amt_paid_msat") or 0) == 1_000_000 and len(mine) == 1 and mine[0].get("status") == "SUCCEEDED"
          and int(mine[0].get("value_msat") or 0) == 1_000_000,
          {"settled_msat": t_settled.get("amt_paid_msat"), "hash": h, "buyer": [{k: p.get(k) for k in ("payment_hash", "status", "value_msat")}
                                                                                for p in lab.buyer_payments()][-4:]})
    r2 = agent.tool("xbt402_pay", url=f"{origin}/small.txt", max_sats=10)
    check(group, "a second call is paid from the same ticket's balance: no new ticket released, 2,500 msat more used",
          r2.get("status") == 200 and r2.get("tickets_released") == 0 and int(r2.get("balance_msat") or 0) == int(r.get("balance_msat") or 0) - 2500,
          {k: r2.get(k) for k in ("verdict", "rail", "status", "tickets_released", "balance_msat", "reason")})
    return {"settled": len(lab.seller_settled()), "balance_msat": r2.get("balance_msat")}


def bytes_hex(b64):
    import base64  # noqa: PLC0415
    try:
        return base64.b64decode(b64 or "").hex()
    except ValueError:
        return ""
