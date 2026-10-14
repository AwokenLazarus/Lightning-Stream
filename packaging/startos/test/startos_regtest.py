#!/usr/bin/env python3
"""AGP-040: the StartOS package's containers on regtest, run the way StartOS runs them (test-startos.sh runs this).

No StartOS VM runs here (no KVM for this user), so this runs the package's own container spec
(xbt-agent-wallet/startos/spec.ts, printed by test/spec-json.mjs: the same data main.ts turns into daemons) on
Docker, with what StartOS does around it:
  * one volume, `main`, root-owned and empty at install (no image skeleton copied into it); every container
    mounts only its sub-paths of it (volume-subpath), read-only where the spec says so;
  * the containers share one network namespace (StartOS runs a service's subcontainers in one LXC container,
    so they reach each other on 127.0.0.1), and each runs as its image's user unless the spec says root;
  * `init` is a oneshot that must exit 0 before the daemons start, in the spec's `requires` order;
  * the node is an external XBT Knots on the AGP-017 regtest chain (the Node connection action's values).

Checks (results.json): I install and layout, U the owner in the UI (setup code, password, key, policy, token),
P the agent's MCP surface and custody of the hot key, G readiness (the fields the package's wallet-ready health check reads), R a restart
after the whole volume came back root-owned (StartOS remounts, or a restore), B backup and restore of
`main` into a new install (sealed keys, the hot key's coins, the UI login), W the reset-password flow.
(P was an agent's payment over the on-chain channel until 2026-10. That channel was removed, and the
package wires no Lightning node into the wallet yet, so the packaged wallet pays no seller: see regtest_lib.py.)
(The H checks ran the hub and are retired with it; the other letters are unchanged. The hub was retired
on 2026-10-11: payments between parties route over ordinary Lightning instead. Its code is in the git
history, last at commit 0911cc0.)
    startos_regtest.py OUT
"""
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(os.path.dirname(HERE), "xbt-agent-wallet")
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
from regtest_lib import (agent_and_custody, agent_rotation_attempts, leaks, POLICY_BASE, ROOT, Chain, Mcp, Ui, check, docker, field, http, log, open_log,  # noqa: E402
                         owner_setup, sh, status, wait_until, write_results)

OUT = sys.argv[1]
PID = os.getpid()
P = f"agp040-s9-{PID}"
NET = f"{P}-net"
P_MCP = int(os.environ.get("STARTOS_TEST_MCP_PORT", "24110"))
P_UI = int(os.environ.get("STARTOS_TEST_UI_PORT", "24130"))
SIGN_BIN = os.path.join(ROOT, "dist/oci/ctx/bin/amd64/xbt-wallet-ui")
RPC_USER, RPC_PASS = "xbt", os.urandom(16).hex()
open_log(os.path.join(OUT, "startos_regtest.log"))


def spec():
    cfg = {"node": {"host": f"{P}-knots", "port": 8332, "user": RPC_USER, "password": RPC_PASS, "chain": "regtest"},
           "mcpUrls": [f"http://127.0.0.1:{P_MCP}/mcp"]}
    r = subprocess.run(["node", "--experimental-strip-types", "--no-warnings", "test/spec-json.mjs", json.dumps(cfg)], cwd=PKG,
                       capture_output=True, text=True, check=True)
    return json.loads(r.stdout)


def run_service(s, images, vol, name=None):
    """One subcontainer as StartOS makes it: the image's user (or the spec's), the spec's mounts of `main`."""
    args = ["run", "-d", "--name", name or f"{P}-{s['id']}", "--network", f"container:{P}-ns", "--restart", "no"]
    if s.get("user"):
        args += ["--user", "0:0" if s["user"] == "root" else s["user"]]
    for k, v in s["env"].items():
        args += ["-e", f"{k}={v}"]
    for m in s["mounts"]:
        mnt = f"type=volume,src={vol},dst={m['mountpoint']},volume-nocopy=true"
        if m["subpath"]:
            mnt += f",volume-subpath={m['subpath']}"
        if m["readonly"]:
            mnt += ",readonly"
        args += ["--mount", mnt]
    args += ["--entrypoint", s["command"][0], images[s["image"]], *s["command"][1:]]
    return docker(*args)


def start_all(sp, vol, only=None):
    """init first (must exit 0), then the daemons in the spec's order (each after what it requires)."""
    by = {s["id"]: s for s in sp["services"]}
    docker("rm", "-f", f"{P}-init", check_rc=False)
    run_service(by["init"], sp["images"], vol)
    code = int(docker("wait", f"{P}-init").stdout.strip())
    rep = docker("logs", f"{P}-init").stdout.strip().splitlines()
    for sid in ["witness", "signer", "mcp", "ui"]:
        if sid in by and (only is None or sid in only):
            docker("rm", "-f", f"{P}-{sid}", check_rc=False)
            run_service(by[sid], sp["images"], vol)
            if sid == "witness":
                wait_until(lambda: docker("exec", f"{P}-witness", "/usr/bin/xbt-anchor-witness", "healthcheck", check_rc=False).returncode == 0,
                           60, "the witness ready (its readyCommand)")
            if sid == "signer":
                wait_until(lambda: docker("exec", f"{P}-signer", "/usr/bin/xbt-signer", "healthcheck", check_rc=False).returncode == 0,
                           120, "the signer ready (its readyCommand)")
    return code, (json.loads(rep[-1]) if rep else {})


def stop_all():
    for sid in ["ui", "mcp", "signer", "witness", "init"]:
        docker("rm", "-f", f"{P}-{sid}", check_rc=False)


def vol_sh(vol, script, ro=True):
    return docker("run", "--rm", "--network", "none", "--mount", f"type=volume,src={vol},dst=/v,volume-nocopy=true" + (",readonly" if ro else ""),
                  "debian:bookworm-slim", "sh", "-c", script)


def main():
    docker("network", "create", NET)
    sp = spec()
    by = {s["id"]: s for s in sp["services"]}
    check("I", "the package spec: init runs as root; every daemon as its image's user; each mounts only its own sub-paths",
          by["init"].get("user") == "root" and all(not by[i].get("user") for i in ("witness", "signer", "mcp", "ui"))
          and [m["subpath"] for m in by["mcp"]["mounts"]] == ["mcp", "run/signer", "run/ui"]
          and by["mcp"]["mounts"][1]["readonly"] and by["mcp"]["mounts"][2]["readonly"]
          and [(m["subpath"], m["readonly"]) for m in by["ui"]["mounts"]] == [("ui", False), ("run/signer", True), ("run/ui", False)]
          and [m["subpath"] for m in by["witness"]["mounts"]] == ["witness", "run/anchor"], sp["services"])

    # --- the external node (the Node connection action's values) -------------------------------
    log("== node (regtest)")
    docker("volume", "create", f"{P}-node")
    vol_sh(f"{P}-node", "chown 1000:1000 /v", ro=False)
    docker("run", "-d", "--name", f"{P}-knots", "--network", NET, "--user", "1000:1000", "-v", f"{P}-node:/data",
           "-v", f"{os.path.join(ROOT, 'packaging/umbrel/regtest')}:/etc/xbt-test:ro", "--entrypoint", "bitcoind", "xbt-a3-knots:29.4.2",
           "-datadir=/data", "-conf=/etc/xbt-test/knots-regtest.conf", f"-rpcuser={RPC_USER}", f"-rpcpassword={RPC_PASS}")
    chain = Chain(f"{P}-knots", RPC_USER, RPC_PASS)
    wait_until(lambda: chain.cli("getblockcount") is not None, 90, "node RPC")
    chain.bootstrap()

    # --- install: an empty, root-owned `main` ----------------------------------------------------------------------
    log("== install: main volume root-owned and empty; init, then the daemons")
    vol = f"{P}-main"
    docker("volume", "create", vol)
    docker("run", "-d", "--name", f"{P}-ns", "--network", NET, "-p", f"127.0.0.1:{P_UI}:8480", "-p", f"127.0.0.1:{P_MCP}:33510",
           "debian:bookworm-slim", "sleep", "infinity")
    before = vol_sh(vol, "stat -c '%u:%g %a' /v; ls -A /v | wc -l").stdout.split()
    t0 = time.time()
    code, rep = start_all(sp, vol)
    check("I", "init on the root-owned empty volume exits 0; its own layout check passes",
          before[:3] == ["0:0", "755", "0"] and code == 0 and rep.get("ok"), {"before": before, "report": rep})
    ls = vol_sh(vol, "stat -c '%u:%g %a %n' /v/signer /v/witness /v/mcp /v/ui /v/run/signer /v/run/anchor /v/signer/secrets/node-rpc-auth "
                     "/v/run/ui /v/run/ui/mcp-http-token; ls /v/ui/secrets /v/mcp/secrets").stdout.split("\n")
    check("I", "each component's sub-path owned by its uid (0700; sockets 0750); node credentials for the signer; the MCP token "
               "is the UI's run/ui/mcp-http-token (0640, the MCP reads it by group), with no other copy; "
               "no UI password file (StartOS uses the UI's own setup code)",
          ls[:9] == ["10001:10001 700 /v/signer", "10002:10002 700 /v/witness", "10003:10003 700 /v/mcp", "10005:10005 700 /v/ui",
                     "10001:10001 750 /v/run/signer", "10002:10002 750 /v/run/anchor",
                     "10001:10001 600 /v/signer/secrets/node-rpc-auth",
                     "10005:10005 750 /v/run/ui", "10005:10005 640 /v/run/ui/mcp-http-token"]
          and "xbt-ui-password" not in ls and "mcp-http-token" not in ls[9:], ls)
    wait_until(lambda: status(f"http://127.0.0.1:{P_MCP}/readyz") == 200 and status(f"http://127.0.0.1:{P_UI}/readyz") == 200,
               180, "MCP and UI /readyz 200")
    check("I", f"MCP and UI ready {time.time() - t0:.1f} s after install (the ports the package's readiness checks watch)", True)
    ids = {s: docker("inspect", "-f", "{{.Config.User}}", f"{P}-{s}").stdout.strip() for s in ("witness", "signer", "mcp", "ui")}
    check("I", "the daemons run as the image users (xbt-anchor-witness, xbt-signer, xbt-wallet-mcp, xbt-wallet-ui)",
          ids == {"witness": "xbt-anchor-witness", "signer": "xbt-signer", "mcp": "xbt-wallet-mcp", "ui": "xbt-wallet-ui"}, ids)

    # --- U: the owner, through the setup code (the Web UI setup code action reads ui/setup-code) ------------------------
    log("== U: the owner's first run: the setup code, a password, the key, the policy, the token")
    code_txt = vol_sh(vol, "cat /v/ui/setup-code").stdout.strip()
    ui = Ui(f"http://127.0.0.1:{P_UI}", headers={"X-Forwarded-Proto": "https", "X-Forwarded-For": "192.168.1.20"})
    st_noc = ui.req("POST", "/setup-password", {"code": "wrong", "password": "owner password 1", "password2": "owner password 1"})[0]
    pw = "owner password 1"
    st = ui.req("POST", "/setup-password", {"code": code_txt, "password": pw, "password2": pw})[0]
    gone = vol_sh(vol, "test -e /v/ui/setup-code && echo present || echo gone; test -s /v/ui/password.scrypt && echo hash").stdout.split()
    check("U", "first run: a wrong setup code is refused; the code from ui/setup-code sets the password; the code is deleted and only the hash kept",
          st_noc != 303 and st == 303 and gone == ["gone", "hash"], {"wrong": st_noc, "right": st, "files": gone})
    ui = Ui(f"http://127.0.0.1:{P_UI}", headers={"X-Forwarded-Proto": "https"})
    st, _ = ui.login(pw)
    check("U", "login with the owner's password; behind StartOS's https proxy the cookie is Secure",
          st == 303 and "Secure" in ui.last_set_cookie, ui.last_set_cookie)
    key = os.path.join(OUT, "device-human.key")
    with open(key, "w") as f:
        f.write(os.urandom(32).hex())
    os.chmod(key, 0o600)
    _, f1, f2 = owner_setup(ui, SIGN_BIN, key, dict(POLICY_BASE, allowlist=[chain.faucet]))
    check("U", "the owner enrols an approval key and signs a policy (allowlist: one address)", "enrolled" in f1.lower() and "applied" in f2.lower(), [f1, f2])
    if "restarts" in f2:
        docker("restart", f"{P}-signer")
        wait_until(lambda: status(f"http://127.0.0.1:{P_MCP}/readyz") == 200, 120, "MCP ready after the signer restart")
    page = ui.get("/agents")
    m = re.search(r'<code id="mcp-token">([0-9a-f]{64})</code>', page)
    token = m.group(1) if m else None
    disk = vol_sh(vol, "cat /v/run/ui/mcp-http-token").stdout.strip()
    check("U", "the UI's Agents page (and the Agent connection action, which reads the same file) gives the MCP URL and token",
          token == disk and f"http://127.0.0.1:{P_MCP}/mcp" in page, {"token_ok": token == disk})

    # --- P: the agent's surface and custody of the hot key ---------------------------------------------------------
    log("== P: the agent's MCP; the hot key funded, counted and swept by the owner")
    sc = lambda meth, p=None: json.loads(docker("exec", f"{P}-signer", "/usr/bin/xbt-signer", "call", meth, json.dumps(p or {})).stdout)  # noqa: E731
    agent = Mcp(f"http://127.0.0.1:{P_MCP}", token)
    agent.start()
    before = agent_and_custody("P", agent, ui, SIGN_BIN, key, chain, sc)

    # --- G: what the wallet-ready health check reads ----------------------------------------------------------------
    log("== G: readiness")
    docker("stop", f"{P}-knots")
    wait_until(lambda: status(f"http://127.0.0.1:{P_MCP}/readyz") == 503, 60, "MCP /readyz 503 with the node down")
    body = json.loads(http("GET", f"http://127.0.0.1:{P_MCP}/readyz")[2])
    check("G", "node down: /readyz 503 and signer_ready.node.reachable false (wallet-ready shows 'The XBT node is not reachable')",
          body.get("signer_ready", {}).get("node", {}).get("reachable") is False, body)
    docker("start", f"{P}-knots")
    wait_until(lambda: status(f"http://127.0.0.1:{P_MCP}/readyz") == 200, 90, "MCP /readyz 200 with the node back")
    check("G", "node back: /readyz 200 (wallet-ready: success)", True)

    # --- R: restart after the volume came back root-owned ---------------------------------------------------------
    log("== R: stop; the whole volume re-owned by root (a remount or a restore); start")
    time.sleep(6)
    stop_all()
    vol_sh(vol, "chown -R 0:0 /v && chmod 755 /v/*", ro=False)
    code, rep2 = start_all(sp, vol)
    wait_until(lambda: status(f"http://127.0.0.1:{P_MCP}/readyz") == 200, 180, "MCP /readyz after the restart")
    check("R", "init gave everything back to its owner (a recursive chown per component) and nothing was regenerated",
          code == 0 and rep2.get("ok") and all(s["result"] in ("unchanged", "fixed") for s in rep2["secrets"])
          and any(d["chowned"] > 1 for d in rep2["dirs"]), rep2)
    agent = Mcp(f"http://127.0.0.1:{P_MCP}", token)
    agent.start()
    ha2 = sc("hot_address")
    check("R", "the same token and hot address, and the hot key's coins as they were left",
          ha2["hot_address"] == before["hot_address"] and ha2.get("hot_sats") == before["hot_sats"]
          and agent.tool("balance").get("hot", {}).get("hot_sats") == before["hot_sats"], {"before": before, "after": ha2})

    # --- B: backup `main`, restore it into a new install ---------------------------------------------------------------
    log("== B: backup and restore of main")
    time.sleep(6)
    stop_all()
    bdir = os.path.join(OUT, "backup")
    os.makedirs(bdir, exist_ok=True)
    docker("run", "--rm", "--network", "none", "--mount", f"type=volume,src={vol},dst=/v,volume-nocopy=true,readonly", "-v", f"{bdir}:/b",
           "debian:bookworm-slim", "sh", "-c", "tar -C /v --numeric-owner -cf /b/main.tar . && chmod 644 /b/main.tar")
    vol2 = f"{P}-main2"
    docker("volume", "create", vol2)
    # a restore lands root-owned (as StartOS restores); init fixes the owners on the first start
    docker("run", "--rm", "--network", "none", "--mount", f"type=volume,src={vol2},dst=/v,volume-nocopy=true", "-v", f"{bdir}:/b:ro",
           "debian:bookworm-slim", "sh", "-c", "tar -C /v --no-same-owner -xf /b/main.tar")
    docker("volume", "rm", vol)
    code, rep3 = start_all(sp, vol2)
    wait_until(lambda: status(f"http://127.0.0.1:{P_MCP}/readyz") == 200 and status(f"http://127.0.0.1:{P_UI}/readyz") == 200, 180, "ready after restore")
    ui = Ui(f"http://127.0.0.1:{P_UI}")
    st, _ = ui.login(pw)
    agent = Mcp(f"http://127.0.0.1:{P_MCP}", token)
    agent.start()
    ha3 = sc("hot_address")
    check("B", "restored into a new install: the sealed keys open (same hot address), the hot key's coins, the MCP token and the UI password are back",
          code == 0 and ha3["hot_address"] == before["hot_address"] and ha3.get("hot_sats") == before["hot_sats"] and st == 303
          and agent.tool("balance").get("hot", {}).get("hot_sats") == before["hot_sats"],
          {"init": rep3.get("ok"), "login": st, "before": before, "after": ha3})
    mcp_base = f"http://127.0.0.1:{P_MCP}"
    tries = agent_rotation_attempts(mcp_base, [token])
    check("W", "an agent holding the token (and the old owner header) cannot rotate it: the MCP has no rotation endpoint",
          all(st in (401, 404, 405) for _, st, _, _ in tries) and vol_sh(vol2, "cat /v/run/ui/mcp-http-token").stdout.strip() == token,
          [(w, st) for w, st, _, _ in tries])
    ui.post("/agents", "/rotate-token", {"confirm": "1"})
    flash_rot = ui.flash("/agents")
    page_rot = ui.get("/agents")
    m_rot = re.search(r'<code id="mcp-token">([0-9a-f]{64})</code>', page_rot)
    ui_tok = m_rot.group(1) if m_rot else None
    st_old_ui = Mcp(mcp_base, token).start()[0]
    st_old_session = agent.post({"jsonrpc": "2.0", "id": 99, "method": "tools/list"})[0]
    disk = vol_sh(vol2, "stat -c '%u:%g %a' /v/run/ui/mcp-http-token; cat /v/run/ui/mcp-http-token; ls -A /v/run/ui").stdout.split("\n")
    agent_new = Mcp(mcp_base, ui_tok or "")
    st_new_ui = agent_new.start()[0]
    seen = agent_rotation_attempts(mcp_base, [token, ui_tok or ""])
    seen.append(("tools/list", *http("POST", agent_new.url, json.dumps({"jsonrpc": "2.0", "id": 5, "method": "tools/list"}).encode(),
                                     {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                                      "Authorization": f"Bearer {ui_tok}", "Mcp-Session-Id": agent_new.sid or ""})))
    for pth in ("/healthz", "/readyz"):
        seen.append((pth, *http("GET", mcp_base + pth)))
    check("W", "Agents page rotate (no restart): old token 401 at once (its open session too), new works; the UI's file replaced "
               "atomically (10005:10005 0640, no temp file); no MCP response carries the new token",
          "rotated" in flash_rot.lower() and ui_tok and ui_tok != token and st_old_ui == 401 and st_old_session == 401 and st_new_ui == 200
          and disk[:3] == ["10005:10005 640", ui_tok, "mcp-http-token"] and not leaks(seen, ui_tok),
          {"flash": flash_rot, "old": st_old_ui, "old_session": st_old_session, "new": st_new_ui,
           "disk": [d if d != ui_tok else "<token>" for d in disk], "leaks": leaks(seen, ui_tok)})
    token = ui_tok  # the owner hands the agents the new token
    time.sleep(6)
    wc = docker("run", "--rm", "--user", "0", "--network", "none",
                "--mount", f"type=volume,src={vol2},dst=/data/witness,volume-subpath=witness,volume-nocopy=true,readonly",
                "--mount", f"type=volume,src={vol2},dst=/data/signer,volume-subpath=signer,volume-nocopy=true,readonly",
                "xbt-anchor-witness:0.1.0", "check", "--store", "/data/witness", "--log", "/data/signer/.run/signatures.jsonl", check_rc=False)
    check("B", "auditor: the restored witness store checks the restored signature log", wc.returncode == 0, wc.stdout + wc.stderr)

    # --- W: Reset the web UI password (the action deletes ui/password.scrypt and restarts) ---------------------------------
    log("== W: reset the UI password")
    vol_sh(vol2, "rm -f /v/ui/password.scrypt", ro=False)
    docker("rm", "-f", f"{P}-ui")
    run_service(by["ui"], sp["images"], vol2)
    wait_until(lambda: status(f"http://127.0.0.1:{P_UI}/healthz") == 200, 60, "UI back")
    new_code = vol_sh(vol2, "cat /v/ui/setup-code").stdout.strip()
    old = Ui(f"http://127.0.0.1:{P_UI}")
    st_old, loc_old = old.login(pw)
    check("W", "after a reset the old password gets no session (the UI sends every request to its first-run page) and a new setup code waits",
          len(new_code) >= 10 and new_code != code_txt and not old.cookie and loc_old.endswith("setup-password"), {"old_login": [st_old, loc_old, old.cookie]})

    # --- W: Rotate the agent token (the action deletes both copies and restarts; xbt-init makes a new one) -------------
    log("== W: rotate the agent token")
    vol_sh(vol2, "rm -f /v/run/ui/mcp-http-token /v/mcp/secrets/mcp-http-token", ro=False)
    stop_all()
    start_all(sp, vol2)
    wait_until(lambda: status(f"http://127.0.0.1:{P_MCP}/readyz") == 200, 120, "MCP back after the rotation")
    new_tok = vol_sh(vol2, "cat /v/run/ui/mcp-http-token").stdout.strip()
    st_old_tok = Mcp(f"http://127.0.0.1:{P_MCP}", token).start()[0]
    st_new_tok = Mcp(f"http://127.0.0.1:{P_MCP}", new_tok).start()[0]
    check("W", "after Rotate the agent token: a new token in the UI's file; the old one gets 401, the new one works",
          len(new_tok) == 64 and new_tok != token and st_old_tok == 401 and st_new_tok == 200, [st_old_tok, st_new_tok])
    with open(os.path.join(OUT, "facts.json"), "w") as f:
        json.dump({"custody": before, "init_install": rep, "init_after_root_chown": rep2, "init_after_restore": rep3}, f, indent=1, default=str)


def teardown():
    for sid in ["init", "witness", "signer", "mcp", "ui", "knots"]:
        with open(os.path.join(OUT, f"{sid}.log"), "w") as f:
            r = docker("logs", f"{P}-{sid}", check_rc=False)
            f.write(r.stdout + r.stderr)
    names = docker("ps", "-aq", "--filter", f"name=^{P}-").stdout.split()
    if names:
        docker("rm", "-f", *names, check_rc=False)
    vols = docker("volume", "ls", "-q", "--filter", f"name=^{P}-").stdout.split()
    if vols:
        docker("volume", "rm", *vols, check_rc=False)
    docker("network", "rm", NET, check_rc=False)
    sh("rm", "-rf", os.path.join(OUT, "backup"), check_rc=False)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        check("X", "the run completed", False, repr(e))
    finally:
        try:
            teardown()
        except Exception as e:  # noqa: BLE001
            check("X", "teardown", False, repr(e))
        ok = write_results(OUT)
    sys.exit(0 if ok else 1)
