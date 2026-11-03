#!/usr/bin/env python3
"""Two Stream Gateway builds side by side on regtest: how fast each hands miners a new block's work, and what it costs.

    scripts/datum_gateway_bench.py --gateway NAME=PATH --gateway NAME=PATH [--modes solo,pool] [--blocks 30]
                                   [--rounds 2] [--clients 20] [--txs 40] [--idle-s 30]

Each build runs alone, in turn (NAME order, then again for each round, so drift on the box falls on both), on a
fresh Knots BLAKE2b regtest node of its own (P2P_HASH_GATEWAYS/bitcoind, as scripts/p2p_hash/regtest.py runs it),
with CLIENTS Stratum clients that subscribe and authorize and never hash. Pool mode puts `primed` (P2P_HASH_PRIMED,
default primed-new, gateway-held keys on) between the gateway and the node, as the masked pool rental does. Each
block is mined with `generatetoaddress` after TXS wallet transactions, so the template has some to carry. The node's
blocknotify stamps the time first (date +%s.%N), then tells the gateway (curl /NOTIFY), so the clock starts at the
same place for both builds. Per block:
  first_job_ms      blocknotify -> the first mining.notify on the new previous block, at the first client
  all_clients_ms    blocknotify -> the last client's first notify on it (the fan-out)
  full_job_ms       blocknotify -> the first client's first job with the template's transactions (a job id with
                    no N prefix): the template update
  split_job_ms      the same for the first full job whose coinbase class isn't 00: in pool mode, the one carrying
                    the pool's split (class 00 pays only the pool: class00_full_jobs counts those sent, every client)
CPU: the gateway's utime+stime (/proc/<pid>/stat) over IDLE_S seconds with the clients connected and no block, and
over the block phase, as a share of one core.

Ports: DATUM_BENCH_PORT_BASE (default 23961) to BASE+9. Regtest only; nothing leaves loopback.
Report: run/datum_gateway_bench.json (every sample) and a summary on stdout.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

HG = os.environ.get("P2P_HASH_GATEWAYS", os.path.expanduser("~/xbt-rnd/hash-gateways"))
PRIMED = os.environ.get("P2P_HASH_PRIMED", f"{HG}/primed-new")
BASE = int(os.environ.get("DATUM_BENCH_PORT_BASE", "23961"))
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
TICK = os.sysconf("SC_CLK_TCK")


class Client(threading.Thread):
    """A Stratum client that never hashes: every mining.notify it gets, with its arrival time."""

    def __init__(self, port: int, user: str) -> None:
        super().__init__(daemon=True)
        self.port, self.user = port, user
        self.events: list[tuple[float, str, str]] = []  # (t, job id, prevhash)
        self.stop = False
        self.lock = threading.Lock()

    def run(self) -> None:
        while not self.stop:
            try:
                s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            except OSError:
                time.sleep(0.2)
                continue
            s.settimeout(0.5)
            for msg in ({"id": 1, "method": "mining.subscribe", "params": ["datum-bench/0.1"]},
                        {"id": 2, "method": "mining.authorize", "params": [self.user, "x"]}):
                s.sendall((json.dumps(msg) + "\n").encode())
            buf = b""
            while not self.stop:
                try:
                    chunk = s.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    chunk = b""
                if not chunk:
                    break
                now = time.time()
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    try:
                        v = json.loads(line)
                    except ValueError:
                        continue
                    if v.get("method") == "mining.notify":
                        p = v["params"]
                        with self.lock:
                            self.events.append((now, p[0], p[1]))
            s.close()


def cpu_ticks(pid: int) -> int:
    with open(f"/proc/{pid}/stat") as f:
        rest = f.read().rsplit(")", 1)[1].split()
    return int(rest[11]) + int(rest[12])  # utime, stime (fields 14 and 15)


def wait(what: str, secs: float, ok: Any) -> None:
    end = time.time() + secs
    while time.time() < end:
        try:
            if ok():
                return
        except Exception:  # noqa: BLE001  (not up yet)
            pass
        time.sleep(0.2)
    raise RuntimeError(f"{what} did not come up in {secs} s")


def port_open(p: int) -> bool:
    socket.create_connection(("127.0.0.1", p), 1).close()
    return True


def run_one(name: str, gw: str, mode: str, a: argparse.Namespace) -> dict[str, Any]:
    home = tempfile.mkdtemp(prefix=f"dgb-{name}-{mode}-")
    rpc, p2p, st, api, prime, stats = BASE, BASE + 1, BASE + 2, BASE + 3, BASE + 4, BASE + 5
    stamps = f"{home}/blocknotify.txt"
    os.makedirs(f"{home}/node")
    with open(f"{home}/node/bitcoin.conf", "w") as f:
        f.write("regtest=1\nserver=1\nlistenonion=0\ndiscover=0\ndnsseed=0\nfixedseeds=0\nfallbackfee=0.0002\ntxindex=1\nblake2b_headline=Lazarus\n"
                f"[regtest]\nlisten=1\nbind=127.0.0.1\nport={p2p}\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport={rpc}\n"
                f"testactivationheight=blake2b@101\nmaxtipage=315360000\n"
                # the node puts the block hash for every %s: the clock's own %s is split so it isn't one
                f"blocknotify=/bin/sh -c 'echo %s $(date \"+%\"\"s.%N\") >> {stamps}; /usr/bin/curl -fsS -m 2 -o /dev/null http://127.0.0.1:{api}/NOTIFY'\n")
    env = {**os.environ, "LD_LIBRARY_PATH": f"{HG}/lib"}
    procs: list[subprocess.Popen[bytes]] = []
    clients: list[Client] = []
    subprocess.run([f"{HG}/bitcoind", f"-datadir={home}/node", "-daemon"], check=True, env=env, stdout=subprocess.DEVNULL)

    def cli(*args: str) -> str:
        return subprocess.run([f"{HG}/bitcoin-cli", f"-datadir={home}/node", *args], check=True, env=env, capture_output=True, text=True).stdout.strip()

    try:
        wait("node", 60, lambda: cli("getblockcount") != "")
        cli("createwallet", "w")
        address = cli("-rpcwallet=w", "getnewaddress", "", "bech32")
        cli("-rpcwallet=w", "generatetoaddress", "220", address)
        legacy = cli("-rpcwallet=w", "getnewaddress", "", "legacy")
        datum: dict[str, Any] = {"pool_host": "", "pooled_mining_only": False}
        pool_address = legacy
        if mode == "pool":
            os.makedirs(f"{home}/prime")
            with open(f"{home}/prime/seed.json", "w") as f:
                json.dump({"credits": [{"ts": int(time.time()) - 120, "identity": address, "work": 1_000_000_000, "source": 2}]}, f)
            with open(f"{home}/prime/prime.toml", "w") as f:
                f.write(f'listen = "127.0.0.1:{prime}"\nstats-listen = "127.0.0.1:{stats}"\nadvertise-address = "127.0.0.1:{prime}"\ndata-dir = "{home}/prime/data"\n'
                        f'motd = "bench"\nheadline = "Lazarus"\npayout-address = "{address}"\ncoinbase-tag = "Lazarus"\nprime-id = 134\nnetwork = "regtest"\nwindow = 8\n'
                        f'window-min-work = 50000000\nmin-payout = 546\nmin-diff = 1\nfee-bps = 0\nhouse-loopback = false\nrpc = "http://127.0.0.1:{rpc}"\n'
                        f'rpc-cookie = "{home}/node/regtest/.cookie"\npoll = 0.5\nimport-ledger = "{home}/prime/seed.json"\ngateway-key = true\n')
            pub = subprocess.run([PRIMED, "-c", f"{home}/prime/prime.toml", "pubkey"], check=True, capture_output=True, text=True).stdout.strip()
            log = open(f"{home}/primed.log", "ab")
            procs.append(subprocess.Popen([PRIMED, "-c", f"{home}/prime/prime.toml", "run"], stdout=log, stderr=log))
            wait("primed", 30, lambda: port_open(prime))
            datum = {"pool_host": "127.0.0.1", "pool_port": prime, "pool_pubkey": pub, "pool_pass_workers": True, "pool_pass_full_users": True,
                     "pooled_mining_only": True, "protocol_global_timeout": 60}
            pool_address = "bc1qt5praystcdle0nq04e3h02yjszha82uzhww85x6972lcy40k4eyqz9jfaq"
        with open(f"{home}/gw.json", "w") as f:
            json.dump({"bitcoind": {"rpccookiefile": f"{home}/node/regtest/.cookie", "rpcurl": f"http://127.0.0.1:{rpc}", "work_update_seconds": 5, "notify_fallback": True},
                       "stratum": {"listen_addr": "127.0.0.1", "listen_port": st, "vardiff_min": 1, "fingerprint_miners": False},
                       "mining": {"pool_address": pool_address, "coinbase_tag_primary": "Lazarus", "coinbase_tag_secondary": "bench"},
                       "api": {"listen_addr": "127.0.0.1", "listen_port": api, "admin_password": ""},
                       "logger": {"log_to_console": True, "log_to_file": False, "log_level_console": 2}, "datum": datum}, f)
        log = open(f"{home}/gateway.log", "ab")
        gwp = subprocess.Popen([gw, "-c", f"{home}/gw.json"], stdout=log, stderr=log)
        procs.append(gwp)
        wait("gateway", 60, lambda: port_open(st))
        clients = [Client(st, address) for _ in range(a.clients)]
        for c in clients:
            c.start()
        wait("every client's first job", 90, lambda: all(c.events for c in clients))
        time.sleep(3)
        # idle: connected clients, no block
        c0, t0 = cpu_ticks(gwp.pid), time.time()
        time.sleep(a.idle_s)
        idle = (cpu_ticks(gwp.pid) - c0) / TICK / (time.time() - t0)
        # blocks
        samples = []
        c1, t1 = cpu_ticks(gwp.pid), time.time()
        for _ in range(a.blocks):
            for _ in range(a.txs):
                cli("-rpcwallet=w", "sendtoaddress", address, "0.001")
            time.sleep(a.settle_s)  # the gateway's own template refresh (work_update_seconds) takes the transactions in
            with clients[0].lock:
                known = {e[2] for e in clients[0].events}  # previous blocks seen so far: a new one is this block's
            prev = cli("generatetoaddress", "1", address)
            block = json.loads(prev)[0]
            deadline = time.time() + 20
            while time.time() < deadline:
                with open(stamps) as f:
                    t_block = next((float(ln.split()[1]) for ln in f if ln.split()[0] == block), None)
                firsts, fulls, splits, pool_only = [], [], [], 0
                for c in clients:
                    with c.lock:
                        ev = [e for e in c.events if e[2] and (prevhash_matches(e[2], block) or e[2] not in known)]
                    if ev:
                        firsts.append(ev[0][0])
                        full = [e for e in ev if not e[1].startswith(("N", "Q"))]
                        if full:
                            fulls.append(full[0][0])
                        # a full template whose coinbase class is 00 pays only the pool (pool mode): the late-coinbaser window
                        split = [e for e in full if not e[1].endswith("00")]
                        if split:
                            splits.append(split[0][0])
                        pool_only += len([e for e in full if e[1].endswith("00")])
                if t_block and len(firsts) == len(clients) and splits:
                    break
                time.sleep(0.05)
            if not (t_block and firsts):
                samples.append({"block": block, "error": "no job on it in 20 s"})
                continue
            samples.append({"block": block, "first_job_ms": round(1000 * (min(firsts) - t_block), 2),
                            "all_clients_ms": round(1000 * (max(firsts) - t_block), 2) if len(firsts) == len(clients) else None,
                            "full_job_ms": round(1000 * (min(fulls) - t_block), 2) if fulls else None,
                            "split_job_ms": round(1000 * (min(splits) - t_block), 2) if splits else None,
                            "class00_full_jobs": pool_only if mode == "pool" else 0})
        busy = (cpu_ticks(gwp.pid) - c1) / TICK / (time.time() - t1)
        with open(f"{home}/gateway.log", errors="replace") as f:
            banner = next((ln.strip() for ln in f if "git commit" in ln), "")
        return {"name": name, "mode": mode, "gateway": gw, "banner": banner, "cpu_idle_core": round(idle, 5), "cpu_blocks_core": round(busy, 5), "samples": samples}
    finally:
        for c in clients:
            c.stop = True
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
        subprocess.run([f"{HG}/bitcoin-cli", f"-datadir={home}/node", "stop"], env=env, capture_output=True)
        time.sleep(2)
        if os.environ.get("DATUM_BENCH_KEEP") != "1":
            shutil.rmtree(home, ignore_errors=True)


def prevhash_matches(stratum_prev: str, block: str) -> bool:
    """A Stratum prevhash is the block hash in 4-byte words, each word's bytes reversed; match either form."""
    if stratum_prev == block:
        return True
    try:
        raw = bytes.fromhex(block)[::-1]
        words = b"".join(raw[i:i + 4][::-1] for i in range(0, 32, 4))
        return stratum_prev in (words.hex(), raw.hex(), words[::-1].hex())
    except ValueError:
        return False


def pct(xs: list[float], q: float) -> float | None:
    if not xs:
        return None
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(q * (len(xs) - 1) + 0.5))], 2)


def summary(runs: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for r in runs:
        k = f"{r['name']}/{r['mode']}"
        s = out.setdefault(k, {"first_job_ms": [], "all_clients_ms": [], "full_job_ms": [], "split_job_ms": [], "class00_full_jobs": [],
                               "cpu_idle_core": [], "cpu_blocks_core": [], "errors": 0})
        for x in r["samples"]:
            if "error" in x:
                s["errors"] += 1
                continue
            for m in ("first_job_ms", "all_clients_ms", "full_job_ms", "split_job_ms", "class00_full_jobs"):
                if x.get(m) is not None:
                    s[m].append(x[m])
        s["cpu_idle_core"].append(r["cpu_idle_core"])
        s["cpu_blocks_core"].append(r["cpu_blocks_core"])
    table = {}
    for k, s in out.items():
        table[k] = {"blocks": len(s["first_job_ms"]), "errors": s["errors"],
                    **{f"{m}_p50": pct(s[m], 0.5) for m in ("first_job_ms", "all_clients_ms", "full_job_ms", "split_job_ms")},
                    **{f"{m}_p90": pct(s[m], 0.9) for m in ("first_job_ms", "all_clients_ms", "full_job_ms", "split_job_ms")},
                    "class00_full_jobs": sum(s["class00_full_jobs"]),
                    "full_job_ms_mean": round(statistics.mean(s["full_job_ms"]), 2) if s["full_job_ms"] else None,
                    "cpu_idle_pct_core": round(100 * statistics.mean(s["cpu_idle_core"]), 3),
                    "cpu_blocks_pct_core": round(100 * statistics.mean(s["cpu_blocks_core"]), 3)}
    return table


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gateway", action="append", required=True, help="NAME=PATH, two or more")
    ap.add_argument("--modes", default="solo,pool")
    ap.add_argument("--blocks", type=int, default=30)
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--clients", type=int, default=20)
    ap.add_argument("--txs", type=int, default=40)
    ap.add_argument("--settle-s", type=float, default=6.0)
    ap.add_argument("--idle-s", type=float, default=30.0)
    ap.add_argument("--out", default=os.path.join(ROOT, "run", "datum_gateway_bench.json"))
    a = ap.parse_args()
    gws = [g.split("=", 1) for g in a.gateway]
    for _, p in gws:
        if not os.access(p, os.X_OK):
            print(f"datum_gateway_bench: {p} is not an executable", file=sys.stderr)
            return 2
    runs = []
    for rnd in range(a.rounds):
        for mode in a.modes.split(","):
            order = gws if rnd % 2 == 0 else gws[::-1]
            for name, path in order:
                print(f"== round {rnd + 1}, {mode}, {name}", flush=True)
                r = run_one(name, path, mode, a)
                print(json.dumps({k: r[k] for k in ("cpu_idle_core", "cpu_blocks_core")} | summary([r])[f"{name}/{mode}"]), flush=True)
                runs.append(r)
    table = summary(runs)
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w") as f:
        json.dump({"host": socket.gethostname(), "nproc": os.cpu_count(), "args": vars(a), "summary": table, "runs": runs}, f, indent=1)
    print(json.dumps(table, indent=1))
    return 0 if all(v["errors"] == 0 for v in table.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
