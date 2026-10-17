#!/usr/bin/env python3
"""The demo: a film behind the gateway, paid piece by piece as it plays; a swarm paid by lottery.

Run by scripts/demo_film.sh, which builds the binaries and brings up the chain node.

    player ---- payproxy ---- xbt-wallet-mcp ---- xbt-signer ==== lf1 ---- lf2 ---- lf3 ==== xbt-gateway ---- Jellyfin
    (a clock, and  (payproxy.py) (MCP, stdio)     (the wallet)   buyer     hop     seller  |  (the film's seller)  (stock, unchanged)
     ffmpeg)                                                                               |
                                                                                           +-- lf4 ==== xbt-gateway ---- the same Jellyfin
                                                                                           |   a seller two hops away
                                                                                           +== xbt-gateway x 20 ---- a file server
                                                                                               (the swarm: one a seller each)

What is real: the signer, the MCP server and the gateways (the release binaries of this tree; the
ticket and lottery rules are the shipped ones, and docs/DEMO.md, "What the demo's settings change",
lists every setting this file sets to something else), four Lightning Fork nodes whose
channels carry 30 pending payments each, and the service: a stock Jellyfin in its own container,
set up over its own API as a node runner would in its web pages (a library, a user without admin
rights), or a Jellyfin that already runs somewhere (DEMO_JELLYFIN_URL), or, with DEMO_SERVICE=files,
a stock `python3 -m http.server`. None of them knows anything of payments. What this file plays:

  the viewer  `Player`: what a player does with an HLS film, with a clock in place of a screen. It
              asks for the playlist, keeps a few seconds of film ahead of the clock, and can pause,
              seek and close. `ffmpeg` is the ordinary player that decodes the first frame.
  the agent   `Mcp`: an MCP client on the wallet's stdio server, with the wallet's tools and nothing else.
  the wire    `Relay`: a TCP relay between the buyer and the film's gateway, standing for the
              network between them, so that a connection can be dropped in the middle of an answer.
  the hand    a kill and a restart of the seller's gateway.

Checks, each PASS or FAIL with what it saw (all, in this order, when none is named):

  film    the film through one routing hop, paid with stream tickets: what the gateway offers and
          what it does not serve; the first frame; a stretch in real time and what it costs a
          minute; a pause; a seek; a dropped connection; a restart of the seller's gateway; a stop
          and what comes back; the whole film; the four counts of money
  far     the same film from the seller two routing hops away: the first frame, a stretch in real
          time, the whole film, the fees
  agent   an agent with only the wallet's tools buys the first part of the film's file and reads it
  swarm   the film's file in pieces of 256 KiB from 20 gateways at once, paid by draws from the
          buyer's one 30-slot channel

Usage: drive.py [check ...]
Environment: LAB, RUN, OUT, BIN, TICKET_E2E_PORT_BASE (as scripts/ticket_e2e/drive.py);
DEMO_SERVICE (jellyfin, files); DEMO_JELLYFIN_URL, DEMO_JELLYFIN_KEY, DEMO_JELLYFIN_ITEM (a Jellyfin
that already runs: its address, a key of a user that may play the film, the film's item id);
DEMO_JELLYFIN_IMAGE; DEMO_FILM (a film file, or `generate`); DEMO_SAT_PER_MIB (100); DEMO_PLAY_S (90).
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import math
import os
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import zipfile
from functools import partial
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "ticket_e2e"))
import drive as e2e  # noqa: E402  (the end-to-end ticket lab: the wallet, the MCP client, the nodes)
from drive import BIN, OUT, PROCS, RUN, LabError, Mcp, brief, check, lab, measured, send, signer, status  # noqa: E402

BASE = e2e.BASE
BUYER, HOP, NEAR, FAR = "lf1", "lf2", "lf3", "lf4"
NODES = (BUYER, HOP, NEAR, FAR)
GW_NEAR, UP_PORT, GW_FAR, RELAY_PORT, JF_PORT, PROXY_PORT = BASE + 4, BASE + 5, BASE + 6, BASE + 7, BASE + 9, BASE + 10  # BASE+8: lf4's REST
SWARM, SWARM_PORT = 20, BASE + 11
#: The origins as buyers know them. The film's gateway is reached through the relay.
ORIGIN_NEAR, ORIGIN_FAR = f"http://127.0.0.1:{RELAY_PORT}", f"http://127.0.0.1:{GW_FAR}"
PROXY = f"http://127.0.0.1:{PROXY_PORT}"
TICKET_MSAT = 1_000_000
MIB = 1 << 20
SAT_PER_MIB = int(os.environ.get("DEMO_SAT_PER_MIB", "100"))
PLAY_S = float(os.environ.get("DEMO_PLAY_S", "90"))
BUFFER_S = 12.0
PIECE = 262_144
PIECE_MSAT = 1_000  # a sat for a piece of 256 KiB: one draw in 64 wins a payment of 64 sat
SERVICE = "jellyfin" if os.environ.get("DEMO_JELLYFIN_URL") else os.environ.get("DEMO_SERVICE", "jellyfin")
JF_IMAGE = os.environ.get("DEMO_JELLYFIN_IMAGE", "jellyfin/jellyfin:10.11.0")
JF_NAME = os.environ.get("COMPOSE_PROJECT_NAME", "demofilm") + "-jellyfin"
#: Big Buck Bunny, (c) 2008 Blender Foundation, www.bigbuckbunny.org, Creative Commons Attribution 3.0.
FILM_URLS = ("https://ftp.nluug.nl/pub/graphics/blender/demo/movies/BBB/bbb_sunflower_1080p_30fps_normal.mp4.zip",
             "https://ftp.halifax.rwth-aachen.de/blender/demo/movies/BBB/bbb_sunflower_1080p_30fps_normal.mp4.zip")
FILM_SHA256 = "ae51005850b0ff757fe60c3dd7a12d754d3cd2397d87d939b55235e457f97658"
FILM_LICENCE = "Big Buck Bunny, (c) 2008 Blender Foundation, www.bigbuckbunny.org, CC BY 3.0"
NETWORK = [""]
CAPTURES = os.path.join(OUT, "demo-captures")


def capture(name: str, lines: list[str]) -> None:
    """A text capture for the write-up: printed, and kept under run/demo-captures."""
    os.makedirs(CAPTURES, exist_ok=True)
    with open(os.path.join(CAPTURES, name + ".txt"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join("  | " + x for x in lines), flush=True)


def clock(secs: float) -> str:
    return f"{int(secs) // 60}:{int(secs) % 60:02d}"


# --- the film -----------------------------------------------------------------------------------------------


class Film:
    """The film file: where it is, what it is, and under what licence it may be passed on."""

    def __init__(self) -> None:
        cache = os.path.join(OUT, "demo-cache")
        os.makedirs(cache, exist_ok=True)
        asked = os.environ.get("DEMO_FILM", "")
        self.licence = FILM_LICENCE
        self.title = "Big Buck Bunny (2008)"
        if asked and asked != "generate":
            self.path, self.licence, self.title = asked, "a file the runner named (DEMO_FILM)", "Demo Film (2026)"
        else:
            self.path = os.path.join(cache, "bbb_sunflower_1080p_30fps_normal.mp4")
            if asked == "generate" or not (os.path.exists(self.path) or self.download(cache)):
                self.path, self.licence, self.title = os.path.join(cache, "generated.mp4"), "generated by this script with ffmpeg's test sources: nobody's work", "Test Pattern (2026)"
                if not os.path.exists(self.path):
                    generate(self.path, 180, "1920x1080", "3500k")
        self.size = os.path.getsize(self.path)
        h = hashlib.sha256()
        with open(self.path, "rb") as f:
            while chunk := f.read(MIB):
                h.update(chunk)
        self.sha256 = h.hexdigest()
        if self.title.startswith("Big Buck") and self.sha256 != FILM_SHA256:
            raise LabError(f"{self.path} is not the Big Buck Bunny file this script names (sha256 {self.sha256})")
        probe = json.loads(subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration,bit_rate:stream=codec_name,width,height", "-of", "json", self.path],
                                          capture_output=True, text=True, check=True).stdout)
        self.seconds = float(probe["format"]["duration"])
        self.mbit = round(int(probe["format"]["bit_rate"]) / 1e6, 2)
        self.streams = [s["codec_name"] + (f" {s['width']}x{s['height']}" if s.get("width") else "") for s in probe["streams"]]

    def download(self, cache: str) -> bool:
        """Fetch the film from a mirror of the Blender Foundation's files. False: no mirror gave it."""
        for url in FILM_URLS:
            part = os.path.join(cache, "film.zip.part")
            try:
                print(f"fetching the film: {url}", flush=True)
                with urllib.request.urlopen(url, timeout=60) as r, open(part, "wb") as f:
                    shutil.copyfileobj(r, f, MIB)
                with zipfile.ZipFile(part) as z:
                    z.extract("bbb_sunflower_1080p_30fps_normal.mp4", cache)
                return True
            except (OSError, zipfile.BadZipFile, KeyError) as e:
                print(f"  not from there: {e}", flush=True)
            finally:
                if os.path.exists(part):
                    os.remove(part)
        return False

    def about(self) -> dict[str, Any]:
        return {"title": self.title, "licence": self.licence, "bytes": self.size, "seconds": round(self.seconds, 1), "mbit_per_s": self.mbit, "streams": self.streams, "sha256": self.sha256}


def generate(path: str, secs: int, size: str, rate: str) -> None:
    """A film nobody owns: ffmpeg's test pattern and a tone."""
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-nostdin", "-f", "lavfi", "-i", f"testsrc2=size={size}:rate=30", "-f", "lavfi", "-i", "sine=frequency=440", "-t", str(secs),
                    "-c:v", "libx264", "-preset", "veryfast", "-b:v", rate, "-g", "60", "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "128k", "-movflags", "+faststart", path], check=True)


# --- the service behind the gateway -------------------------------------------------------------------------


class Service:
    """What the film's gateways stand in front of: its address, the paths the gateway prices, the
    path a player opens, and the path of the film's file as it is."""

    upstream = ""
    routes: list[str] = []
    play = ""
    file = ""
    #: A path the service would answer and the gateway has no route for.
    outside = ""
    what = ""


def jf(method: str, path: str, body: Any = None, token: str = "", port: int = JF_PORT) -> tuple[int, Any]:
    headers = {"Content-Type": "application/json", "Authorization": 'MediaBrowser Client="demo", Device="demo_film", DeviceId="demo-film", Version="1"' + (f', Token="{token}"' if token else "")}
    status_code, _, raw = send(method, path, port, headers, json.dumps(body).encode() if body is not None else b"")
    try:
        return status_code, json.loads(raw) if raw else None
    except ValueError:
        return status_code, None


def jf_ok(method: str, path: str, body: Any = None, token: str = "") -> Any:
    status_code, out = jf(method, path, body, token)
    if status_code >= 300:
        raise LabError(f"Jellyfin {method} {path.split('?')[0]}: {status_code}")
    return out


def jf_movies(token: str) -> dict[str, str]:
    return {i["Name"]: i["Id"] for i in jf_ok("GET", "/Items?Recursive=true&IncludeItemTypes=Movie", token=token)["Items"]}


def hls_query(item: str, key: str) -> str:
    """What a Jellyfin client asks for when it wants the film as HLS in codecs every player has:
    the video as it is (H.264 is copied, not encoded again), the sound as AAC."""
    return f"MediaSourceId={item}&api_key={key}&VideoCodec=h264&AudioCodec=aac&SegmentContainer=ts&TranscodingMaxAudioChannels=2"


def jellyfin_container(film: Film) -> Service:
    """A stock Jellyfin in its own container, set up as its first-run pages set it up: an owner, a
    library `Open films` with the one film, a second library the demo must never reach, and a user
    `stream-demo` without admin rights who sees `Open films` only."""
    root = f"{RUN}/jellyfin"
    title = film.title
    for d in ("config", "cache", f"media/open/{title}", "media/private/Home Video (2025)"):
        os.makedirs(f"{root}/{d}", exist_ok=True)
    dest = f"{root}/media/open/{title}/{title}.mp4"
    try:
        os.link(film.path, dest)
    except OSError:
        shutil.copyfile(film.path, dest)
    generate(f"{root}/media/private/Home Video (2025)/Home Video (2025).mp4", 10, "640x360", "500k")
    subprocess.run(["docker", "rm", "-f", JF_NAME], capture_output=True, check=False)
    run = subprocess.run(["docker", "run", "-d", "--name", JF_NAME, "--cpus", "2", "--user", f"{os.getuid()}:{os.getgid()}", "-p", f"127.0.0.1:{JF_PORT}:8096",
                          "-v", f"{root}/config:/config", "-v", f"{root}/cache:/cache", "-v", f"{root}/media:/media:ro", JF_IMAGE], capture_output=True, text=True, check=False)
    if run.returncode != 0:
        raise LabError(f"docker run {JF_IMAGE}: {run.stderr.strip()[:300]}")
    # it answers 503 to its setup pages while it is still starting
    lab.wait("Jellyfin", 180, lambda: jf("GET", "/System/Info/Public")[0] == 200 and jf("GET", "/Startup/Configuration")[0] == 200)
    info = jf_ok("GET", "/System/Info/Public")
    version = info.get("Version") or info.get("version") or "?"  # this one answer is in camel case until the server is set up
    owner_pw, demo_pw = os.urandom(12).hex(), os.urandom(12).hex()
    jf_ok("POST", "/Startup/Configuration", {"UICulture": "en-US", "MetadataCountryCode": "US", "PreferredMetadataLanguage": "en"})
    jf_ok("GET", "/Startup/User")
    jf_ok("POST", "/Startup/User", {"Name": "owner", "Password": owner_pw})
    jf_ok("POST", "/Startup/Complete")
    admin = jf_ok("POST", "/Users/AuthenticateByName", {"Username": "owner", "Pw": owner_pw})["AccessToken"]
    # no metadata or pictures are fetched from the internet for these libraries
    options = {"LibraryOptions": {"EnableRealtimeMonitor": False, "TypeOptions": [{"Type": "Movie", "MetadataFetchers": [], "ImageFetchers": []}]}}
    for name, path in (("Open films", "/media/open"), ("Private", "/media/private")):
        jf_ok("POST", f"/Library/VirtualFolders?name={urllib.parse.quote(name)}&collectionType=movies&paths={urllib.parse.quote(path, safe='')}&refreshLibrary=true", options, admin)
    lab.wait("Jellyfin has scanned both libraries", 300, lambda: len(jf_movies(admin)) >= 2, every=1)
    movies = jf_movies(admin)
    item = next(i for n, i in movies.items() if not n.startswith("Home Video"))
    private = movies["Home Video"] if "Home Video" in movies else next(i for n, i in movies.items() if n.startswith("Home Video"))
    open_lib = next(v["ItemId"] for v in jf_ok("GET", "/Library/VirtualFolders", token=admin) if v["Name"] == "Open films")
    user = jf_ok("POST", "/Users/New", {"Name": "stream-demo", "Password": demo_pw}, admin)
    policy = dict(user["Policy"], IsAdministrator=False, EnableAllFolders=False, EnabledFolders=[open_lib], EnableContentDeletion=False, EnableContentDownloading=False,
                  EnableLiveTvAccess=False, EnableLiveTvManagement=False, EnableAllChannels=False)
    jf_ok("POST", f"/Users/{user['Id']}/Policy", policy, admin)
    key = jf_ok("POST", "/Users/AuthenticateByName", {"Username": "stream-demo", "Pw": demo_pw})["AccessToken"]
    sees = sorted(i["Name"] for i in jf_ok("GET", f"/Items?Recursive=true&IncludeItemTypes=Movie&userId={user['Id']}", token=key)["Items"])
    check("setup: a stock Jellyfin is up with a library of one freely licensed film and a user without admin rights who sees that library only",
          len(sees) == 1 and sees[0].startswith(film.title.rsplit(" (", 1)[0]) and policy["IsAdministrator"] is False, {"jellyfin": version, "image": JF_IMAGE, "the_demo_user_sees": sees, "licence": film.licence})
    s = Service()
    s.upstream, s.routes = f"http://127.0.0.1:{JF_PORT}", [f"/Videos/{item}/"]
    s.play, s.file, s.outside = f"/Videos/{item}/master.m3u8?{hls_query(item, key)}", f"/Videos/{item}/stream?static=true", f"/Videos/{private}/stream?static=true"
    s.what = f"Jellyfin {version} (the image {JF_IMAGE}, unchanged), in a container on this host"
    return s


def jellyfin_running() -> Service:
    """A Jellyfin that already runs: nothing on it is changed. Its owner has made a library of
    freely licensed films and a user who sees that library only, and names the film here."""
    url, key, item = (os.environ.get(k, "") for k in ("DEMO_JELLYFIN_URL", "DEMO_JELLYFIN_KEY", "DEMO_JELLYFIN_ITEM"))
    if not (url.startswith("http://") and key and item):
        raise LabError("DEMO_JELLYFIN_URL (http://host:port), DEMO_JELLYFIN_KEY and DEMO_JELLYFIN_ITEM are all needed for a Jellyfin that already runs")
    s = Service()
    s.upstream, s.routes = url.rstrip("/"), [f"/Videos/{item}/"]
    s.play, s.file = f"/Videos/{item}/master.m3u8?{hls_query(item, key)}", f"/Videos/{item}/stream?static=true"
    s.outside = "/Videos/00000000000000000000000000000000/stream?static=true"
    s.what = "a Jellyfin that was already running, unchanged"
    return s


def file_server(film: Film) -> Service:
    """The film cut into HLS by ffmpeg (the video and sound copied, not encoded again) behind the
    stock file server that also serves the swarm's pieces."""
    os.makedirs(f"{RUN}/www/film", exist_ok=True)
    os.makedirs(f"{RUN}/www/private", exist_ok=True)
    shutil.copyfile(film.path, f"{RUN}/www/film/film.mp4")
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-nostdin", "-i", film.path, "-map", "0:v:0", "-map", "0:a:0", "-c:v", "copy", "-c:a", "aac", "-ac", "2", "-f", "hls",
                    "-hls_time", "6", "-hls_playlist_type", "vod", "-hls_segment_filename", f"{RUN}/www/film/%04d.ts", f"{RUN}/www/film/main.m3u8"], check=True)
    with open(f"{RUN}/www/private/notes.txt", "w") as f:
        f.write("not for sale\n")
    s = Service()
    s.upstream, s.routes = f"http://127.0.0.1:{UP_PORT}", ["/film/"]
    s.play, s.file, s.outside = "/film/main.m3u8", "/film/film.mp4", "/private/notes.txt"
    s.what = "python3 -m http.server (stock), serving the film cut into HLS by ffmpeg"
    return s


# --- the wallet, the sellers, the wire ---------------------------------------------------------------------


def swarm_origin(i: int) -> str:
    return f"http://127.0.0.1:{SWARM_PORT + i}"


class Wallet(e2e.Wallet):
    def policy(self) -> dict[str, Any]:
        near, far = lab.pubkey(NEAR), lab.pubkey(FAR)
        swarm = [swarm_origin(i) for i in range(SWARM)]
        return {
            # the film's two sellers, each tied to its node, and the swarm's 20 (which share the near seller's node)
            "allowlist": [ORIGIN_NEAR, ORIGIN_FAR] + swarm,
            "counterparties": {ORIGIN_NEAR: {"ln_node": near}, ORIGIN_FAR: {"ln_node": far}, **{o: {"ln_node": near} for o in swarm}},
            "max_per_tx_sats": 50_000,
            "daily_budget_sats": 4_000_000,
            "weekly_budget_sats": 8_000_000,
            "per_counterparty_cap_sats": 4_000_000,
            "velocity_max": 1_000,
            "velocity_window_s": 3600,
            "human_threshold_sats": 40_000,
            "split_window_s": 0,
            "regtest_mine": False,
            "anchor_interval_s": 3600,
            "ln": {"enabled": True, "split_height": e2e.SPLIT},
            # Not the shipped policy. Shipped and kept: 2 tickets held with a seller, 15 held in all, tickets of 1,000 sat,
            # wins of 64 sat through a hop. Changed here (shipped value in brackets): velocity_max above (8), max_sellers
            # (15: the swarm pays 20 at once), max_new_sellers_per_min (30), max_sends_per_hour (1,200), max_answer_s (50);
            # the budgets, max_per_tx_sats and human_threshold_sats above are a lab wallet's, lower than shipped;
            # split_window_s is 0 (600) and anchor_interval_s 3600 (60); and min_expected_wins is 0 (4): as shipped, the
            # swarm's calls, each expecting under one win from its seller, would be paid with a prepaid ticket each, and
            # what the swarm shows is the draws. docs/DEMO.md has the table
            "tickets": {"enabled": True, "max_sellers": SWARM + 8, "max_new_sellers_per_min": 200, "max_sends_per_hour": 100_000, "max_answer_s": 120,
                        "lottery": {"min_expected_wins": 0},
                        "tasks": {"film": {"budget_sats": 1_000_000}, "swarm": {"budget_sats": 100_000, "max_sellers": SWARM + 8}}},
        }


def write_gateway(name: str, port: int, public: str, node: str, upstream: str, routes: list[dict[str, Any]], lottery: dict[str, Any] | None = None, tick_ms: int = 500) -> dict[str, Any]:
    cfg: dict[str, Any] = {
        "listen": f"127.0.0.1:{port}",
        "public_url": public,
        "upstream": upstream,
        "state_dir": f"{RUN}/state-{name}",
        "chain": "regtest",
        "network": NETWORK[0],
        "node": {"rest": f"https://127.0.0.1:{lab.PORT[node]}", "tls_cert": f"{RUN}/{node}.tls.cert", "macaroon": f"{RUN}/{node}.invoices.macaroon", "info_macaroon": f"{RUN}/{node}.info.macaroon"},
        # every buyer of this lab comes from 127.0.0.1: no cap on sessions from one address (shipped: 2). The other
        # caps as shipped
        "caps": {"sessions_per_address": 0},
        # not as shipped: a block height may be 30 s old (shipped: 10), and the swarm's gateways tick every 5 s
        # (shipped and here for the film's: 500 ms)
        "times": {"height_max_age_secs": 30, "tick_ms": tick_ms},
        "routes": routes,
    }
    if lottery is not None:
        cfg["lottery"] = lottery
    with open(f"{RUN}/{name}.json", "w") as f:
        json.dump(cfg, f, indent=1)
    return cfg


def start_gateway(name: str) -> None:
    with open(f"{RUN}/{name}.log", "ab") as log:
        PROCS[name] = subprocess.Popen([f"{BIN}/xbt-gateway", f"{RUN}/{name}.json"], stdout=log, stderr=log)


def gateway_up(port: int) -> bool:
    try:
        return json.loads(send("GET", "/x402/ticket/health", port)[2])["height"] is not None
    except (OSError, ValueError, KeyError, http.client.HTTPException):
        return False


class Relay:
    """A TCP relay in front of a gateway: the network between a buyer and a seller. It passes every
    byte on unchanged, and can drop a connection once, after it has carried a stated number of the
    seller's bytes: a connection that is lost in the middle of an answer."""

    def __init__(self, port: int, to: int) -> None:
        self.to, self.cut_after, self.cuts = to, 0, 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(64)
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self) -> None:
        while True:
            try:
                client, _ = self.sock.accept()
                up = socket.create_connection(("127.0.0.1", self.to), timeout=10)
                up.settimeout(None)
            except OSError:
                continue
            threading.Thread(target=self.pump, args=(client, up, False), daemon=True).start()
            threading.Thread(target=self.pump, args=(up, client, True), daemon=True).start()

    def pump(self, src: socket.socket, dst: socket.socket, from_seller: bool) -> None:
        carried = 0
        try:
            while chunk := src.recv(1 << 16):
                carried += len(chunk)
                if from_seller and self.cut_after and carried > self.cut_after:
                    self.cut_after, self.cuts = 0, self.cuts + 1
                    break  # the bytes of this read are lost with the connection
                dst.sendall(chunk)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                s.close()


RELAY: list[Relay] = []
SERVICE_NOW: list[Service] = []
FILM: list[Film] = []


def invoices(node: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    offset = 0
    while True:
        page = lab.get(node, f"/v1/invoices?index_offset={offset}&num_max_invoices=1000")
        for i in page.get("invoices", []):
            out[base64.b64decode(i["r_hash"]).hex()] = i
        if len(page.get("invoices", [])) < 1000:
            return out
        offset = int(page["last_index_offset"])


def setup() -> None:
    film = Film()
    FILM.append(film)
    print("the film: " + json.dumps(film.about()), flush=True)
    lab.wait("the chain node", 120, lambda: lab.chain("getblockchaininfo"))
    lab.chain("createwallet", "lab")
    lab.chain("createwallet", "agent")
    lab.wallet("generatetoaddress", "130", lab.wallet("getnewaddress"))
    lab.dc("up", "-d", *NODES)

    def ready(node: str) -> bool:
        lab.load_credentials(node)
        return lab.synced(node)

    for node in NODES:
        lab.wait(f"{node} answering and synced", 180, partial(ready, node))
    e2e.send_pinned(lab.lncli(BUYER, "newaddress", "p2wkh")["address"], "0.2")
    lab.fund(HOP, "0.2")
    lab.fund(NEAR, "0.2")
    lab.mine(6, NODES)
    for node in (BUYER, HOP, NEAR):
        lab.wait(f"{node}'s coin", 60, partial(lab.wallet_sat, node))
    e2e.open_channel(BUYER, HOP, 5_000_000)
    e2e.open_channel(HOP, NEAR, 5_000_000)
    e2e.open_channel(NEAR, FAR, 5_000_000)
    lab.mine(8, NODES)
    for node, count in ((BUYER, 1), (HOP, 2), (NEAR, 2), (FAR, 1)):
        lab.wait(f"{node}'s channels active", 240, partial(e2e.active, node, count))
    lab.wait("the buyer knows the three channels", 300, lambda: lab.known_channels(BUYER) >= 3, every=2)
    slots = {n: min(int(c[k]["max_accepted_htlcs"]) for c in lab.channels(n) for k in ("local_constraints", "remote_constraints")) for n in (BUYER, NEAR, FAR)}
    check("setup: four Lightning Fork nodes in a line, and every channel a ticket crosses carries 30 pending payments", slots == {BUYER: 30, NEAR: 30, FAR: 30}, slots)
    os.makedirs(f"{RUN}/keys", exist_ok=True)
    with open(f"{RUN}/rpc.cookie", "w") as f:
        f.write("lab:lab")
    # the credentials: the wallet's rail macaroon for the buyer's node, and the two narrow ones of each seller's gateway
    baked = [("rail", BUYER, lab.BUYER_PERMISSIONS)] + [(f"{n}.{kind}", n, perms) for n in (NEAR, FAR) for kind, perms in (("invoices", lab.SELLER_PERMISSIONS), ("info", ("info:read",)))]
    for name, node, perms in baked:
        with open(f"{RUN}/{name}.macaroon", "wb") as f:
            f.write(bytes.fromhex(lab.bake(node, perms)))
        os.chmod(f"{RUN}/{name}.macaroon", 0o600)
    NETWORK[0] = "bip122:" + lab.chain("getblockhash", "101")[:32]
    # the stock file server: the swarm's pieces, and the film where no Jellyfin is used
    os.makedirs(f"{RUN}/www/pieces", exist_ok=True)
    service = file_server(film) if SERVICE == "files" else jellyfin_running() if os.environ.get("DEMO_JELLYFIN_URL") else jellyfin_container(film)
    SERVICE_NOW.append(service)
    with open(f"{RUN}/upstream.log", "ab") as log:
        PROCS["upstream"] = subprocess.Popen([sys.executable, "-m", "http.server", str(UP_PORT), "--bind", "127.0.0.1", "--directory", f"{RUN}/www"], stdout=log, stderr=log)
    lab.wait("the file server", 20, lambda: send("GET", "/pieces/", UP_PORT)[0] == 200, every=0.1)
    # the film's two sellers: one price, by the byte, for the film's own paths and for nothing else
    price = {"byte_msat": SAT_PER_MIB * 1000, "per_bytes": MIB}
    routes = [{"path": p, "price": price} for p in service.routes]
    cfg = write_gateway("gateway-near", GW_NEAR, ORIGIN_NEAR, NEAR, service.upstream, routes)
    write_gateway("gateway-far", GW_FAR, ORIGIN_FAR, FAR, service.upstream, routes)
    shown = json.loads(json.dumps(cfg).replace(RUN, "/var/lib/xbt-gateway").replace(service.upstream, "http://127.0.0.1:8096" if SERVICE == "jellyfin" else service.upstream))
    capture("1-the-sellers-config", ["The whole of the seller's side: the gateway's config for the film (paths shortened).", ""] + json.dumps(shown, indent=1).splitlines())
    # the swarm: 20 gateways beside the near seller's node, each offering the lottery for pieces of 256 KiB
    for i in range(SWARM):
        write_gateway(f"swarm{i}", SWARM_PORT + i, swarm_origin(i), NEAR, f"http://127.0.0.1:{UP_PORT}", [{"path": "/pieces/", "price": {"byte_msat": PIECE_MSAT, "per_bytes": PIECE}}],
                      lottery={"piece_bytes": PIECE, "sessions_per_address": 0}, tick_ms=5000)
    for name in ["gateway-near", "gateway-far"] + [f"swarm{i}" for i in range(SWARM)]:
        start_gateway(name)
    lab.wait("every gateway", 120, lambda: all(gateway_up(p) for p in [GW_NEAR, GW_FAR] + [SWARM_PORT + i for i in range(SWARM)]), every=0.5)
    RELAY.append(Relay(RELAY_PORT, GW_NEAR))
    # the wallet stores every body whole, for the proxy to pass on
    os.environ["B2_BODY_CAP"] = "0"
    e2e.WALLET_PROC = Wallet()
    e2e.WALLET_PROC.write_policy()
    e2e.WALLET_PROC.start()
    st = signer("ln_status")
    check("setup: the wallet's Lightning rail is ready on the buyer's node", st.get("ready") is True, {"ready": st.get("ready"), "warnings": st.get("warnings")})


# --- the buyer's side: the proxy and the viewer --------------------------------------------------------------


def start_proxy(seller: str) -> None:
    stop_proxy()
    env = dict(os.environ, B2_SIGNER_SOCK=e2e.SOCK)
    with open(f"{RUN}/proxy.log", "ab") as log:
        PROCS["proxy"] = subprocess.Popen([sys.executable, os.path.join(HERE, "payproxy.py"), "--seller", seller, "--listen", f"127.0.0.1:{PROXY_PORT}", "--mcp", f"{BIN}/xbt-wallet-mcp",
                                           "--task", "film", "--max-sats", "2000", "--idle-stop", "120", "--play", SERVICE_NOW[0].play, "--log", f"{RUN}/proxy-mcp.log"],
                                          env=env, stdout=log, stderr=log)
    lab.wait("the paying proxy", 30, lambda: send("GET", "/-/status", PROXY_PORT)[0] == 200, every=0.1)


def stop_proxy() -> None:
    p = PROCS.pop("proxy", None)
    if p is not None and p.poll() is None:
        p.send_signal(signal.SIGTERM)
        try:
            p.wait(30)
        except subprocess.TimeoutExpired:
            p.kill()


def readout() -> dict[str, Any]:
    return json.loads(send("GET", "/-/status", PROXY_PORT)[2])


def proxy_stop() -> dict[str, Any]:
    return json.loads(send("POST", "/-/stop", PROXY_PORT)[2])


class Player:
    """What a player does with an HLS film, with a clock in place of a screen. It reads the
    playlist, then keeps `buffer_s` seconds of film ahead of the clock, one segment at a time, as
    players do. Paused, the clock stands still, so it stops asking once that much is ahead. A
    segment that fails is asked for again; while nothing is ahead of the clock, the film stalls."""

    def __init__(self, play: str, buffer_s: float = BUFFER_S) -> None:
        self.play_path, self.buffer_s = play, buffer_s
        self.lock = threading.Lock()
        self.segments: list[tuple[float, float, str]] = []  # (starts at, lasts, path)
        self.pos, self.ahead_to, self.next, self.epoch = 0.0, 0.0, 0, 0
        self.playing, self.closed, self.fetching = False, False, False
        self.at = time.monotonic()
        self.got_segments, self.got_bytes, self.got_seconds, self.stalled_s = 0, 0, 0.0, 0.0
        self.errors: list[str] = []
        self.last_ok = 0.0
        self.thread = threading.Thread(target=self.run, daemon=True)

    def get(self, path: str) -> bytes:
        status_code, _, body = send("GET", path, PROXY_PORT)
        if status_code != 200:
            raise LabError(f"{status_code} {body[:200]!r}")
        return body

    def open(self) -> "Player":
        text = self.get(self.play_path).decode()
        path = self.play_path
        if "#EXTINF" not in text:
            # a master playlist: the first variant
            path = urllib.parse.urljoin(self.play_path, next(x for x in text.splitlines() if x and not x.startswith("#")))
            text = self.get(path).decode()
        at, lasts = 0.0, 0.0
        for line in text.splitlines():
            if line.startswith("#EXTINF:"):
                lasts = float(line[8:].split(",")[0])
            elif line and not line.startswith("#"):
                self.segments.append((at, lasts, urllib.parse.urljoin(path, line)))
                at += lasts
        if not self.segments:
            raise LabError("the playlist names no segment")
        self.thread.start()
        return self

    def tick(self) -> None:
        """Move the clock. Called with the lock held."""
        now = time.monotonic()
        dt, self.at = now - self.at, now
        if not self.playing:
            return
        room = max(self.ahead_to - self.pos, 0.0)
        self.pos += min(dt, room)
        if dt > room and self.pos < self.length():
            self.stalled_s += dt - room

    def length(self) -> float:
        return self.segments[-1][0] + self.segments[-1][1]

    def run(self) -> None:
        while not self.closed:
            with self.lock:
                self.tick()
                want = self.ahead_to - self.pos < self.buffer_s and self.next < len(self.segments)
                idx, epoch = self.next, self.epoch
                self.fetching = want
            if not want:
                time.sleep(0.02)
                continue
            _, lasts, path = self.segments[idx]
            try:
                body = self.get(path)
            except (LabError, OSError, http.client.HTTPException) as e:
                with self.lock:
                    self.errors.append(f"segment {idx}: {str(e)[:160]}")
                time.sleep(0.5)
                continue
            with self.lock:
                self.tick()
                if epoch != self.epoch:
                    continue  # the viewer has moved on: this segment is not shown
                self.next, self.ahead_to = idx + 1, self.segments[idx][0] + lasts
                self.got_segments, self.got_bytes, self.got_seconds = self.got_segments + 1, self.got_bytes + len(body), self.got_seconds + lasts
                self.last_ok = time.monotonic()

    def play(self) -> None:
        with self.lock:
            self.tick()
            self.playing = True

    def pause(self) -> None:
        with self.lock:
            self.tick()
            self.playing = False

    def seek(self, to: float) -> None:
        with self.lock:
            self.tick()
            idx = max(i for i, s in enumerate(self.segments) if s[0] <= to)
            self.pos, self.ahead_to, self.next, self.epoch = to, self.segments[idx][0], idx, self.epoch + 1

    def now(self) -> dict[str, Any]:
        with self.lock:
            self.tick()
            return {"position": round(self.pos, 1), "ahead_s": round(max(self.ahead_to - self.pos, 0), 1), "segments": self.got_segments, "bytes": self.got_bytes,
                    "film_seconds_bought": round(self.got_seconds, 1), "stalled_s": round(self.stalled_s, 2), "failed_requests": len(self.errors), "fetching": self.fetching}

    def settled(self) -> bool:
        """Nothing is being asked for and nothing more will be until the clock moves."""
        with self.lock:
            return not self.fetching and (self.ahead_to - self.pos >= self.buffer_s or self.next >= len(self.segments))

    def close(self) -> None:
        self.closed = True
        self.thread.join(200)


def line(p: Player | None, r: dict[str, Any], t0: float) -> str:
    """One line of the live readout."""
    held = f"{r['held_tickets']} held" if r.get("held_tickets") is not None else "held ?"
    left = "" if r.get("balance_sats") is None else f"  {r['balance_sats']:,} sat left with the seller"
    film = ""
    if p is not None:
        n = p.now()
        film = f"film {clock(n['position'])} (+{n['ahead_s']:.0f} s ahead)  "
    return (f"{clock(time.monotonic() - t0)}  {film}{r['bytes'] / MIB:6.1f} MiB  paid {r['paid_sats']:,} sat  {r['tickets_released']} tickets released, {held}{left}")


class Readout:
    """The readout, a line every few seconds while something plays."""

    def __init__(self, p: Player | None, every: float = 5.0) -> None:
        self.p, self.every, self.lines, self.t0 = p, every, [], time.monotonic()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self) -> None:
        while not self.stop.wait(self.every):
            self.say()

    def say(self, note: str = "") -> None:
        try:
            text = line(self.p, readout(), self.t0) + (f"   <- {note}" if note else "")
        except (OSError, ValueError, KeyError, http.client.HTTPException):
            return
        self.lines.append(text)
        print("  | " + text, flush=True)

    def __enter__(self) -> "Readout":
        self.thread.start()
        return self

    def __exit__(self, *_: Any) -> None:
        self.stop.set()
        self.thread.join(10)


class Pending:
    """The payments pending on the buyer's channel, asked every 20 ms while something runs."""

    def __init__(self) -> None:
        self.samples: list[int] = []
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self) -> None:
        while not self.stop.is_set():
            try:
                self.samples.append(lab.pending_htlcs(BUYER))
            except (LabError, OSError, http.client.HTTPException):
                pass
            time.sleep(0.02)

    def __enter__(self) -> "Pending":
        self.thread.start()
        return self

    def __exit__(self, *_: Any) -> None:
        self.stop.set()
        self.thread.join(5)

    def report(self) -> dict[str, Any]:
        n = max(len(self.samples), 1)
        return {"samples": len(self.samples), "most_pending_at_once": max(self.samples or [0]), "nothing_pending_share": round(sum(1 for x in self.samples if x == 0) / n, 3)}


# --- what the nodes and the wallet say -------------------------------------------------------------------------


def money() -> dict[str, Any]:
    """The counts that must be one: what the buyer's node paid, what the sellers' nodes received,
    and what the wallet's ledger holds (each payment and its routing fee)."""
    pays = e2e.buyer_payments()
    done = [p for p in pays.values() if p["status"] == "SUCCEEDED"]
    got = {n: sum(int(i["amt_paid_msat"]) for i in invoices(n).values() if i["state"] == "SETTLED") for n in (NEAR, FAR)}
    st = status()
    rows = e2e.WALLET_PROC.ledger()
    return {"buyer_node_paid_msat": sum(int(p["value_msat"]) for p in done), "sellers_nodes_received_msat": sum(got.values()), "received_by": got,
            "wallet_ledger_sats": sum(int(r["amount_sats"]) for r in rows), "buyer_node_cost_sats": sum(e2e.cost_sats(p) for p in done),
            "fees_msat": sum(int(p["fee_msat"]) for p in done), "payments": len(done), # a held ticket the seller cancelled is a payment that failed on the buyer's node: its sats came back
            "failed_payments": sum(1 for p in pays.values() if p["status"] == "FAILED"),
            "in_flight": sum(1 for p in pays.values() if p["status"] == "IN_FLIGHT"), "booked_not_settled_sats": int(st.get("booked_sats") or 0)}


def agrees(m: dict[str, Any]) -> bool:
    return (m["buyer_node_paid_msat"] == m["sellers_nodes_received_msat"] and m["wallet_ledger_sats"] == m["buyer_node_cost_sats"] and m["in_flight"] == 0
            and m["booked_not_settled_sats"] == 0)


def quiet(secs: float = 90) -> float:
    """Wait until nothing is locked anywhere: nothing pending on the buyer's channel, no ticket
    locked in the wallet's book, nothing booked that is not settled."""

    def ok() -> bool:
        st = status()
        return lab.pending_htlcs(BUYER) == 0 and int((st.get("locked") or {}).get("tickets") or 0) == 0 and int(st.get("booked_sats") or 0) == 0

    return lab.wait("nothing locked anywhere", secs, ok, every=0.25)


def stop_sessions() -> None:
    for s in status().get("sessions", []):
        if s["state"] == "open":
            e2e.agent().tool("ticket_stop", {"session": s["session"]})
    quiet()


def spent(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """What happened between two readings of `money`."""
    n = after["payments"] - before["payments"]
    fees = after["fees_msat"] - before["fees_msat"]
    return {"payments": n, "paid_sats": (after["buyer_node_paid_msat"] - before["buyer_node_paid_msat"]) // 1000, "fees_msat": fees, "fee_msat_a_payment": round(fees / n) if n else None,
            "payments_that_came_back": after["failed_payments"] - before["failed_payments"]}


def first_frame(url: str) -> float:
    """An ordinary player opens the film and decodes its first picture: the seconds that took."""
    t0 = time.monotonic()
    r = subprocess.run(["ffmpeg", "-v", "error", "-nostdin", "-i", url, "-map", "0:v:0", "-frames:v", "1", "-f", "null", "-"], capture_output=True, text=True, timeout=180, check=False)
    if r.returncode != 0:
        raise LabError(f"ffmpeg could not show a first frame: {r.stderr.strip()[-300:]}")
    return time.monotonic() - t0


def first_frames(seller: str, label: str) -> dict[str, Any]:
    """The first frame from nothing (a new session: the terms, two tickets locked through the
    route, the playlist, the first segment), three times; and again with the session open."""
    url = PROXY + SERVICE_NOW[0].play
    cold, warm, cost = [], [], []
    for _ in range(3):
        proxy_stop()
        quiet()
        before = readout()
        cold.append(first_frame(url))
        after = readout()
        cost.append({"paid_sats": after["paid_sats"] - before["paid_sats"], "tickets_released": after["tickets_released"] - before["tickets_released"], "held_tickets": after["held_tickets"],
                     "requests": after["requests"] - before["requests"], "MiB": round((after["bytes"] - before["bytes"]) / MIB, 2)})
        warm.append(first_frame(url))
    proxy_stop()
    quiet()
    out = {"new_session_s": [round(x, 2) for x in cold], "median_s": round(statistics.median(cold), 2), "session_open_s": [round(x, 2) for x in warm],
           "session_open_median_s": round(statistics.median(warm), 2), "what_it_took": cost}
    check(f"{label}: an ordinary player (ffmpeg) pointed at the proxy decodes the film's first frame, from a wallet with no session open, three times",
          all(c["held_tickets"] == 2 and c["tickets_released"] >= 1 for c in cost), out)
    measured(f"{label}_first_frame", out)
    return out


def whole_film(label: str) -> dict[str, Any]:
    """Every segment of the film, one after the other as fast as they come: what the whole film
    is, costs and holds."""
    proxy_stop()
    quiet()
    r0, m0 = readout(), money()
    p = Player(SERVICE_NOW[0].play, buffer_s=1e9)
    t0 = time.monotonic()
    with Pending() as pending, Readout(p, every=10):
        p.open()
        p.pause()  # the clock stands still: it reads on to the end
        lab.wait("the whole film", 1500, lambda: p.now()["segments"] == len(p.segments) or len(p.errors) > 50, every=0.25)
    secs = time.monotonic() - t0
    n = p.now()
    p.close()
    r1 = readout()
    stopped = proxy_stop()
    quiet()
    m1 = money()
    d = spent(m0, m1)
    price_msat = r1["price_msat"] - r0["price_msat"]
    out = {"segments": n["segments"], "of": len(p.segments), "film_seconds": round(p.length(), 1), "MiB": round((r1["bytes"] - r0["bytes"]) / MIB, 1), "price_sats": round(price_msat / 1000, 1),
           "tickets_released": r1["tickets_released"] - r0["tickets_released"], "seconds": round(secs, 1), "failed_requests": n["failed_requests"], **d,
           "pending_on_the_buyers_channel": pending.report(), "left_with_the_seller_msat": [s.get("left_with_the_seller_msat") for s in stopped.get("sessions", [])]}
    check(f"{label}: the whole film arrives, every segment, and what the buyer's node paid for it is the tickets released: the price rounded up to a ticket, and never more than 3 payments pending on the buyer's channel (2 tickets held ahead, and one released and not yet settled)",
          n["segments"] == len(p.segments) and not n["failed_requests"] and d["paid_sats"] * 1000 == out["tickets_released"] * TICKET_MSAT
          and 0 <= d["paid_sats"] * 1000 - price_msat < TICKET_MSAT and out["pending_on_the_buyers_channel"]["most_pending_at_once"] <= 3, out)
    measured(f"{label}_whole_film", out)
    return out


# --- the checks -------------------------------------------------------------------------------------------------


def film() -> None:
    service, about = SERVICE_NOW[0], FILM[0].about()
    stop_sessions()
    start_proxy(ORIGIN_NEAR)
    # what the seller offers, and what it does not serve
    code, headers, _ = send("GET", service.play, RELAY_PORT)
    pr = json.loads(base64.b64decode(headers.get("payment-required", "e30=")))
    offers = [(a.get("scheme"), (a.get("extra") or {}).get("settle")) for a in pr.get("accepts", [])]
    outside = send("GET", service.outside, RELAY_PORT)[0]
    listing = send("GET", "/Items", RELAY_PORT)[0] if SERVICE == "jellyfin" else send("GET", "/", RELAY_PORT)[0]
    check("film: an unpaid request for the film gets a 402 that offers stream tickets (held, and prepaid) and no lottery; a path of the service that is not the film's has no route, and is not served",
          code == 402 and [o[0] for o in offers] == ["ticket", "ticket"] and outside == 404 and listing == 404,
          {"status": code, "offers": offers, "price": f"{SAT_PER_MIB} sat a MiB", "another_film_of_the_same_server": outside, "the_servers_own_pages": listing, "service": service.what})
    measured("film", about)
    measured("price", {"sat_per_MiB": SAT_PER_MIB, "ticket_sats": TICKET_MSAT // 1000, "note": "a number chosen so that a ticket lasts about half a minute of this film; not a market price"})
    first_frames(ORIGIN_NEAR, "film")

    # a stretch in real time, on a proxy started anew so that its counts start at nothing
    start_proxy(ORIGIN_NEAR)
    m0 = money()
    p = Player(service.play)
    with Readout(p) as ro:
        t0 = time.monotonic()
        p.open()
        p.play()
        time.sleep(PLAY_S)
        n, r = p.now(), readout()
        ro.say(f"{PLAY_S:.0f} s of playing")
        per_min = r["price_msat"] / 1000 / max(n["film_seconds_bought"], 1) * 60
        check(f"film: the film plays in real time for {PLAY_S:.0f} s through one routing hop without a stall, bought a few seconds ahead of the clock and paid for as it arrives",
              n["stalled_s"] < 1.0 and not n["failed_requests"] and abs(n["position"] - PLAY_S) < 3 and r["tickets_released"] >= 1 and r["held_tickets"] == 2,
              {**n, "paid_sats": r["paid_sats"], "tickets_released": r["tickets_released"], "held_tickets": r["held_tickets"], "sats_a_minute_of_film": round(per_min)})
        measured("film_sats_a_minute", {"by_price": round(per_min), "film_seconds_bought": n["film_seconds_bought"], "price_sats": round(r["price_msat"] / 1000, 1),
                                        "film_mbit_per_s": about["mbit_per_s"], "MiB_a_minute": round(r["bytes"] / MIB / max(n["film_seconds_bought"], 1) * 60, 1)})

        # a pause
        pressed = readout()
        p.pause()
        lab.wait("the player to stop asking", 60, p.settled, every=0.05)
        a, paid_a = readout(), money()["payments"]
        ro.say("paused: the player's buffer is full")
        time.sleep(20)
        b, paid_b = readout(), money()["payments"]
        ro.say("20 s into the pause")
        check("film: paused, the player stops asking once its buffer is full and the wallet pays nothing more: at most one ticket after the pause was pressed, none in the 20 s after, and the 2 held tickets stay held, not spent",
              a["tickets_released"] - pressed["tickets_released"] <= 1 and b["tickets_released"] == a["tickets_released"] and b["paid_sats"] == a["paid_sats"] and paid_a == paid_b
              and b["held_tickets"] == 2 and b["requests"] == a["requests"],
              {"tickets_released_after_the_pause_was_pressed": a["tickets_released"] - pressed["tickets_released"], "film_bought_ahead_s": p.now()["ahead_s"], "paid_in_the_20_s_after_sats": b["paid_sats"] - a["paid_sats"],
               "held_tickets": b["held_tickets"], "held_sats": b["held_sats"], "left_of_the_last_ticket_sats": b["balance_sats"]})

        # on again, and a seek
        p.play()
        time.sleep(8)
        was = p.now()
        to = min(300.0, p.length() * 0.5)
        t_seek = time.monotonic()
        p.seek(to)
        lab.wait("the film at the new place", 60, lambda: p.now()["ahead_s"] > 0, every=0.01)
        seek_s = time.monotonic() - t_seek
        time.sleep(6)
        n = p.now()
        ro.say(f"after a seek to {clock(to)}")
        check(f"film: played on after the pause, then a seek to {clock(to)}: the film is there again and plays from the new place",
              was["position"] > PLAY_S + 5 and to + 4 < n["position"] < to + 9 and not n["failed_requests"], {"seek_to_playing_s": round(seek_s, 2), "position": n["position"], "stalled_s_in_all": n["stalled_s"]})
        measured("film_seek_s", round(seek_s, 2))

        # a dropped connection, in the middle of a segment
        before, errs, segs = readout(), len(p.errors), p.now()["segments"]
        RELAY[0].cut_after = 300_000
        t_cut = time.monotonic()
        lab.wait("the connection to drop", 60, lambda: RELAY[0].cuts >= 1, every=0.01)
        t_cut, segs, stall = time.monotonic(), p.now()["segments"], p.now()["stalled_s"]
        lab.wait("the segment to arrive at the second asking", 120, lambda: p.now()["segments"] > segs, every=0.01)
        back_s = time.monotonic() - t_cut
        time.sleep(8)
        after, n = readout(), p.now()
        ro.say("after a dropped connection")
        check("film: the connection to the seller is dropped in the middle of a segment: the player asks again and the film goes on; what the cut answer had brought was paid for and is bought again, and nothing else is lost",
              len(p.errors) > errs and n["segments"] > segs + 1 and after["tickets_released"] - before["tickets_released"] <= 3,
              {"failed_requests": len(p.errors) - errs, "said": p.errors[errs][:200] if len(p.errors) > errs else None, "film_stalled_s": round(n["stalled_s"] - stall, 2),
               "the_segment_whole_after_s": round(back_s, 2),
               "the_cut_answers": after.get("cut_short", [])[-2:], "tickets_released_meanwhile": after["tickets_released"] - before["tickets_released"]})
        measured("film_dropped_connection", {"the_segment_whole_after_s": round(back_s, 2), "film_stalled_s": round(n["stalled_s"] - stall, 2), "failed_requests": len(p.errors) - errs, "the_cut_answers": after.get("cut_short", [])[-2:]})

        # the seller's gateway is killed and started again
        before, errs, segs, stall = readout(), len(p.errors), p.now()["segments"], p.now()["stalled_s"]
        t_kill = time.monotonic()
        PROCS["gateway-near"].kill()
        PROCS["gateway-near"].wait(10)
        time.sleep(8)  # the seller is away for eight seconds: longer than the player goes without asking
        start_gateway("gateway-near")
        lab.wait("the gateway", 60, lambda: gateway_up(GW_NEAR), every=0.05)
        up_s = time.monotonic() - t_kill
        lab.wait("the film to go on after the restart", 240, lambda: p.now()["segments"] > segs + 2, every=0.05)
        back_s = time.monotonic() - t_kill
        time.sleep(3)
        after, n = readout(), p.now()
        ro.say("after the seller's gateway was killed and started again")
        check("film: the seller's gateway is killed and started again 8 s later: the player's requests fail meanwhile and it asks again; the film goes on, with the tickets that were held or with a new session, and the viewer loses at most what was left of one ticket",
              n["segments"] > segs + 2 and len(p.errors) > errs and after["tickets_released"] - before["tickets_released"] <= 4,
              {"gateway_back_after_s": round(up_s, 2), "film_going_again_after_s": round(back_s, 2), "film_stalled_s": round(n["stalled_s"] - stall, 2), "failed_requests": len(p.errors) - errs,
               "said": sorted({e.split(": ", 1)[1][:120] for e in p.errors[errs:]})[:3], "new_session": after["session"] != before["session"],
               "tickets_released_meanwhile": after["tickets_released"] - before["tickets_released"], "balance_before_sats": before["balance_sats"], "balance_after_sats": after["balance_sats"]})
        measured("film_seller_restart", {"gateway_back_after_s": round(up_s, 2), "film_going_again_after_s": round(back_s, 2), "film_stalled_s": round(n["stalled_s"] - stall, 2),
                                         "new_session": after["session"] != before["session"]})

        # the viewer closes the film
        p.pause()
        lab.wait("the player to stop asking", 60, p.settled, every=0.05)
        last = readout()
        t_stop = time.monotonic()
        stopped = proxy_stop()
        back = quiet()
        stop_s = time.monotonic() - t_stop
        ro.say("stopped")
        p.close()
    capture("2-the-readout-while-it-plays", [f"{about['title']}: {about['mbit_per_s']} Mbit/s, {SAT_PER_MIB} sat a MiB, tickets of 1,000 sat, one routing hop. A line every 5 s.", ""] + ro.lines)
    m1 = money()
    check("film: the viewer stops: the 2 tickets that were held and not spent are cancelled by the seller and are back on the buyer's node within 6 s; what is left of the last ticket stays with the seller",
          stop_s <= 6.0 and all(s.get("seller_took_the_cancel") and s.get("still_locked") == [] for s in stopped.get("sessions", [{}])) and m1["in_flight"] == 0,
          {"seconds": round(stop_s, 2), "held_before": {"tickets": last["held_tickets"], "sats": last["held_sats"]}, "stop": stopped.get("sessions"), "wait_s": round(back, 2)})
    capture("3-the-stop", ["What stopping returned, as the proxy reports it:", ""] + json.dumps(stopped, indent=1).splitlines()
            + ["", f"held before the stop: {last['held_tickets']} tickets, {last['held_sats']:,} sat; back on the buyer's node {stop_s:.2f} s after the stop was asked"])
    whole = whole_film("film")
    m2 = money()
    check("film: what the buyer's node paid, what the seller's node received and what the wallet's ledger holds (each ticket and its routing fee) agree, to the millisat",
          agrees(m2), m2)
    measured("film_one_hop_money", {**spent(m0, m2), "of_which_the_whole_film": whole["paid_sats"]})


def far() -> None:
    service = SERVICE_NOW[0]
    stop_sessions()
    start_proxy(ORIGIN_FAR)
    m0 = money()
    first_frames(ORIGIN_FAR, "far")
    start_proxy(ORIGIN_FAR)  # anew, so that its counts start at nothing
    p = Player(service.play)
    with Readout(p) as ro:
        p.open()
        p.play()
        time.sleep(min(PLAY_S, 45))
        n, r = p.now(), readout()
        ro.say("two routing hops")
        p.close()
    check("far: the same film from the seller two routing hops away plays in real time without a stall",
          n["stalled_s"] < 1.0 and not n["failed_requests"] and r["tickets_released"] >= 1 and r["held_tickets"] == 2,
          {**n, "paid_sats": r["paid_sats"], "tickets_released": r["tickets_released"], "held_tickets": r["held_tickets"]})
    whole = whole_film("far")
    m1 = money()
    check("far: after the film from two hops away the buyer's node, the two sellers' nodes and the wallet's ledger agree, to the millisat", agrees(m1), m1)
    measured("far_two_hops_money", {**spent(m0, m1), "of_which_the_whole_film": whole["paid_sats"]})
    stop_proxy()


def agent() -> None:
    """An agent that has the wallet's MCP tools and nothing else: it finds what it may call, buys
    the first part of the film's file with one call that may use 300 sat, and reads what came."""
    service, film_file = SERVICE_NOW[0], FILM[0]
    stop_sessions()
    a = Mcp()
    try:
        tools = sorted(t["name"] for t in a.tools())
        url = ORIGIN_NEAR + service.file
        t0 = time.monotonic()
        r = a.tool("xbt402_pay", {"url": url, "max_sats": 300, "task": "film"})
        secs = time.monotonic() - t0
        got = int(r.get("bytes") or 0)
        stored = r.get("saved_to", "")
        head, same = b"", None
        if stored:
            with open(stored, "rb") as f:
                data = f.read()
            head = data[:12]
            os.remove(stored)
            if not os.environ.get("DEMO_JELLYFIN_URL"):
                with open(film_file.path, "rb") as f:
                    same = f.read(got) == data
        by_count = math.ceil(got * SAT_PER_MIB * 1000 / MIB)
        check("agent: an agent with only the wallet's tools buys the first part of the film's file with one call that may use 300 sat: the wallet stops the answer where 300 sat are used by its own count, and what arrived is the file's own first bytes",
              "xbt402_pay" in tools and r.get("verdict") == "allow" and r.get("rail") == "ticket" and r.get("status") == 200 and r.get("complete") is False
              and str(r.get("ended", "")).startswith("stopped by the wallet: max_sats") and 300_000 <= by_count <= 300_000 + 7_000 and same is not False and head[4:8] == b"ftyp",
              {"the_agents_tools": tools, "bytes": got, "price_of_those_bytes_msat": by_count, "charged_sats": r.get("charged_sats"), "tickets_released": r.get("tickets_released"),
               "ended": str(r.get("ended"))[:90], "is_the_films_first_bytes": same, "it_read": head[4:12].decode("latin1"), "seconds": round(secs, 2)})
        st = a.tool("ticket_status", {})
        sid = next((s["session"] for s in st.get("sessions", []) if s["state"] == "open"), "")
        stopped = a.tool("ticket_stop", {"session": sid}) if sid else {}
        quiet()
        check("agent: the agent then stops the session itself, and the tickets it held come back",
              bool(sid) and (stopped.get("http") or {}).get("still_locked") == [], {"session": sid, "stop": {k: (stopped.get("http") or {}).get(k) for k in ("cancel_asked", "cancel_sent", "still_locked")}})
        measured("agent_call", {"bytes": got, "charged_sats": r.get("charged_sats"), "seconds": round(secs, 2), "reply": {k: v for k, v in brief(r).items() if k not in ("receipt", "account")}})
    finally:
        a.close()


def swarm() -> None:
    """The film's file cut into pieces of 256 KiB; piece k is bought from seller k mod 20; 20
    downloads run at once, each with its own agent on the one wallet."""
    film_file = FILM[0]
    stop_sessions()
    hashes = []
    with open(film_file.path, "rb") as f:
        k = 0
        while chunk := f.read(PIECE):
            hashes.append(hashlib.sha256(chunk).hexdigest())
            with open(f"{RUN}/www/pieces/{k:05d}", "wb") as out:
                out.write(chunk)
            k += 1
    pieces = len(hashes)
    os.makedirs(f"{RUN}/swarm-out", exist_ok=True)
    agents = [Mcp() for _ in range(SWARM)]
    results: list[dict[str, Any]] = [{"draws": 0, "wins": 0, "wins_paid": 0, "paid_sats": 0, "pieces": 0, "bad": [], "win_msat": set()} for _ in range(SWARM)]

    def one(i: int) -> None:
        got = results[i]
        for k in range(i, pieces, SWARM):
            try:
                r = agents[i].tool("xbt402_pay", {"url": f"{swarm_origin(i)}/pieces/{k:05d}", "max_sats": 200, "task": "swarm"})
            except (LabError, OSError, ValueError) as e:
                got["bad"].append(f"piece {k}: {str(e)[:160]}")
                continue
            if not (r.get("verdict") == "allow" and r.get("rail") == "lottery" and r.get("status") == 200 and r.get("complete") is True and r.get("body_digest") == hashes[k]
                    and not r.get("wins_unpaid") and r.get("saved_to")):
                got["bad"].append(f"piece {k}: {json.dumps(brief(r))[:300]}")
                continue
            os.replace(r["saved_to"], f"{RUN}/swarm-out/{k:05d}")
            got["pieces"] += 1
            got["paid_sats"] += int(r.get("charged_sats") or 0)
            for key in ("draws", "wins", "wins_paid"):
                got[key] += int(r.get(key) or 0)
            if r.get("win_msat"):
                got["win_msat"].add(int(r["win_msat"]))

    try:
        m0 = money()
        t0 = time.monotonic()
        with Pending() as pending:
            threads = [threading.Thread(target=one, args=(i,)) for i in range(SWARM)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(1200)
        secs = time.monotonic() - t0
        lab.wait("nothing pending on the buyer's channel", 120, lambda: lab.pending_htlcs(BUYER) == 0 and int(status().get("booked_sats") or 0) == 0, every=0.25)
        m1 = money()
        d = spent(m0, m1)
        h = hashlib.sha256()
        for k in range(pieces):
            path = f"{RUN}/swarm-out/{k:05d}"
            if os.path.exists(path):
                with open(path, "rb") as f:
                    h.update(f.read())
        bad = [b for r in results for b in r["bad"]]
        wins = sum(r["wins"] for r in results)
        win_msat = sorted({w for r in results for w in r["win_msat"]})
        price_sats = sum(math.ceil(min(PIECE, film_file.size - k * PIECE) * PIECE_MSAT / PIECE) for k in range(pieces)) / 1000
        paid_nothing = sum(1 for r in results if r["wins"] == 0)
        p = pending.report()
        out = {"sellers": SWARM, "pieces": pieces, "draws": sum(r["draws"] for r in results), "wins": wins, "expected_wins": round(price_sats * 1000 / (win_msat[0] if win_msat else 64_000), 1),
               "win_sats": [w // 1000 for w in win_msat], "price_sats": round(price_sats, 1), **d, "sellers_paid_nothing": paid_nothing, "wins_by_seller": [r["wins"] for r in results],
               "seconds": round(secs, 1), "MiB": round(film_file.size / MIB, 1), "pending_on_the_buyers_channel": p, "bad": bad[:3]}
        check(f"swarm: the film's file arrives whole in {pieces} pieces of 256 KiB from {SWARM} sellers at once, every piece its own hash, each piece one draw, paid by the wallet's own rule with draws",
              not bad and h.hexdigest() == film_file.sha256 and out["draws"] == pieces and sum(r["pieces"] for r in results) == pieces, out)
        check(f"swarm: {SWARM} sellers are paid from the one 30-slot channel: every win is one payment of the win's size, none failed, never more than 9 pending on the channel at once (the wallet sends 8 at a time), and nothing is held between wins",
              d["payments"] == wins and sum(r["wins_paid"] for r in results) == wins and d["payments_that_came_back"] == 0 and len(win_msat) <= 1 and d["paid_sats"] * 1000 == wins * (win_msat[0] if win_msat else 0)
              and p["most_pending_at_once"] <= 9 and lab.pending_htlcs(BUYER) == 0, {**d, **p})
        check("swarm: after the swarm the buyer's node, the sellers' node and the wallet's ledger agree, to the millisat", agrees(m1), m1)
        measured("swarm", out)
        rows = [f"seller {i:2d}  {r['pieces']:3d} pieces  {r['draws']:3d} draws  {r['wins']} wins  paid {r['wins'] * (win_msat[0] if win_msat else 0) // 1000:4d} sat" for i, r in enumerate(results)]
        capture("4-the-swarm", [f"{film_file.title} as a file: {pieces} pieces of 256 KiB at 1 sat a piece ({price_sats:,.0f} sat), from {SWARM} sellers at once, paid by draws.",
                                f"A win is {win_msat[0] // 1000 if win_msat else '?'} sat; one draw in {(win_msat[0] if win_msat else 64_000) // PIECE_MSAT} wins.", ""] + rows
                + ["", f"in all: {out['draws']} draws, {wins} wins ({out['expected_wins']} expected), {d['paid_sats']:,} sat paid for pieces priced {price_sats:,.0f} sat, "
                       f"{paid_nothing} sellers paid nothing, {d['fees_msat'] / 1000:.1f} sat in routing fees, {secs:.0f} s"])
    finally:
        for s in status().get("sessions", []):
            if s["state"] == "open":
                e2e.agent().tool("ticket_stop", {"session": s["session"]})
        for a in agents:
            a.close()


CHECKS = {"film": film, "far": far, "agent": agent, "swarm": swarm}


def main() -> int:
    names = sys.argv[1:] or list(CHECKS)
    unknown = [n for n in names if n not in CHECKS]
    if unknown:
        print(f"unknown check {unknown}; the checks are {' '.join(CHECKS)}", file=sys.stderr)
        return 2
    t0 = time.time()
    try:
        setup()
        print(f"lab up in {time.time() - t0:.0f} s: {BUYER} (buyer) - {HOP} (hop) - {NEAR} (seller) - {FAR} (seller, two hops), height {lab.height()}; the service: {SERVICE_NOW[0].what}", flush=True)
        for name in names:
            try:
                CHECKS[name]()
            except (LabError, OSError, http.client.HTTPException, KeyError, IndexError, ValueError, AssertionError, subprocess.SubprocessError, StopIteration) as e:
                check(f"{name}: ran to its end", False, f"{type(e).__name__}: {e}")
                break  # the lab is in an unknown state: later checks would report that, not themselves
    except (LabError, OSError, http.client.HTTPException, KeyError, ValueError, subprocess.SubprocessError, StopIteration) as e:
        check("setup: the lab came up", False, f"{type(e).__name__}: {e}")
    finally:
        stop_proxy()
        for m in e2e.AGENT:
            if m.proc.poll() is None:
                m.proc.kill()
        for p in PROCS.values():
            if p.poll() is None:
                p.send_signal(signal.SIGTERM)
        if SERVICE == "jellyfin" and not os.environ.get("DEMO_JELLYFIN_URL") and os.environ.get("DEMO_KEEP", "0") != "1":
            subprocess.run(["docker", "rm", "-f", JF_NAME], capture_output=True, check=False)
    e2e.REPORT["failed"] = e2e.FAILED
    e2e.REPORT["seconds"] = round(time.time() - t0)
    with open(os.path.join(OUT, "demo_film.json"), "w") as f:
        json.dump(e2e.REPORT, f, indent=1)
    passed = sum(1 for c in e2e.REPORT["checks"] if c["ok"])
    print(f"demo: {passed} of {len(e2e.REPORT['checks'])} checks passed, {e2e.REPORT['seconds']} s", flush=True)
    return 1 if e2e.FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
