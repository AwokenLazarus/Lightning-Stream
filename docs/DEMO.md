# A film behind the gateway: a guide for a node runner

You run a Lightning node and a media server. This guide puts the gateway in front of the media
server, so that a buyer pays for a film piece by piece as it plays, and shows the same file
bought from twenty sellers at once by lottery. The media server here is **Jellyfin**, as it comes:
nothing is installed into it and none of its settings change.

**Status: regtest only.** Everything below has run on one host, on an XBT regtest chain, between
our own Lightning Fork nodes (`scripts/demo_film.sh`). Nothing has run on mainnet or between two
people. Do not use it with real funds. What the gateway and the wallet do not do is in
[`LIMITS.md`](LIMITS.md); the wire is [`TICKETS.md`](TICKETS.md).

## Run the whole demo

```bash
scripts/demo_film.sh
```

It needs docker with compose, python3, ffmpeg and a Rust toolchain, and takes about 7 minutes once the lab and the film are there (the first run also builds the nodes and fetches the film). It
builds the wallet and the gateway, brings up four Lightning Fork nodes on a regtest chain, starts a
stock Jellyfin in a container with one film, puts gateways in front of it, and plays the film
through the wallet. It prints PASS or FAIL for each check and a readout while the film plays, and
writes `run/demo_film.json`. `DEMO_SERVICE=files` uses a plain file server where no Jellyfin image
is wanted. The head of the script lists its ports and settings.

The film is **Big Buck Bunny**, (c) 2008 Blender Foundation, www.bigbuckbunny.org, licensed under
Creative Commons Attribution 3.0: 276 MB, 10:34, 1080p, 3.5 Mbit/s. The script fetches it; it is
not in this repository.

## The seller's side, step by step

### 1. What you install

- Your Lightning node, with inbound capacity. The gateway speaks to Lightning Fork nodes (a fork
  of lnd). A Core Lightning node cannot be the seller's node: it has no hold invoices, and the
  gateway does not speak its interface ([`TICKETS.md`](TICKETS.md), section 8).
- Your Jellyfin, as it is.
- `xbt-gateway`, one program, on the machine the node runs on:
  `cargo build --release -p xbt-gateway`.

### 2. In Jellyfin: a library for what you sell, and nothing else

In Jellyfin's own pages make a library that holds only the films you sell, and a user without
admin rights who sees only that library. Sell only what you may: the demo's library holds one
freely licensed film.

**What a buyer can reach is decided by the gateway's routes.** Name each film you sell by its
item id in the gateway's config. A path with no route is not served: in the demo another film on
the same server, and the server's own pages, answer 404 through the gateway. Do not rely on the
service's own logins or library limits for that, and never publish the service's own port: only
the gateway's.

The film's item id is the long hex name in the film's address in Jellyfin's web pages
(`…#/details?id=<item id>`).

### 3. Two narrow macaroons

```bash
lncli bakemacaroon invoices:read invoices:write --save_to invoices.macaroon
lncli bakemacaroon info:read --save_to info.macaroon
```

The first makes, follows, settles and cancels invoices. The second reads the block height.
Neither can send coins, pay, open a channel or bake a macaroon, so the gateway can receive for
you and can never spend. (`crates/xbt-gateway/README.md` has a third, optional one.)

### 4. The config

The whole of it, for one film at 100 sat a MiB:

```json
{
  "listen": "127.0.0.1:8402",
  "public_url": "https://films.example",
  "upstream": "http://127.0.0.1:8096",
  "state_dir": "/var/lib/xbt-gateway",
  "chain": "regtest",
  "network": "bip122:<the first 32 hex characters of your chain's block 101>",
  "node": {
    "rest": "https://127.0.0.1:8081",
    "tls_cert": "/var/lib/lnd/tls.cert",
    "macaroon": "/var/lib/xbt-gateway/invoices.macaroon",
    "info_macaroon": "/var/lib/xbt-gateway/info.macaroon"
  },
  "routes": [
    {"path": "/Videos/<item id>/", "price": {"byte_msat": 100000, "per_bytes": 1048576}}
  ]
}
```

`upstream` is your Jellyfin. The one route covers everything a player asks for that film: its
playlists, its segments and the file itself. Then:

```bash
xbt-gateway --check gateway.json   # reads the config and the macaroons, says what the caps cost
xbt-gateway gateway.json
```

A config that names no chain is a regtest one, and mainnet has to be asked for twice
(`crates/xbt-gateway/README.md`). For buyers elsewhere, put a TLS reverse proxy in front and set
`public_url` to the address they use; the gateway listens off 127.0.0.1 only when `public_url`
is `https`. The demo does not do this: everything in it listens on 127.0.0.1.

### 5. By the byte, or by the second?

Jellyfin sends a film in one of two ways. **Direct play**: the player asks for parts of the file
itself with HTTP range requests. **HLS**: Jellyfin cuts the film into segments of about six
seconds and the player asks for a playlist and then one segment after another; where the film's
video is already H.264, Jellyfin copies it into the segments and encodes nothing.

**Price it by the byte.** A byte price is the same for both ways, follows the film's quality, and
charges a viewer who seeks for exactly what they fetched. The gateway's price by the second counts
the seconds an answer is open, which for a segment that arrives in a tenth of a second says
nothing about the film. If you want a price per minute of film, price each segment as a request:
a segment is a fixed length of film.

The demo plays over HLS, for a reason on the buyer's side: the wallet's `xbt402_pay` asks for a
whole address and cannot yet send a `Range` header, which direct play needs. The gateway already
passes `Range` on to the service.

### 6. What you publish

The film's address at your gateway. For HLS that is

```
https://films.example/Videos/<item id>/master.m3u8?MediaSourceId=<item id>&api_key=<the demo user's key>&VideoCodec=h264&AudioCodec=aac&SegmentContainer=ts&TranscodingMaxAudioChannels=2
```

The key is that of the user who sees only the library you sell from. It is in the address because
Jellyfin wants one for playlists and the gateway cannot yet add a credential of its own to a
request; treat it as public.

### 7. How you see what you earned

- Your node: every ticket a buyer used is a settled invoice of 1,000 sat
  (`lncli listinvoices`), and the sats are in your channel balance at once.
- The gateway: `GET /x402/ticket/health` on its own address counts the tickets settled and those
  buyers hold now, and each answer it sends carries a signed receipt with the session's totals.

## The buyer's side

### A person watching

The viewer runs the wallet of this tree (`xbt-signer`, with a policy that names the seller and a
budget for the task) and a small **paying proxy**, `scripts/demo/payproxy.py`. An ordinary player
is pointed at the proxy in place of the seller:

```bash
scripts/demo/payproxy.py --seller https://films.example --mcp target/release/xbt-wallet-mcp --task film \
    --play '/Videos/<item id>/master.m3u8?…'
mpv 'http://127.0.0.1:18310/Videos/<item id>/master.m3u8?…'
```

Every request the player makes becomes one call of the wallet's `xbt402_pay` tool for the same
path at the seller, so the wallet pays as the film plays and stops when the player stops asking.
`http://127.0.0.1:18310/-/` is a page with the film and a live readout: sats paid, tickets
released and held, what is left with the seller, and a stop button.

What a viewer needs installed: the wallet and its MCP server (two binaries), python3 for the
proxy, a Lightning Fork node with a channel, and a player that plays HLS (mpv, VLC, ffmpeg's
ffplay, or a browser that plays HLS itself).

The proxy holds no key and no ticket secret, and can do nothing an AI agent with the same three
tools could not. It is a demonstration: one seller, one request at a time, GET only, no `Range`.

### An AI agent

An agent with the wallet's MCP tools calls `xbt402_pay` with the address and the most it may use.
In the demo it buys the first part of the film's file with a call that may use 300 sat, and the
wallet stops the answer where 300 sat are used by its own count.

## What the demo measured

One host, loopback, regtest; Lightning Fork nodes whose channels carry 30 pending payments;
Jellyfin 10.11.0; the film above at 100 sat a MiB, in tickets of 1,000 sat. The price is a number
chosen so that a ticket lasts about half a minute of this film. It is not a market price.

| What | One routing hop | Two routing hops |
|---|---|---|
| First frame in an ordinary player (ffmpeg), from a wallet with no session open: the terms, 2 tickets locked along the route, the playlist, the first segment | 0.46 s (median of 3) | 0.55 s |
| The same with a session open | 0.17 s | 0.12 s |
| 90 s in real time, the player keeping 12 s of film ahead | no stall; 4 tickets released, 2 held | no stall (45 s) |
| What it costs | 2,213 sat a minute of film (22.1 MiB a minute) | the same |
| The whole film, as fast as it comes | 106 segments, 274.7 MiB, 27,466 sat by the price; 28 tickets paid: 28,000 sat | the same 28 tickets |
| Routing fees for the whole film | 28 sat (1.001 sat a ticket) | 56 sat (2.002 sat a ticket) |
| Held ahead while it plays | 2 tickets (2,000 sat), never more pending on the buyer's channel | 2 tickets |

| What happens when | Measured (one hop) |
|---|---|
| **Pause** | The player stops asking once its 12 s are ahead. In the 20 s after: nothing paid, no ticket released, the 2 held tickets still held and not spent |
| **Seek** to 5:00 | Playing from the new place after 0.03 s (Jellyfin had those segments ready) |
| **The connection drops** in the middle of a segment | One request fails; the player asks again and has the segment whole 0.5 s later; the film does not stall. The 0.28 MiB that had arrived were paid for (30 sat) and are bought again |
| **The seller's gateway is killed** and started 8 s later | One request is refused ("the seller gave no answer"); the film stands still for 19 s and then goes on in the same session, with the balance it had. Why it is 19 s and not 8 was not traced; the wallet waits up to 30 s for a seller to close an answer that was cut |
| **Stop** | The 2 held tickets are cancelled by the seller and back on the buyer's node 0.24 s later. 458 sat, what was left of the last released ticket, stay with the seller |
| **The agent's call**, 300 sat at most | 3.0 MiB, the file's own first bytes, in 0.37 s; one ticket released |

After every part, what the buyer's node paid, what the sellers' nodes received and what the wallet's
ledger holds agreed to the millisat. The readout counts a ticket with its fee limit (1,015 sat)
when it is released; the node then paid 1,001.

Numbers of one run on 2026-10-13; rerun with `scripts/demo_film.sh`, which writes
`run/demo_film.json`. That run's report was overwritten by later runs. The report of the latest
run (2026-10-14) is in the tree as [`reports/demo_film.json`](../reports/demo_film.json), and
differs from these tables where one run differs from another: its stop left 455 sat with the
seller, and its swarm drew 10 wins. On one host everything is a loopback away, so the times say
what the software adds and nothing about a real network.

### What the demo's settings change

The demo does not run the shipped defaults throughout. The rules of tickets and of the lottery
are the shipped ones: 2 tickets held with a seller, at most 15 held in all, tickets of 1,000 sat
that live 40 blocks, wins of 64 sat through a routing hop, the seller's window of 8 pieces and
its grace. The driver (`scripts/demo/drive.py`) sets the following to something else. Where the
script gives a reason it is given here; where it gives none, this says so.

The wallet's policy:

| Setting | Shipped | The demo | Why |
|---|---|---|---|
| `tickets.enabled`, and the tasks `film` (a budget of 1,000,000 sat) and `swarm` (100,000 sat) | off, no task | on | Tickets are off until an owner turns them on and names a task with a budget |
| `allowlist`, `counterparties` | empty | the two film gateways and the 20 swarm gateways, each tied to its node id | The owner names its sellers; nothing in the demo is paid as a stranger |
| `velocity_max` | 8 payments an hour | 1,000 | A ticket or lottery session counts as one payment, and the demo opens more than 8 sessions in an hour: 20 for the swarm alone |
| `tickets.max_sellers`, also for the `swarm` task | 15 | 28 | The swarm pays 20 sellers at once |
| `tickets.max_new_sellers_per_min` | 30 | 200 | No reason given. The demo's 20 new sellers are within the shipped 30 |
| `tickets.max_sends_per_hour` | 1,200 | 100,000 | No reason given. Whether the run stays within 1,200 was not checked |
| `tickets.max_answer_s` | 50 s | 120 s | The wallet cuts an answer that is paid as it arrives after this long. No reason given; the whole film came in 4.6 s in the latest report |
| `tickets.lottery.min_expected_wins` | 4 | 0 | As shipped, a call that expects fewer than 4 wins from its seller is paid with a prepaid ticket where the seller offers one. Each of the swarm's calls expects under one win, so as shipped the swarm would buy 20 prepaid tickets and draw nothing; the demo turns the rule off to show the draws. |
| `max_per_tx_sats`, `daily_budget_sats`, `weekly_budget_sats`, `per_counterparty_cap_sats`, `human_threshold_sats` | 10,000,000; 50,000,000; 200,000,000; 30,000,000; 10,000,000 | 50,000; 4,000,000; 8,000,000; 4,000,000; 40,000 | A lab wallet's budgets, all lower than shipped |
| `split_window_s` | 600 s | 0 | Payments to one seller inside this window add up against `max_per_tx_sats` and the human threshold; at 0 each ticket is judged alone. No reason given |
| `anchor_interval_s`, `regtest_mine`, `ln.enabled`, `ln.split_height` | 60 s; unset; off; unset | 3,600 s; off; on; the lab chain's | Settings of the lab chain and its Lightning rail |

Each gateway's config:

| Setting | Shipped | The demo | Why |
|---|---|---|---|
| `caps.sessions_per_address`, and `lottery.sessions_per_address` on the swarm's gateways | 2, and 4 | 0: no cap | Every buyer of this lab comes from 127.0.0.1 |
| `times.height_max_age_secs` | 10 s | 30 s | No reason given. A gateway takes no secret without a block height at most this old |
| `times.tick_ms`, on the 20 swarm gateways only | 500 ms | 5,000 ms | No reason given. All 20 stand beside one node, and each asks it for the height every tick |
| `lottery` on the swarm's gateways | not offered unless the section is written | offered, with `piece_bytes` 262,144, which is the shipped piece size | The swarm is paid by draws |
| `chain`, `network` | the runner's chain | regtest | The lab |

Three of the script's checks pass on a looser bound than this page's measured figure, and the
check's own words now name the bound it asserts:

| Check | Asserted | Measured in the run above |
|---|---|---|
| The held tickets are back on the buyer's node after a stop | within 6 s | 0.24 s |
| Payments pending on the buyer's channel during the swarm | never more than 9 (the wallet sends 8 at a time) | at most 4 |
| Payments pending on the buyer's channel while the whole film is bought | never more than 3 | 2 |

## Many sellers at once: the swarm

The same film file, cut into pieces of 256 KiB at 1 sat a piece, bought from 20 gateways at once.
A piece costs far less than a ticket, and 20 sellers are more than tickets can be held with from
one channel of 30 slots, so the wallet pays by **draws**: every piece is a fair draw, one in 64
wins, and a win is an ordinary payment of 64 sat. Nothing is locked with any seller.

| What | Measured |
|---|---|
| The file | 263.3 MiB in 1,054 pieces, every piece checked against its hash, whole in 3 s |
| Draws | 1,054, one a piece |
| Wins | 14 (16.5 expected), each one payment of 64 sat |
| Paid | 896 sat for pieces priced 1,053 sat: this run was lucky for the buyer; the run before it paid 576 sat |
| Sellers paid nothing | 9 of 20. Each sold about 52 sat of pieces, less than one win |
| Routing fees | 14 sat, 1 sat a win |
| On the buyer's 30-slot channel | at most 4 payments at once; nothing held between wins; no payment failed |

That is the lottery as it is: exact in expectation and uneven in one run, for the buyer and for
each seller. With 16.5 wins expected the spread of one run is about a quarter of the price
(1 ÷ √16.5), and a seller that expects 0.8 of a win is paid nothing in 44% of runs (e^(−0.82)).

The 20 gateways stand beside one seller node: the buyer's channel and the route carry what 20
sellers' wins would, and the sellers' side is one node's work.

## What this does not show

- **Real coins, or two people.** It is regtest, on one host, between our own nodes. "Let people
  stream from it" needs a shared test network or mainnet, a seller's gateway reachable from
  outside behind TLS, and a decision to expose a home server.
- **A stock Jellyfin app paying.** The player here is given the film's address. Jellyfin's own
  web and TV apps also log in, browse and report progress with headers the gateway does not pass
  on by default, and they direct-play with `Range`. A paying proxy that carries those is not
  built.
- **A player on a screen.** The players of the run are ffmpeg, for the first frame, and a script
  that asks for segments as an HLS player does. mpv, VLC and a browser were not tried.
- **Direct play.** See section 5.
- **Seeking inside what was paid for.** A viewer who seeks back pays for those segments again.
- **An AI model as the agent.** The agent of the demo is a script that speaks MCP.
- **Anything the limits already say**: a seller that takes a ticket and serves nothing keeps at
  most one ticket; what is left of the last ticket stays with the seller; a buyer that never pays
  a win was served about one win's worth ([`LIMITS.md`](LIMITS.md)).
