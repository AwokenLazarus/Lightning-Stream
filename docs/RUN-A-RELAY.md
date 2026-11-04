# Run a Stream relay

Lightning Stream connects a buyer's app to a seller's directly when it can: an encrypted link
between the two apps (iroh, QUIC with TLS 1.3), punched through both routers. Some routers and
VPNs don't allow that. Then a **relay** passes the traffic between the two apps.

Anyone can run a relay. Each one adds capacity for everyone whose network blocks direct
connections, and apps prefer a relay near them. A relay can be free, or, from 0.3.0, charge the
apps that make it their home by the GB (paid relays, below).

## What a relay sees, and what it doesn't

- **It can't read anything.** The link is encrypted from one app to the other; the relay passes
  sealed packets. It can't change them either: a changed packet is refused at the other end.
- **It does see** the IP addresses of both apps, when they connect, and how much passes between
  them. Keep no logs of those (the setup below doesn't).
- **It isn't an exit.** A relay carries traffic only between two Stream apps. Nothing it carries
  goes out to the rest of the internet from your address, so it does not draw the abuse reports
  an exit or a Tor exit does.

## What you need

- A server with a public IPv4 address: usually a small rented server (VPS). A home box would need
  a port forward and puts strangers' (encrypted) traffic on your home connection.
- **TCP port 443** reachable from the internet.
- **UDP** reachable too, if you can (port 7842 below). It lets apps learn their own public
  address from your relay (QUIC address discovery), which helps direct connections. Some
  providers block inbound UDP; the relay still works without it.
- A domain name pointing at the server (an `A` record; with Cloudflare, **DNS only**, not proxied).
- Bandwidth: 4K video through a relay is about 11 to 36 GB per hour of watching, per stream.
  1080p is about a third of that. Pick a plan whose transfer you won't mind using.
- Linux with systemd 253 or newer (for `LogFilterPatterns`). Ubuntu 24.04 and Debian 13 are fine.

## The easy way: switch it on in Lightning Stream

The Linux package has a relay built in. On a server with a public address:

1. **Install Lightning Stream** with the Linux package (`docs/LINUX.md`), and answer **1** when
   `install.sh` asks about the Stream relay. That installs the relay service; it stays idle.
   (Already installed? Run `install.sh` again, or `docker compose --profile relay up -d` in the
   folder you installed it to.)
2. **Point a domain at the server:** an `A` record to its public address (with Cloudflare,
   **DNS only**, not proxied).
3. **Open TCP 443** (and UDP 7842 if you want QUIC address discovery) in the server's firewall and
   the provider's.
4. In the app, **Settings → Advanced → Stream relays → Run a relay for the Stream network**: enter the domain
   and an e-mail address for Let's Encrypt, and switch it on.

Before anything is asked of Let's Encrypt, the relay checks:

- that the domain resolves, and to this server's public address;
- that port 443 is free on this server;
- that a connection to the domain on 443 comes back to this server;
- that it hasn't already tried 3 times in the last hour.

Only when they pass does it ask for the certificate (Let's Encrypt refuses a name for an hour after
5 failed validations, so the relay never loops). The page shows each check in plain words, what to
fix when one fails, a **Try again** button, and once it runs, how much it has carried and how many
apps are connected. Then **Announce a relay** lists it for other apps.

The built-in relay uses the same settings as the hand-made one below: the same limits, no client
addresses in the logs, its own unprivileged user, and Docker's own network (443 mapped to 8443
inside), so it never touches the host's network.

**Umbrel and StartOS** can't run it: an Umbrel app can't take the box's port 443, and StartOS keeps
443 for itself. Those apps say so on the same page. A home box is a poor place for a relay
anyway (it would carry strangers' encrypted traffic on your home connection); a small rented
server is the right place.

**Behind a home router** (if you do run it at home with the Linux package): forward TCP 443 to the
box and tick **TCP 443 is forwarded to this box**. A box can't always reach itself through its own
public address from behind a router, so there the relay takes your word for the forward.

## Or: run the relay on its own

Without Lightning Stream on the server, set up iroh-relay by hand.

### Set it up by hand

The steps below are what runs Genesis's relay, `relay.lightning-stream.com` (also served as
`iroh.lazarus-xbt.xyz`, its name in 0.2). Replace
`relay.example.com` and the contact address with yours.

#### 1. The firewall, first

Open the ports **before** the relay starts. It asks Let's Encrypt for its certificate in its first
seconds, through port 443. Let's Encrypt allows **5 failed validations per hour** per name; a
relay started behind a closed port uses them up, and then has to wait an hour.

With nftables, in your `inet filter` input chain:

```
tcp dport 443 ct state new meter relay-conn { ip saddr ct count over 32 } drop
tcp dport 443 ct state new meter relay-rate { ip saddr limit rate over 10/second burst 20 packets } drop
tcp dport 443 accept
udp dport 7842 accept    # only if you enable QUIC address discovery
```

(With ufw: `ufw allow 443/tcp` and, if used, `ufw allow 7842/udp`.)

#### 2. The binary

The relay is the stock `iroh-relay` 1.4.1, the version Lightning Stream's link is built against:

```
cargo install iroh-relay --version 1.4.1 --features server --locked
sudo install -m 755 ~/.cargo/bin/iroh-relay /usr/local/bin/iroh-relay
sudo useradd --system --no-create-home --shell /usr/sbin/nologin iroh-relay
```

#### 3. The configuration

`/etc/iroh-relay/iroh-relay.toml`:

```toml
enable_relay = true
# Captive-portal HTTP on loopback only, so port 80 is never opened.
http_bind_addr = "127.0.0.1:3340"
# QUIC address discovery on UDP 7842. Set false if your provider blocks inbound UDP.
enable_quic_addr_discovery = true
# Metrics on loopback only.
enable_metrics = true
metrics_bind_addr = "127.0.0.1:9091"
# A public relay: any Stream app may connect.
access = "everyone"

[tls]
https_bind_addr = "0.0.0.0:443"
quic_bind_addr = "0.0.0.0:7842"
cert_mode = "LetsEncrypt"
hostname = "relay.example.com"
contact = "you@example.com"
prod_tls = true
cert_dir = "/var/lib/iroh-relay/certs"

[limits]
# New connections: 10 a second, bursts of 50.
accept_conn_limit = 10.0
accept_conn_burst = 50

[limits.client.rx]
# Per client: 6 MB/s steady (48 Mbit/s, about two high-bitrate 4K streams), 12 MB bursts.
# A client is one link key: a shop on several keys (docs/DIRECT-LINKS.md) has this for each.
bytes_per_second = 6000000
max_burst_bytes = 12000000
```

```
sudo install -d -m 755 /etc/iroh-relay
sudo cp iroh-relay.toml /etc/iroh-relay/iroh-relay.toml
```

#### 4. The service

`/etc/systemd/system/iroh-relay.service`: sandboxed, capped, and with no client addresses in
the logs.

```ini
[Unit]
Description=Stream relay (iroh-relay, TCP 443)
After=network-online.target
Wants=network-online.target

[Service]
User=iroh-relay
Group=iroh-relay
ExecStart=/usr/local/bin/iroh-relay --config-path /etc/iroh-relay/iroh-relay.toml
Restart=on-failure
RestartSec=5
# Logs: warnings and errors, but nothing from inside a connection (those lines carry the client's
# address), and journald drops any line that names one anyway. Never use LogLevelMax here:
# the relay writes to stderr, which journald stores at priority info, so LogLevelMax=err hides
# every line, errors included.
Environment=RUST_LOG=warn,[conn]=off
Environment=NO_COLOR=1
LogFilterPatterns=~peer=
LogFilterPatterns=~opened from 
# Caps: size them below what the server can spare.
CPUQuota=200%
MemoryMax=1G
TasksMax=256
CPUAccounting=yes
MemoryAccounting=yes
IPAccounting=yes
LimitNOFILE=65536
# Bind 443 without root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
# Sandbox.
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
UMask=0077
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallArchitectures=native
ReadOnlyPaths=/etc/iroh-relay
StateDirectory=iroh-relay
ReadWritePaths=/var/lib/iroh-relay
InaccessiblePaths=-/root -/home -/mnt -/srv -/opt

[Install]
WantedBy=multi-user.target
```

Keep the trailing space after `~opened from `. If the server also runs other services, add
their data directories to `InaccessiblePaths`. `systemd-analyze security iroh-relay` should rate
the unit "OK".

#### 5. Faster single connections (BBR)

A relay carries each app over one TCP connection, so how fast one connection can go is what
matters. BBR keeps it fast over long or lossy paths, where the default (cubic) slows down:

```
echo tcp_bbr | sudo tee /etc/modules-load.d/bbr.conf
sudo modprobe tcp_bbr
printf "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n" | sudo tee /etc/sysctl.d/90-relay.conf
sudo sysctl --system
```

This applies to every service on the server. To undo it: delete the two files and run
`sudo sysctl -w net.ipv4.tcp_congestion_control=cubic net.core.default_qdisc=fq_codel`.

#### 6. Start it, once

Check the name points at the server (`dig +short relay.example.com`), then:

```
sudo systemctl daemon-reload
sudo systemctl enable --now iroh-relay
```

Don't restart it in a loop if something is wrong: each failed certificate attempt counts against
the hourly limit. The certificate is kept in `/var/lib/iroh-relay/certs` and renewed by itself.

#### 7. Check it

```
systemctl is-active iroh-relay
# a WebSocket upgrade on /relay must answer 101 (the request then stays open: stop it with Ctrl-C)
curl -s -o /dev/null -w '%{http_code}\n' -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  -H 'Sec-WebSocket-Protocol: iroh-relay-v1' https://relay.example.com/relay
# no addresses in the log
sudo journalctl -u iroh-relay -n 50 | grep -c 'peer='     # 0
```

`/` answers 404: that's expected.

#### 8. Watch it

The traffic, CPU and memory against the caps:

```
systemctl show iroh-relay -p IPIngressBytes -p IPEgressBytes -p CPUUsageNSec -p MemoryCurrent -p MemoryMax
curl -s 127.0.0.1:9091/metrics | grep -i relay | head
```

## Tell apps about it

Apps learn of relays from announcements on Nostr: a signed note with the relay's address,
where it runs, roughly what it can carry and, optionally, how to reach you. An announcement
lasts at most 30 days; announce again to stay listed (a monthly timer is fine).

- **From the Lightning Stream app:** Settings → Advanced → Stream relays → *Announce your relay*. The app
  signs it with a key it keeps for this (`secrets/relay-operator.key`) and lists the relay as yours.
- **From the relay server itself**, with the `xbt-relay-announce` tool from this repository:

  ```
  cargo build --release -p xbt-nostr --bin xbt-relay-announce
  ./target/release/xbt-relay-announce --relay https://relay.example.com --region eu-central \
      --capacity-mbit 500 --udp --contact you@example.com \
      --nostr wss://nostr.lazarus-xbt.xyz --nostr wss://nos.lol
  ```

  It keeps its signing key in `~/.config/stream-relay/nostr.key` (mode 600), made the first time.
  Keep that file: it is how you update or replace the announcement. `--dry-run` prints the signed
  event without publishing it.

An announcement doesn't prove you run the relay, and doesn't need to: apps never trust a relay
with anything they can't check. Each app probes every relay it knows itself, and uses the ones
that answer, nearest first.

## How apps choose

Settings → Advanced → Stream relays shows every relay the app knows, how fast each answers, and the order
the app uses them in. The first is the app's home relay; the others follow; ours
(`relay.lightning-stream.com`) is always last unless the owner blocks it; iroh's public relays come
after those, for address discovery and as a final fallback. The owner can:

- **Prefer** a relay: it is tried first whenever it answers.
- **Block** a relay: it is never used, ours included.
- **Use only my own relays**: only relays the owner added as theirs. The public relays are
  dropped too, so if the owner's relays don't answer, nothing does.

**By what the connection carries.** The app keeps two orders:

- for **AI, hashrate and pages**, where the quickest answer matters, relays rank by round trip;
- for **video, files, VPN exits and sellers' web apps**, where what a relay can carry matters,
  relays rank by the throughput real sessions through them reached, then by the capacity their
  announcement claims, then by round trip.

The choices are kept in `relays.json` in the app's data directory: `selected` (the order for
latency), `selected_throughput` (the order for throughput), and `observed` (what the link
measured each relay carrying, in Mbit/s), which the link reads and writes.

### What decides the path, and what is planned

In iroh, each app keeps one **home relay**, and a connection to an app that can't be reached
directly goes through **that app's** home relay: the buyer's app dials the seller through the
seller's home relay. So:

- **A seller's home relay serves its buyers.** A seller's app picks its home relay from the
  announced relays for the kind of service it sells (throughput for video, latency for AI and
  hashrate), favouring relays near the seller with room to spare. *Built: the ranking. Planned:
  the seller weighing relays by where its buyers are.*
- **A buyer's choice matters for the buyer's own leg** (its connection to the seller's relay) and
  when the buyer sells or is dialled. *Planned: a buyer measuring the real path through the
  seller's relay and, when a clearly faster relay is available to both, asking the seller to be
  reachable there too.* iroh's addresses can list several relays for one app, but an app is
  connected to its home relay only, so this needs the seller's app to keep a second relay
  connection open; that is not in iroh 1.4 and would be a change to iroh.
- **Measuring throughput, not just ping.** A probe measures the round trip only. Throughput comes
  from real sessions: the link reports what each relay sustained, and the ranking uses it.
  *Planned: an optional short download test through a candidate relay when nothing has been
  measured yet.*
- **Re-checking during long sessions.** *Planned:* the app re-probes every few minutes during a
  session. Once a direct path forms, iroh moves the connection onto it by itself without
  dropping it; moving a live connection from one relay to another is up to iroh's path handling
  when a home relay changes, and is to be tested before we claim it.

## The announcement event

For anyone writing their own tool: a NIP-78 application-data event, kind **30078** (addressable:
the newest per author and `d` replaces the older).

| Tag | Value |
| --- | --- |
| `d` | `lightning-stream-relay:` followed by the relay URL |
| `t` | `lightning-stream-relay` |
| `relay` | `https://host[:port]/`: TLS, no path |
| `region` | 1 to 32 characters, such as `eu-central` |
| `udp` | `1` when it answers QUIC address discovery, else `0` |
| `expiration` | NIP-40: Unix time, at most 30 days after `created_at` |
| `capacity_mbit` | optional: what it can carry, in Mbit/s |
| `contact` | optional: up to 128 characters |

`content` is a short note for people (up to 280 characters), never read by the app. An app
refuses an announcement whose signature fails, whose `d` doesn't match its `relay`, that is dated
more than 10 minutes ahead, or that has lapsed.

## Paid relays (0.3.0)

`docs/PAID-RELAYS.md` is the design and what is built. In short:

- **Who pays:** each app, shop or buyer, pays its own home relay, and only that relay, for the
  bytes it receives there. Nobody pays a relay it didn't choose: a relay charges a key only after
  the key itself has signed that the relay is its home.
- **Price:** each relay announces its own price per GB (2 sats is the suggested one) and a free
  allowance (64 MB a day per key unless it says otherwise). Apps buy credit 10 GB at a time.
- **How:** the relay is a Stream seller. Its operator sells credit as a priced route on their own
  shop, paid with the same prepaid tickets as everything else, inside the payer's signed spending
  rules ("Most for relays in 24 hours"), with signed receipts. The operator receives into their own
  Lightning node: no custody. The relay itself never touches Lightning.
- **When credit runs out:** past a small grace, the app's traffic waits at the relay for the next
  credit (the sender is slowed, nothing is lost). If none comes within a few seconds, what waits is
  dropped and counted on the app's account, which the app reads and shows its owner.
- **Choosing:** every app starts on Genesis's relay, and moves by itself to a relay that answers
  clearly faster, at or below its owner's most per GB, saying so on its relay page; the owner can
  pin one instead.

The built-in relay's paid side is switched on in its `relay.json` (`paid`); `xbt-relay-announce`
takes `--price-msat-per-gb`, `--credit` and `--free-mb-per-day`.
