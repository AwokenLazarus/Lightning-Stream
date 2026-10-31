# VPN exits

A buyer's devices (a phone, a laptop, a TV, a whole home behind a router) send their traffic out
through another Stream user's internet connection, in the country the buyer chooses. Paid as you
use it, by the GB, within the buyer's spending rules. No port forward on either side: buyer and exit
reach each other over Stream's encrypted links (iroh), straight when routers allow it and through a
relay when they don't.

The crate is `xbt-vpn`. The plan, decisions and measurements are in the project's plan AGP-P-015.

## The principle

Privacy for buyer and exit wherever possible; where that is not possible, the exit's operator sets a
policy to protect themselves. So:

- **Private exits are the default.** The buyer's own app resolves names over encrypted DNS, so the
  exit never sees a DNS question; browsers can use Encrypted ClientHello where sites offer it. The
  exit sees destination addresses (every VPN's exit does) and, for sites without Encrypted
  ClientHello, their names.
- **Operators always have content-blind protections:** ports never carried (email's 25 by default),
  address blocklists, each buyer's speed and number of connections. An exit never reaches its own
  network, and never records where buyers go: only byte counts.
- **Filtered exits** are an operator's choice: their own blocklist and category lists (below) apply
  to names seen in DNS, TLS and HTTP. They are labelled as filtered, since they see site names.
- **Every exit's kind and policy is in its listing,** and buyers see it before choosing.

## How a flow travels

A device's WireGuard packets reach the buyer's app, which ends each connection on its own side in
a user-space TCP/IP stack and carries the flow, not the packets: each TCP connection is one QUIC
stream to the exit, UDP goes in QUIC datagrams. The exit opens an ordinary socket for each. No TUN
device, NAT rule or special capability is needed on either side.

There is no way out except through an exit. If no exit meets a device's policy, or the exit or the
buyer's app stops, the device's traffic stops; it never falls back to the buyer's own connection.
Checked with a real WireGuard client: with the exit stopped, and with the buyer's app stopped,
nothing reached the server outside the tunnel.

### Two hops

A buyer can ask for two hops: the flow goes through a first hop run by someone other than the exit,
so the exit never learns the buyer's address. Each flow is one TLS 1.3 session between the buyer and
the exit, inside a stream the hop only joins to another (`xbt_vpn::hop`, `xbt_vpn::sealed`):

- both ends authenticate with raw Ed25519 public keys (RFC 7250): the exit with its link key, which
  the buyer knows from the exit's listing; the buyer with a key made for the run, which names nobody;
- the **first hop** sees the buyer's address and which exit it asked for, never the destination or
  the bytes;
- the **exit** sees the first hop's address, never the buyer's.

Two hops carry TCP only (a private exit's DNS is already DNS-over-TLS or -HTTPS); UDP such as QUIC
is refused, and browsers fall back to TCP.

### Private DNS

The buyer asks its resolver (Quad9 by default) over DNS-over-TLS through the exit. Many networks
block DNS-over-TLS's port 853, so when it fails the buyer asks over DNS-over-HTTPS (port 443,
HTTP/2), and keeps using HTTPS after that.

## Buyer policies

Each device can have its own policy: the kind of exit (private, filtered or either), a country, two
hops, the most it may cost a GB, the slowest exit it may use, no-logs exits only, and how exits are
chosen (the best one, switching new connections when a better one appears; one exit until it
fails; or spread over several exits, each destination kept on one). Matching is strict: nothing is
relaxed, and a device whose policy no exit meets is blocked with the reason in plain words.

An exit's country is checked, not believed: its observed egress address is looked up in an offline
geo-IP table, with a round-trip sanity check.

## Category blocklists

A filtered exit's operator can tick categories: adult content, gambling, malware, phishing, scams
(`xbt_vpn::lists`). Each is a public list, fetched over HTTPS, saved beside the exit's files, checked
for a newer copy once a day, and swapped in whole while flows keep being checked. A failed fetch
keeps the last good copy. Sources and licences are recorded with each category: The Block List
Project (the repository is under The Unlicense; the list files' headers say MIT).

Filtering by name is not airtight: Encrypted ClientHello, sites reached by bare address and other
encrypted-DNS services can get past it. With filtering on, an exit refuses DNS-over-TLS, the
well-known DNS-over-HTTPS services and QUIC, which closes the common routes.

## The app

- **Services → VPN** (buyers): devices, each with its rules, what it's using now and why it's
  blocked if it is; adding a device gives its WireGuard settings and a QR code, shown once.
- **Sell → VPN exit** (operators): offer the connection as an exit, after a plain warning; price a GB;
  private or filtered; categories and an own list; protections under Advanced.

The pages write `devices.json` and `exit.json` in `XBT_UI_VPN_DIR`, and read what the VPN service
writes in `XBT_UI_VPN_STATUS_DIR` (the same folder unless set): `endpoint.json` (the WireGuard key
devices pair with), `status.json` and `exit-status.json`. A device's private key is shown once and
never kept.

## The VPN service

`xbt-vpn serve` is the service the pages drive (the `xbt-vpn` image, as uid 10018). It reads the
devices and the exit from those files, runs the WireGuard endpoint devices pair with, routes each
device by its own rules, and runs this box's exit if the owner offers one. It keeps its keys
(WireGuard, the exit's link key, its Nostr key) and the category lists in its own folder, readable by
it only. When the devices or the exit change it exits, and the package starts it again with them.

WireGuard and the TCP/IP stack run in the process (userspace), so the service needs no TUN device and
no capabilities. Only one UDP port is published, for the devices on the LAN:

| Package | Devices reach it on | How it is switched on |
| --- | --- | --- |
| Linux | UDP 51820 (`LS_VPN_PORT`), on Docker's own network | `LS_VPN=1` at install (profile `vpn`) |
| Umbrel | UDP 51830 on the box's name | always installed, idle until a device is added or an exit offered |
| StartOS | UDP 51830 (a two-port range, the way StartOS forwards UDP) | likewise |

Exits are found on the package's Nostr relays: each exit signs an announcement (NIP-78, kind 30078,
`d` = `lightning-stream-vpn-exit:<exit id>`) with its owner's Nostr key, and its link key signs the
pairing of the two, so nobody can announce an exit that isn't theirs. The announcement says what the
exit is (private or filtered, its categories, port rules, two hops, price a GB) and lives a week;
the service renews it every 6 hours and looks for exits every 10 minutes. An exit is announced only
once its owner sets its country on the exit page.

An announced exit's country is checked, not taken on its word. The buyer's app reads the exit's
egress address through the exit itself, from several HTTPS pages run by different operators
(Cloudflare's trace, AWS's checkip, ifconfig.co, ipify; each sees only the exit's address, never the
buyer's). Over TLS the exit can't change what they say, as it could a plain page or a STUN answer.
The address is believed only when at least two answer and every one that answers agrees. It is then
looked up in an offline geo-IP table: DB-IP's "IP to Country Lite" (CC BY 4.0, <https://db-ip.com>),
which ships with the app (`/usr/share/xbt-vpn`, refreshed at each release), so a box checks regions
from install with no download and no service of anyone's. Newer months are fetched into the
service's keys dir only where the owner sets a source (`XBT_VPN_GEO_URL`, empty by default: the
app depends on no one's service). Where region results are shown, the page credits DB-IP with a
link, as its licence asks. No lookup about an exit or a buyer leaves the box. If the owner gives their own country
(`--home-country` / `XBT_VPN_HOME_COUNTRY`), a round trip faster than the distance to the claimed
country allows is caught too; the app never looks the owner's country up from the network. An exit
whose region does not check out is not offered for that region, and is checked again every 6 hours.
A **priced** exit's region is read through a paid tunnel, so it is checked only when a device's own
rules ask for that region and would otherwise take it. A check is charged at most 20 sats
(`max_charge_sats`), but a buyer with no credit at the exit's shop must first buy one of its
tickets, so the wallet may move up to 2,000 sats out for one check (the check tunnel's `max_sats`,
within the owner's rules); a shop whose ticket is bigger can't be checked. What the check leaves of
the ticket stays as credit with that shop, for the tunnel after it. Every check through a paid
tunnel (an exit that named one, whatever price it announced) shares one budget
(`xbt_vpn::holds::CheckGate`): at most 4,000 sats may leave the wallet for them in a budget day, the
24 hours from the first check after the last budget day ran out (a fixed window, so 24 hours that
straddle two of them may see up to 8,000). A check starts only if the budget day's spend plus its
2,000 still fits. Its 2,000 is counted, and written to `region-checks.json` in the keys dir
(readable by the service's own user only), before the wallet is asked for its tunnel; once it is
done, what actually left for it is counted instead, as the wallet's answer says (the tickets it
bought or released for the check). Where that is not known (no answer, an error, an answer that
tells of a seller's fault or of a payment with no final answer, an opening given up, or the service
stopped during the check) the full 2,000 stays counted. The budget is kept in wall-clock time in
that file, so the service starting again (as it does at every change of its settings) does not
start the budget day again: the checks never move more than 4,000 sats in a budget day, however
many exits are announced, under how many keys, or how often the service starts. If the file is
there but can't be read, or isn't a gate's, the budget day counts as spent (no paid check for 24
hours) rather than starting again. With shops whose ticket and its routing fee come to T sats, that
is 1 + ⌊2,000 / T⌋ checks a budget day: 2 when T is over 1,000 (so a 1,000-sat ticket with any fee),
3 when T is 667 to 1,000, 4 when T is 501 to 666. An exit's opening, the check's reads through it
and the wallet's answer after are each given their own time (45 s, 30 s and 30 s), so a slow
opening from no credit is not cut short. Also one check of an exit in 24 hours, none more for 24
hours for an operator (the exit's Nostr key) whose checks failed twice within them, and the exits
seen longest first, so a crowd of new announcements can't push the others out.
Until the table has loaded, no region is verified, and a device whose rules name a country is told
no exit qualifies rather than sent to one that may be elsewhere. Each exit's result is in
`status.json` (`exits`), in plain words, and on the VPN page.

## Measured

On a home LAN (a 100 MB HTTP file):

| Path | Flows | Throughput | Notes |
| --- | --- | --- | --- |
| Exit on a Raspberry Pi 4 | 4 | 122–148 Mbit/s | Pi exit at 75% of one core |
| Same, through a first hop | 4 | 127 Mbit/s | sealing costs about 11% |
| Exit on a PC, through a Pi 4 first hop | 4 | 111–120 Mbit/s | the Pi hop at 90% of one core (of 4) |
| A WireGuard client (Pi) through the buyer's app | 1 | 43–48 Mbit/s | 94 Mbit/s without the tunnel |

Category lists, on a Raspberry Pi 4: each list is compiled once into a compact sorted set (a finite
state transducer) on disk and memory-mapped, so it costs memory only for the pages a lookup touches.

| List | Names | Before: loaded in memory | Now: file (mapped) | Now: added to the service |
| --- | --- | --- | --- | --- |
| adult | 953,393 | 95 MiB | 8.4 MiB | about 1 MiB |
| malware | 2,655,820 | 178 MiB | 27.5 MiB | about 1 MiB |

A name is checked, with each of its parent domains, in 1.1–1.6 µs. While a list is fetched and
compiled the service peaks at 49 MiB (adult) and 114 MiB (malware), where it was 137 and 286 MiB.

## Paying

An exit is one of its operator's Stream services, priced per GB both ways, and it is paid with the
same tickets as any other service, so a buyer's spending rules (per-seller and daily caps, the
approval threshold) apply.

### How a tunnel is paid

- **The exit's side.** Offering an exit on the Sell → VPN exit page adds a route to the owner's shop,
  `/vpn/` (the `vpn-exit` service), that carries WebSockets and is priced at the exit's sats a GB
  (`byte_msat` per GiB). The shop's gateway joins each paid tunnel to the VPN service's tunnel
  endpoint (`XBT_VPN_TUNNEL_LISTEN`, 51880, never published to the LAN), which serves the buyer's
  flows on it as it serves a link connection. The exit announces the tunnel's address on its shop
  (`https://<shop>/vpn/tunnel`, the announcement's `tunnel` tag). A priced exit carries no flows over
  its link, so nothing reaches it unpaid; two hops (which reach an exit over the link) are for free
  exits only.
- **Only the gateway is let in.** The tunnel endpoint listens where other apps on the box's network
  could reach it, so the gateway and the endpoint share a secret: `tunnel.secret` beside the exit's
  settings, 32 random bytes in hex, which the wallet app writes with the route (whole or not at all,
  with the folder's group, the VPN service's, and mode 0640) and the gateway sends in
  `X-Stream-Tunnel`. The endpoint reads the file again for each tunnel and compares by digest. Until
  there is a whole one (none yet, or a short or garbled file) it lets **nobody** in (503): it fails
  closed. A priced exit without one is not announced, and the Sell page says why
  (`exit-status.json`, `paid_tunnels_closed_because`, which tells a missing secret from one the
  service can't read); the service starts again when the file appears. A secret an older build
  wrote owner-only is given to the service's group when the wallet app starts, the same secret.
- **The buyer's side.** For each device and priced exit, the buyer's VPN service asks the owner's
  wallet to open the tunnel: the signer's `xbt402_pay` with `upgrade` and `stream_to`, the call a web
  app's WebSocket makes (`xbt_vpn::paid`). The wallet pays as the tunnel's bytes pass, under the
  owner's rules (the task `default` unless `XBT_VPN_TASK` says otherwise) and the tunnel's own
  `max_sats` (`XBT_VPN_TUNNEL_MAX_SATS`, 10,000 by default), for at most `tickets.max_socket_s` (6 h by
  default). The device's flows are carried on the tunnel's one byte stream by a multiplexer
  (`xbt_vpn::mux`): each TCP flow a stream with its own window, so one slow flow never holds up the
  others; UDP in datagram frames, dropped as UDP is when the way out is backed up. A tunnel that ends
  (its limit, the session's, a fault, the exit gone) ends its flows, and the device's next flow opens
  a new one, so the owner's rules are asked again. Without a wallet, priced exits are not used.

When the wallet's session with an exit is stopped while tunnels are open (the owner stops it, or
moves the device to another exit), the tunnels close first and each one's last receipt is taken,
up to 15 s, before the stop says what the session spent and what it leaves with the exit's shop
(`docs/TICKETS.md`, "Stop"). What a tunnel cost is its bytes both ways at the announced price.
The seller's VPN page shows what its shop has earned: the gateway's `chargedMsat` in its health,
counted across every session there has been, those the gateway no longer keeps included (a
compacted journal carries their sum, so it is written with the rest of the book, at once).

If the exit's signed counts fall far below the wallet's own count of an open tunnel (under half,
past 32 MiB, on two counts in a row), the wallet says so once in its log and audit
(`ticket_interim_undercount`). It is not a fault: such a shop charges less, not more.

### Interim receipts

The seller signs one receipt for an answer at its end; a tunnel lives for hours, so the buyer checks
the exit's charges while it runs too, with **interim receipts**.

**What one is:** the same signed receipt as any other (`xbt402::ticket::receipt_message`, the receipt key of the
seller's terms, the same `scheme`, `session` and `seq`, the session's `releasedMsat` and
`spentMsat`, and `charged`: what the call has cost so far). Its `bodyHash` is
`interim:<part>:<bytesUp>:<bytesDown>`: `part` counts 1, 2, 3… for each interim receipt of the
call, and the byte counts are what the seller passed each way so far. It is signed as any receipt's
`bodyHash` is, and can never be taken for a finished body's hash (64 hex) or a head's (empty).

**Cadence:** the gateway signs one each time `charged` grows by the price of 1 MiB, or every 10 s
while bytes flow, whichever comes first; none while the call is idle. The latest one of each open
answer is listed in `status`, under `interim` (apart from `responses`, the answers that ended), and
the wallet reads it every 10 s (`B2_INTERIM_POLL_MS`). Old buyers ignore it.

### What the signer checks on each one

Its signature, its session, and `spentMsat` never above its own `releasedMsat` (the session's
totals in it are not taken as the session's: those, and their check against what the wallet
released, come from final receipts and `status`, as for any answer), and also:

1. **Order:** `part` is later than the last one seen (the wallet polls, so it may skip parts);
   `charged`, `bytesUp` and `bytesDown` never fall.
2. **The ceiling:** `charged` never exceeds the call's own `max_sats`. This is the same per-call
   ceiling the concurrent-session fix enforces across concurrent calls (its must-fix #2): the sum of
   all open calls' `charged` stays within what the session may spend.
3. **The seller's count against the buyer's:** the wallet reads its own count once the seller's
   `status` answer is in. The bytes the seller says it passed each way are no more than the wallet
   counted on the call, plus 2% and 4 MiB for bytes on their way when the receipt was signed; and
   `charged` is no more than its own byte counts cost at the call's price, plus two 16 KiB chunks
   (one paid for and still being written each way when the other way signed; the gateway signs
   only for bytes it has counted). Over either, it is a seller fault.
4. **The price shown:** the wallet opens the tunnel only if the shop's terms are within the price
   the exit announced (`price_ceiling`: its price a GB, and nothing per request); an exit asking
   more is paid nothing and not used for a day, nor are its operator's other exits, unless it
   announces a higher price first (an honest exit raising its price). Announcing the same price or
   less doesn't end the hold.
5. **Liveness:** once a seller has sent one, bytes that keep flowing (2 MiB or more) with no newer
   one for 30 s (`B2_INTERIM_STALE_MS`) are a seller fault too, once the seller has had its say: two
   `status` answers in a row with nothing newer, or `status` failing (no answer, or none the wallet
   can take) for three times as long. A slow or lossy link to an honest seller is not taken for one
   that stopped counting, and a seller that answers only errors is still caught. (A `status` call
   still holds the session's `order` lock where the seller's `seqWindow` is 1, so a slow one delays
   the session's next request; it never stalls the tunnel's paying, which runs on its own thread.)
   A seller that never sends any (one from before interim receipts) is held to the rules every
   answer has: its spend never passes what was released.

A seller fault ends the call at once, the socket both ways, quiet or not, so the buyer's VPN fails
over to another exit; the session takes no more releases (the rule the web-app work already
applies); the receipt goes into the wallet's audit log as evidence (`ticket_interim_fault`). The
final receipt then closes the call as any answer's does.

### Exits that waste a buyer's money

Each paid tunnel pays its opening, so the buyer holds off exits that would make it pay for nothing
(`xbt_vpn::holds::Holds`), by exit and by **operator**, since exit ids cost nothing to make:
- a tunnel that ends within 10 s having carried under 16 KiB died young: its exit is held off for
  30 s, doubling to an hour, and an operator with three such exits in a day is held off as a whole.
  A tunnel that served well (lived longer, or carried more) starts its exit's doubling again;
- an exit asking more than it announced is held off for a day, with its operator (above);
- at most 48 paid tunnels are opened to one exit for one device in a day; only openings that
  succeeded (and were paid) count, so a while of wallet trouble doesn't lock an honest exit out;
- every hold and the daily count are asked again once a tunnel's turn to open comes, not only
  before it waits.

### Fitting the concurrent-session ceiling

The signer change that lets one session carry many paid calls keeps every call in its book of open
calls from send until its last receipt, and admits a receipt's session totals only within what the
open calls and the closed answers allow. Interim receipts fit it as follows:
- an interim receipt's session totals are not taken as the session's: the wallet checks only that
  its spend is within what it says was released, and orders interim receipts by `part`, not by the
  totals (the session's totals still come from ordinary receipts, as before);
- its `charged` is checked against the call's own maximum (check 2) and the buyer's count (check 3);
  as long as it never exceeds the call's maximum, the session ceiling already allows it;
- the call is closed only by its **final** receipt, which adds what the seller charged beyond the
  wallet's own count; interim receipts are never counted as a closed answer's charge.

