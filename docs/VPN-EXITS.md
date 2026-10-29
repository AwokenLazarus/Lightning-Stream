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
writes there: `endpoint.json` (the WireGuard key devices pair with), `status.json` and
`exit-status.json`. A device's private key is shown once and never kept.

## Measured

On a home LAN (a 100 MB HTTP file):

| Path | Flows | Throughput | Notes |
| --- | --- | --- | --- |
| Exit on a Raspberry Pi 4 | 4 | 122–148 Mbit/s | Pi exit at 75% of one core |
| Same, through a first hop | 4 | 127 Mbit/s | sealing costs about 11% |
| Exit on a PC, through a Pi 4 first hop | 4 | 111–120 Mbit/s | the Pi hop at 90% of one core (of 4) |
| A WireGuard client (Pi) through the buyer's app | 1 | 43–48 Mbit/s | 94 Mbit/s without the tunnel |

Category lists in memory: adult 953,393 names (0.3 s to load, about 82 MiB); malware 2,655,820
names (0.8 s, about 140 MiB).

## Paying (designed, not built)

An exit is a Stream seller whose price is per GB, and it is paid with the same tickets as any other
service, so a buyer's spending rules (per-seller and daily caps, the approval threshold) apply.

### What exists today, and what is missing

A long-lived flow already has a seam: one `xbt402_pay` call with `stream_to` (a socket the flow's
bytes cross) and `upgrade` on a route that carries WebSockets. The signer meters bytes both ways and
pays the next ticket ahead in its watcher. Each such call is bounded by its `max_sats` and
`max_answer_s` (at most 86,400 s). But the seller signs **one receipt, at the call's end**. A VPN
session lives for hours and carries many flows, so the buyer must be able to check the exit's
charges while it runs, not only at the end. That needs a new piece on both sides: **interim
receipts** for an answer still open, issued by the gateway and checked by the signer.

### Interim receipts

The same signed receipt as today (`xbt402::ticket::receipt_message`, the receipt key of the
seller's terms, the same `scheme` and `session`), with these fields added:

| Field | Meaning |
| --- | --- |
| `interim` | `true`: the answer is still open. The final receipt has no `interim`, exactly as today. |
| `seq` | The call's sequence number (the same one the final receipt carries). |
| `part` | 1, 2, 3…: one more for each interim receipt of this call. |
| `bytesUp`, `bytesDown` | Bytes carried each way on this call so far, as the seller counts them. |
| `charged` | What this call has cost so far, in msat (the field the final receipt already has). |
| `releasedMsat`, `spentMsat` | The session's totals, as today. |

**Cadence:** the gateway sends one on the call's control stream each time `charged` grows by the
price of 1 MiB, or every 10 s while bytes flow, whichever comes first; none while the call is idle.

### What the signer checks on each one

Everything it checks on a final receipt today (the signature, the session, `spentMsat` never above
`releasedMsat`, `releasedMsat` never above what the wallet released and never falling), and also:

1. **Order:** `part` is exactly one more than the last; `charged`, `bytesUp` and `bytesDown` never fall.
2. **The ceiling:** `charged` never exceeds the call's own `max_sats`. This is the same per-call
   ceiling the concurrent-session fix enforces across concurrent calls (its must-fix #2): the sum of
   all open calls' `charged` stays within what the session may spend.
3. **The seller's count against the buyer's:** `charged` is at most the price of the bytes the
   buyer's own side counted for this call (`Device::meter` for a VPN flow), plus a tolerance for
   framing (2% plus 64 KiB). Over that, it is a seller fault.
4. **Liveness:** if bytes keep flowing and no interim receipt arrives for 30 s (three periods), the
   wallet treats it as a seller fault too.

A seller fault stops the session at once, for all its calls (the rule the web-app work already
applies), keeps the receipts as evidence, and tells the owner in plain words. The final receipt then
closes the call as today, and must agree with the last interim one.

### Fitting the concurrent-session ceiling

The signer change that lets one session carry many paid calls keeps every call in its book of open
calls from send until its last receipt, and admits a receipt's session totals only within what the
open calls and the closed answers allow. Interim receipts fit it as follows:
- an interim receipt's session totals go through the same check as any receipt's (older ones are
  passed over by value, so order is checked by `part`, not by the totals);
- its `charged` is checked against the call's own maximum (check 2) and the buyer's count (check 3);
  as long as it never exceeds the call's maximum, the session ceiling already allows it;
- the call is closed only by its **final** receipt, which adds what the seller charged beyond the
  wallet's own count; interim receipts are never counted as a closed answer's charge.

### How a VPN session uses it

1. **One session per buyer at each exit,** keyed to the key the buyer shows the exit (its link key,
   or its sealed key behind a first hop).
2. **One long-lived call per device,** carrying all that device's flows to that exit, priced as
   `byteMsat` per `perBytes` both ways.
3. **Paid as you use it, with no pause:** the wallet keeps one small ticket in hand and pays the next
   just before it runs out. At most one ticket is ever at risk with an exit.
4. **A clean stop at a limit:** when a device's or the wallet's limit is reached, new flows are
   refused and live ones end; the exit stops carrying a buyer whose credit is gone, after a short
   grace for a refill in flight.

**Build order:** after the concurrent-session must-fixes land on `fix/concurrent-session`: the
interim receipt in `xbt402` (format, signing, verification); the gateway issuing them on an open
answer; the signer's four checks; then the VPN exit as a seller and the buyer's call per device.
