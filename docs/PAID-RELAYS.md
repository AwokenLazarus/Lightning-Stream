# Paid relays (0.3.0, draft)

**Status: design and core, not released.** The relay's metering and gate, its credit API, the
price and free allowance in the announcement, the choice of a home relay, the payer, the shop's
gateway paying its home relay and the box's relay settings are built behind switches that are off
by default, and tested on one machine (below). Nothing here has carried a real shop's traffic or
real money yet. A buyer's wallet paying a paid home relay, the packaging (the credit API reached
from the operator's gateway container, the gateway reaching the signer) and a run on regtest with
real Lightning payments are still to do.

A Stream relay carries encrypted traffic between two apps that can't reach each other directly
(`docs/RUN-A-RELAY.md`). Until 0.3.0 relays are free. With paid relays, a relay operator charges for
what the relay carries, by the GB, and the apps that make it their home pay it over Lightning, with
the same Stream tickets buyers pay shops with.

## Decisions (2026-11-04)

1. **Scanner.** The 9 upstream lines in the vendored iroh-relay that credit the project its relay
   protocol comes from are allowed by the publish scanner, each by path and exact text. Nothing else
   is relaxed.
2. **Who pays: each app pays its own home relay, and only that relay, for the bytes it receives
   there.** Every app has at most one relay account, at the home relay it chose. Nobody pays a
   relay it didn't choose. A buyer on a free home relay (the default: Genesis's, free for buyers
   unless its operator prices it) pays nothing and sees no change. A private-mode shop pays its home
   relay for what it receives.
3. **Price.** Each relay announces its own price per GB (2 sats a GB is the default for ours).
   Apps buy credits of 10 GB, within the owner's relays budget.
4. **The cap.** Each app's owner caps what it pays its home relay: "Most for relays in 24 hours"
   and "Most to any one relay", signed rules like the others, 0 by default. Past the cap, traffic
   waits for the next credit and is never silently dropped.
5. **Accounts** are per link key for 0.3.0.
6. **Free allowance.** 64 MB a day per key by default; each relay may change it in its
   announcement.
7. **Admitting relays.** Any relay announced on Nostr may be paid, within the relays budget.
   Genesis's relay, `relay.lightning-stream.com` (also served as `iroh.lazarus-xbt.xyz`, its 0.2
   name), is every app's default home.
8. **Choosing.** Every app starts on the default. It moves by itself to a clearly better relay
   (measured faster) at or below the owner's most per GB, and says so on its relay page; the owner
   can pin one instead.
9. **Carrying the iroh patch.** A fork of iroh pinned by commit, in place of the vendored copies,
   and an offer upstream of the generic hook (`docs/IROH-UPSTREAM.md`).

## Who pays whom, and why each side pays its own

In iroh a client is connected to one **home relay**, and a packet sent through a relay goes to the
relay its **receiver** is reached at. A relayed session can therefore cross two relays, one each
way: a buyer's requests reach a shop through the shop's home relay, and the shop's answers reach
the buyer through the buyer's home relay. Charging the shop for everything (the first draft) would
make it pay for the buyer's relay, which it didn't choose; charging by the receiver makes each side
pay the relay it chose for what that relay brings it.

There is one exception, measured (`crates/xbt-stream-relay/tests/relay_routes.rs`): iroh answers a
peer on the relay it heard from it on when it knows no other relay for it. A buyer in private mode
says nothing of its own home, so a shop's answers go back through **the shop's** home relay, the
one the requests came in on. As run on 2026-11-04, with a shop homed on one relay and a buyer on
another, the shop's relay carried both directions (14 KB of requests, 2 MB of answers) and the
buyer's relay nothing. The buyer didn't choose the shop's relay, so it isn't charged there; the
shop did, so the meter charges such a packet to its **sender** when the sender is homed on that
relay and the receiver isn't. In practice, then, a shop pays its home relay for most of its relayed
traffic, both ways, as the first draft had it; a buyer pays its own home relay only for what
reaches it there.

## How the relay measures bytes per app

The relay knows each client by its iroh key: for a shop, its **link key**. The relay's access
control sees every relayed packet: who it is from, who it is to, and its length (a small patch to
iroh-relay 1.4.1, `docs/IROH-UPSTREAM.md`; iroh-relay as published decides only on connect). The
meter (`crates/xbt-stream-relay/src/paid.rs`) charges each packet once, by the length of its
datagrams (the relay's framing is not counted):

1. to its **receiver's free allowance** (64 MB a day by default, as the relay announces it): hole
   punching, address discovery, a buyer's requests to a shop that doesn't pay this relay;
2. else to its **receiver**, when the receiver is homed here;
3. else to its **sender**, when the sender is homed here and the receiver isn't (above);
4. else it is not carried.

**Home** is the app's own word, signed: a balance read signed with the link key and `home=1` says
the relay is that key's home for 15 minutes, and the app's payer renews it every minute. Crediting
a key is a gift and declares nothing, so a key that never declared a relay its home is never
charged there, whatever credit it was given; and a key that moves its home stops being charged by
the old one within 15 minutes.

Each account keeps a running total of bytes charged in and out, what was credited, what was
received free, and what was dropped. The accounts are kept in the relay's state directory across
restarts.

**Neither side has to trust the other's count.** An app prepays one credit at a time (10 GB, 20
sats at 2 sats a GB) and buys the next only when its balance runs low. A relay that over-counts or
carries nothing can take at most what the app bought ahead and hasn't used: one credit and the low
water mark. An app that stops paying gets at most the grace (256 MB by default) past its credit:
that is the relay's exposure. An app that thinks a relay over-counts stops paying it and moves.

## Running out: traffic waits, and is never silently dropped

Past the grace, an app's traffic **waits** for its next credit: the relay holds the packet and
reads nothing more from its sender until it can forward it (iroh-relay's `Forward::Hold`; the
sender is slowed as by a full connection, and nothing is lost), asking again every 50 ms. The app's
payer sees `waiting` in its next balance read and buys a credit at once if its rules allow. If no
credit comes within 8 seconds, the packets are dropped and counted on the account
(`dropped_bytes`), which the app's payer reads and the owner is told of, until the app pays again;
the connection stays up, so the relay carries it again the moment it pays (a credit pays off the
debt first). Holding a packet holds its sender's other traffic through that relay too, for those
seconds.

Past the owner's cap (the relays budget in the signed rules) the signer refuses the next credit, so
the same happens: the traffic waits, then is dropped and counted, until the budget allows a credit.

## Paying: the relay is a seller

The relay doesn't touch Lightning. Its operator sells relay credit like any Stream service: a
priced route on the operator's own shop (gateway), paid with xbt402 tickets, whose upstream is the
relay's **credit API** (`crates/xbt-stream-relay/src/credit.rs`, on loopback or the operator's
private network):

| Request | |
| --- | --- |
| `POST <credit>/credit` `{"key": "<link key>"}` | the priced route: one paid request is one credit (10 GB) for that key, at the relay's price per GB. The gateway adds the secret `x-relay-credit-token` header (the route's `upstream_headers`), which the API requires |
| `GET <credit>/balance?key=&ts=&sig=` | free: the key's account, for its holder only. `sig` is the link key's ed25519 signature of `xbt-stream-relay/balance/v1\|<key>\|<ts>`, within 5 minutes of the relay's clock |
| `GET <credit>/balance?key=&ts=&sig=&home=1` | the same, and this relay is the key's home for 15 minutes: `sig` signs `xbt-stream-relay/home/v1\|<key>\|<ts>` |
| `GET <credit>/terms` | free: the price per GB, the credit's size and price, the grace, the free allowance |

So an app's signer pays the relay operator exactly as a buyer's signer pays any shop: tickets under
the owner's signed spending rules, receipts signed by the operator's gateway, money into the
operator's own Lightning node. Crediting a key is a gift to it, so the route needs no proof that
the payer holds the key; a balance shows how much an app receives, so only the key may read it.

The payer (`crates/xbt-iroh-link/src/relay_pay.rs`): for each link key homed on a paid relay, every
minute it declares the home and reads the key's balance; below the low water mark (1 GB by default)
or when its traffic waits, it reads the relay's terms, checks them against the announcement and the
owner's most per GB, and has the signer pay one credit with `xbt402_pay` (`task: "relays"`, a
`price_ceiling` of one credit and nothing by the byte). A refusal (a spending rule reached, the
wallet away, terms out of bounds) waits ten minutes before the next payment is tried; the home is
still declared meanwhile. The shop's gateway runs it from its `relay_pay` section, which the app
writes when the box's home relay charges and the gateway can reach the signer
(`XBT_UI_GW_SIGNER_SOCK`); otherwise the shop stays on Genesis's relay.

## Announcing a price

A paid relay is announced with the same kind-30078 event as a free one, with these changes
(`crates/xbt-nostr/src/relays.rs`):

| Tag | Value |
| --- | --- |
| `t` | `lightning-stream-relay-paid` **instead of** `lightning-stream-relay` |
| `price_msat_per_gb` | its price per GB, in msat (1 to 1,000,000) |
| `credit` | the https URL of the priced route on the operator's shop (`<credit>/credit`, `/balance`, `/terms`) |
| `free_bytes_per_day` | what each key may receive there free each day; left out, 64 MB |

The separate topic is what keeps older apps safe: an app before 0.3.0 asks only for the free topic
and so never makes a paid relay its home, where it would be cut off after its free allowance. An
announcement under both topics is refused. `xbt-relay-announce` takes `--price-msat-per-gb`,
`--credit` and `--free-mb-per-day`.

## Choosing a home relay

The same rules for every app, shop or buyer (`choose_home` in `crates/xbt-nostr/src/relays.rs`, kept
by the wallet UI in `relays.json`, a look each time the relays are probed and every half hour):

- Every app starts on **Genesis's relay**, and keeps its home while it answers.
- It moves by itself to a **clearly better** relay: one that answers in at most three quarters of
  the home's round trip and at least 20 ms quicker, in two looks in a row. Only relays it may use
  count: not blocked, and a paid one only when the owner allows paid relays at its price or more.
  The relay page says when and why it moved.
- A home that stops answering, or is no longer allowed, is replaced by the quickest that is.
- A relay the owner **pins** is home whenever it answers.

"Faster" is measured from the box itself (a WebSocket upgrade to each relay). For a shop that is a
stand-in for its buyers, whose round trips the shop doesn't see.

The other relays the app knows stay behind the home in its relay list: when the home stops
carrying, the link falls back to them. The shop's link names its home first and Genesis's relay
after it; a list of relays the owner wrote by hand into the gateway's config is kept.

## The box's relay settings

Settings → Stream relays, Home relay: the box's home relay, its price and free allowance, the last
time it moved by itself, the owner's pin (or "choose by itself"), and the most a home relay may
charge per GB (0 keeps the box on free relays). The relays budget is in the spending rules beside
the others: **Most for relays in 24 hours** and **Most to any one relay in 24 hours**, a ticket task
`relays` (`admit: "any"`, since relays are found on Nostr, not on the owner's allowlist; the cap
for one relay is the task's `unlisted_max_spend_sats`). Both 0, the default: no relay is paid, and
the box keeps a free home relay. They are signed by the owner, so the gateway cannot raise them.

## Privacy

The relay already sees the two apps' addresses and how much passes between them; paid relays add
only an account per link key: credits, bytes in and out. It never sees contents (the link is
encrypted end to end). The account is readable only with the link key's signature. The operator's
gateway sees one paid request per credit from the app's wallet, with the link key in its body, as
any shop sees its buyers' requests. A shop's link key is already public in its listing.

## Abuse: a flood costs what the owner allows, no more

A buyer that floods a shop's home relay with packets to the shop makes the shop pay for what it
receives, as any traffic would, up to the owner's relays budget: past it the shop's traffic waits,
then is dropped and counted, and the relay's per-client rate limit applies to the flooder as
before. The first draft's inbound cap (inbound charged up to the shop's own outbound in the hour)
is gone: the owner's budget is the cap now, for what the app receives.

## Compatibility

- **Off by default on every side.** A relay is paid only with `paid.enabled` in its `relay.json`;
  otherwise it runs the free meter, which carries everything as in 0.2. A shop pays only with a
  `relay_pay` section in its gateway config, which the app writes only for a paid home and a
  gateway that reaches the signer. An app uses paid relays only when its owner sets a most per GB
  above 0 and a relays budget.
- Older apps never see paid relays (the topic). Free relays' announcements are unchanged.
- Genesis's relay is named `relay.lightning-stream.com`; `iroh.lazarus-xbt.xyz`, its 0.2 name, is
  the same relay, so announcements, pins and kept homes under the old name count as the new one.
- The iroh-relay patch only adds a hook whose default carries everything; iroh's relay client
  builds from the same copy and is unchanged.

## What is built and tested

- iroh-relay (`vendor/iroh-relay` until the fork is pushed, `docs/IROH-UPSTREAM.md`): the
  `on_forward` hook, answering `Forward::{Yes, Drop, Hold}`, and its test against a real relay (a
  per-sender budget; dropped packets, held packets forwarded in order once there is budget).
- `xbt-stream-relay`: the paid meter, the credit API with home declarations, `relay.json`'s `paid`
  section, accounts kept across restarts, totals on the status file. Unit tests for receiver pays,
  sender pays on its own home, nobody paying a relay it didn't choose, the free allowance, the wait
  and the drop, prices and credits, the API's token and signatures. Integration tests with real
  relays on loopback (`tests/paid_relay.rs`, `tests/relay_routes.rs`): the free allowance carrying
  a small download unpaid; a shop paying its home relay to the byte; a download that outruns the
  credit waiting at the relay and completing when the next credit comes, nothing dropped; a spent
  budget dropping and counting, then carrying again on payment; a shop and a buyer on two paid
  relays, each with an account only at its own; a shop moving its home and the old relay charging
  nothing more; a free relay unaffected; which relay carries which direction.
- `xbt-nostr`: the paid announcement with its free allowance, the choice by price, the home relay
  choice (start on the default, a clearly better relay after two looks, replacement, pin), the old
  name of Genesis's relay.
- `xbt-iroh-link`: the payer, the signed home declaration and balance read.
- `xbt-gateway`: the `relay_pay` section and its payer thread.
- `xbt-wallet-ui`: the Home relay card and its form, the relays budget in the rules, the home
  relay kept in `relays.json`, the shop's link and `relay_pay` written from the home.

Not built: a buyer's wallet (the signer's link) paying a paid home relay; until then a buyer's link
stays on Genesis's relay, free. Not run: a regtest with real Lightning payments for credit through
an operator's gateway.
