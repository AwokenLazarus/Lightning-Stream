# Paid relays (0.3.0, draft)

**Status: design and core, not released.** The relay's metering and gate, its credit API, the
price in the announcement, the choice of relays by price and the shop's payer are built behind
switches that are off by default, and tested on one machine (below). Nothing here has carried a
real shop's traffic or real money yet. The pages for sellers and relay operators, the packaging
(the credit API reached from the operator's gateway container) and a run on regtest across a real
relay are still to do.

A Stream relay carries encrypted traffic between a buyer's app and a shop that can't reach each
other directly (`docs/RUN-A-RELAY.md`). Until 0.3.0 relays are free. With paid relays, a relay
operator charges for what the relay carries, by the GB, and a shop pays the relays it uses over
Lightning, with the same Stream tickets buyers pay shops with.

## Who pays whom

**The shop pays each relay it uses, for the bytes that relay carried for it.** In iroh a buyer
reaches a shop through the shop's home relay, so the bytes a relay carries for a shop's sales are
on the shop's account: the shop builds them into its prices. Buyers pay nothing to the shop's
relay. (A buyer that chooses a relay for itself, as in a private mode, would pay it the same way;
that is not built.)

## How the relay measures bytes per shop

The relay knows each client by its iroh key: for a shop, its **link key**. The relay's access
control now sees every relayed packet: who it is from, who it is to, and its length (a small patch
to iroh-relay 1.4.1, `vendor/iroh-relay/XBT-PATCH.md`; iroh-relay as published decides only on
connect). The meter (`crates/xbt-stream-relay/src/paid.rs`) charges each packet once, by the length
of its datagrams (the relay's framing is not counted):

- to its **sender** when the sender has an account with credit ("out": the shop's answers);
- else to its **receiver** when the receiver has one ("in": buyers' requests to the shop), up to
  the inbound cap below;
- else to the sender's **free allowance** (64 MB a day by default per key: hole punching, address
  discovery, a buyer's requests to a shop that does not pay this relay), and past that it is not
  carried.

Each account keeps a running total of bytes charged out and in, what was credited, and the bytes
refused for want of credit. The accounts are kept in the relay's state directory across restarts.

**Neither side has to trust the other's count.** The shop prepays small credits (by default 20
sats, 10 GB at 2 sats a GB) and buys the next one only when its balance runs low. A relay that
over-counts or carries nothing can take at most what the shop bought ahead and hasn't used: one
credit and the low water mark, like a buyer's exposure on prepaid stream tickets. A shop that stops
paying gets at most the grace (256 MB by default) past its credit: that is the relay's exposure.
A shop that thinks a relay over-counts stops paying it and moves elsewhere.

## Paying: the relay is a seller

The relay doesn't touch Lightning. Its operator sells relay credit like any Stream service: a
priced route on the operator's own shop (gateway), paid with xbt402 tickets, whose upstream is the
relay's **credit API** (`crates/xbt-stream-relay/src/credit.rs`, on loopback or the operator's
private network):

| Request | |
| --- | --- |
| `POST <credit>/credit` `{"key": "<link key>"}` | the priced route: one paid request is one credit for that key. The gateway adds the secret `x-relay-credit-token` header (the route's `upstream_headers`), which the API requires |
| `GET <credit>/balance?key=&ts=&sig=` | free: the key's account, for its holder only. `sig` is the link key's ed25519 signature of `xbt-stream-relay/balance/v1\|<key>\|<ts>`, within 5 minutes of the relay's clock |
| `GET <credit>/terms` | free: the price per GB, the credit's price and size, the grace and the free allowance |

So the shop's signer pays the relay operator exactly as a buyer's signer pays any shop: tickets
under the owner's signed spending rules, receipts signed by the operator's gateway, money into the
operator's own Lightning node. Crediting a key is a gift to it, so the route needs no proof that
the payer holds the key; a balance shows how much a shop sells, so only the key may read it.

The shop's side (`crates/xbt-iroh-link/src/relay_pay.rs`, run by the gateway's `relay_pay`
section): for each link key whose home relay is a paid one, every minute it reads the key's
balance; below the low water mark (1 GB by default) it reads the relay's terms, checks them against
the announcement and the owner's bounds, and has the signer pay one credit with `xbt402_pay`
(`task: "relays"`, a `price_ceiling` of one credit and nothing by the byte). A refusal (a spending
rule reached, the wallet away, terms out of bounds) waits ten minutes before the next try.

## Announcing a price

A paid relay is announced with the same kind-30078 event as a free one, with three changes
(`crates/xbt-nostr/src/relays.rs`):

| Tag | Value |
| --- | --- |
| `t` | `lightning-stream-relay-paid` **instead of** `lightning-stream-relay` |
| `price_msat_per_gb` | its price per GB, in msat (1 to 1,000,000) |
| `credit` | the https URL of the priced route on the operator's shop (`<credit>/credit`, `/balance`, `/terms`) |

The separate topic is what keeps older apps safe: an app before 0.3.0 asks only for the free topic
and so never makes a paid relay its home relay, where it would be cut off after its free
allowance. An announcement under both topics is refused. `xbt-relay-announce` takes
`--price-msat-per-gb` and `--credit`.

## Choosing relays

`select_for` ranks relays as before (round trip for AI and pages, throughput for video and files),
with two additions (`Prefs::paid`, `Prefs::max_msat_per_gb`, kept in `relays.json` as `paid` and
`max_msat_per_gb`):

- A paid relay is left out, like one that doesn't answer, unless the owner allows paid relays and
  its price is at most the owner's most per GB. The owner's own relays are never left out for a
  price.
- Between relays that rank the same, the cheaper first.

The free relays and ours (last) stay in the list behind any paid one: when a paid relay stops
carrying the shop, or stops answering, the link falls back to them.

## Running out

When the shop's credit is used up the relay carries it for the grace, then stops: its packets, and
packets to it, are dropped unless the free allowance covers them. The shop's connection stays open,
so the relay carries it again the moment it pays (a credit pays off the debt first). Today the
shop's payer logs the refusal; Phase 2 makes the link move its home to the next relay when its
paid relay stops carrying it, and shows the owner why.

## Privacy

The relay already sees the two apps' addresses and how much passes between them; paid relays add
only an account per link key: credits, bytes in and out. It never sees contents (the link is
encrypted end to end). The account is readable only with the link key's signature. The operator's
gateway sees one paid request per credit from the shop's wallet, with the link key in its body, as
any shop sees its buyers' requests. The link key is already public in the shop's listing.

## Abuse: a buyer can't make a shop pay by flooding

Bytes into a shop are charged to it only up to its own outbound bytes in the same hour (100%,
`inbound_pct`), plus a small allowance (8 MB). A buyer that floods a shop therefore costs it at
most about what the shop itself sent that hour; the rest falls on the flooder's own free allowance,
then is dropped, and the relay's per-client rate limit applies to the flooder as before. The shop's
spending rule caps the day whatever happens.

## Compatibility

- **Off by default on both sides.** A relay is paid only with `paid.enabled` in its `relay.json`;
  otherwise it runs the free meter, which carries everything as in 0.2. A shop pays only with a
  `relay_pay` section in its gateway config, and an app uses paid relays only with `paid` in
  `relays.json`.
- Older apps never see paid relays (the topic). Free relays' announcements are unchanged.
- The iroh-relay patch only adds a hook whose default carries everything; iroh's relay client
  builds from the same copy and is unchanged.

## The seller's spending rule

"**Most for relays per day**" is a ticket task named `relays` in the wallet's policy, with
`budget_sats` the most per day and `window_s` 86400. It is a task like the others, signed by the
owner, so the gateway cannot raise it. The relay route is paid with `admit: "any"` within that
budget (relays are found on Nostr, not on the owner's allowlist), or the owner adds each relay
operator's shop to the allowlist. Phase 2 puts it on the wallet's rules page beside a seller's
other settings.

## What is built and tested (Phase 1)

- `vendor/iroh-relay`: the `on_forward` hook.
- `xbt-stream-relay`: the paid meter (`paid.rs`), the credit API (`credit.rs`), `relay.json`'s
  `paid` section, accounts kept across restarts, totals on the status file. Unit tests for the
  metering, the inbound cap, the grace and resuming, the free allowance, prices, the API's token
  and signature checks; an integration test (`tests/paid_relay.rs`) with a real relay on loopback,
  a shop and a buyer reaching each other only through it, and the shop's payer paying through a
  stand-in wallet: the shop is charged for what was carried (the body and the link's overhead), is
  stopped within the grace when it stops paying, and is carried again when it pays; and a free
  relay carrying everything.
- `xbt-nostr`: the paid announcement and the choice by price.
- `xbt-iroh-link`: the payer and the signed balance read.
- `xbt-gateway`: the `relay_pay` section and its payer thread.

## Open questions for the owner

1. **Price and credit size.** 2 sats a GB and 20-sat credits (10 GB)? A smaller credit lowers the
   shop's exposure but means more payments: at 4K video rates (11 to 36 GB an hour) a shop buys
   a credit every few minutes.
2. **Inbound bytes.** Charging inbound up to 100% of outbound an hour suits video and files. A VPN
   exit or an upload service receives more than it sends: should the shop set its own cap, or
   should inbound past the cap be carried free (the operator's cost) rather than dropped?
3. **One account per shop, or per key.** A shop on several link keys now pays each key separately.
   Binding keys into one account needs a signature from each; worth it?
4. **Free allowance.** 64 MB a day per key, or 0 (paid-only relays)? It is also what buyers'
   requests to non-paying shops ride on.
5. **Admitting relay operators.** `admit: "any"` within the relays budget, or only operators the
   owner adds? The first is easier; the second is safer if the gateway is compromised.
6. **Who chooses for the shop.** Should a shop pick a paid relay by itself when it measures one
   clearly better (within the owner's price), or only when the owner pins it?
7. **Upstreaming the iroh-relay hook.** Offer it to iroh as is, or keep the patch?
