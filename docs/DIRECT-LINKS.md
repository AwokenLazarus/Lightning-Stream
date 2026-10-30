# Direct links: selling without a web address

A seller can sell a web service that runs on its own network (a media server, an AI model, any web
app) without a domain, a certificate, a tunnel or a port forward. Buyers reach it over a direct
link: an encrypted connection from the buyer's app to the seller's gateway that finds its way
through both home routers, or through a relay when it cannot. Payment works as it does over https:
the same 402 terms, tickets, metering and signed receipts.

This page covers what a shop without a web address is, how a buyer knows it is talking to the
seller it pays, what the seller and the buyer see, privacy, and packaging. The link itself (iroh:
QUIC, hole punching, relays) is in the `xbt-iroh-link` crate.

## A shop named by its key

A shop without a web address is named by its gateway's Nostr key. Everywhere the code wants a
seller's origin it gets one made from that key:

    http://<the key in base32, 52 letters>.shop.invalid

`.invalid` never resolves (RFC 6761), so nothing reaches that name except through a link the
shop's signed listing names. The policy, the allowlist, the counterparties, receipts and credit all
key on that origin and need nothing new. People see and share the key as an `npub` (NIP-19); the
app takes an `npub`, `nostr:<npub>` or `nostr:<64 hex>` wherever it takes a seller's address, and
the signer folds them into the origin (`xbt402::shop`).

The name proves itself. A shop's listing reaches buyers in a Nostr event, and a listing whose
`seller` is a shop name is accepted only from the key in that name. The receipt key that signs the
listing also binds that Nostr key to the seller, as it does for any listing (`docs/NOSTR.md`).

A listing with a shop name is an ordinary `listing/1`. Apps from before direct links read it, show
it, and then cannot connect to it, and say so.

## How a buyer reaches the shop: `transport/1`

Beside its listing, the shop publishes a `transport/1` document, signed by the same receipt key the
same way, that lists the links it can be reached by:

```json
{"version": "transport/1",
 "seller": "http://<base32>.shop.invalid",
 "receipt_key": "<hex>",
 "transport": [{"kind": "iroh", "endpoint_id": "<hex>", "relays": ["https://iroh.lazarus-xbt.xyz"],
                "direct": ["192.0.2.7:33512"], "expires": 1793000000, "node_sig": "<zbase32>"}],
 "updated": "2026-10-29",
 "sig": "<hex>"}
```

It is a document of its own and not a field of the listing, because apps before it refuse a
listing with a field they do not know. It travels in the shop's Nostr listing event as a tag of its
own (`transport`), and a shop that also has a web address serves it at
`/.well-known/lightning-stream-transport.json`.

### The node vouches for the link

A link key is an iroh endpoint key, and anyone can make one. What makes it the seller's is a
statement the seller's own Lightning node signs with lnd's SignMessage:

    lightning-stream link v1
    endpoint <endpoint id, hex>
    seller <the shop's origin>
    expires <unix time>

The buyer checks it offline, before it sends a byte: it recovers the signer from the signature and
compares it with the node it pays (`xbt402::claim`, `xbt402::transport::verify`). A link no node
vouches for, one another node vouches for, or one whose statement has expired is dropped. Links of
a kind the app does not know are skipped, so a seller can add kinds later.

A shop without a web address has no 402 terms reachable over the web to name its node, and its
listing names none. Its node is the one that vouches for its link
(`xbt402::transport::node_of`): whoever holds the shop's receipt key chose it, as a seller with a
web address chooses the node its terms name. The buyer's app allows the shop to be paid through
that node, and pays only it.

### Who signs

The gateway signs its own statement and renews it before it expires, with a key that holds one
permission: lnd's `SignMessage` (a URI permission, `uri:/lnrpc.Lightning/SignMessage`). The key
can sign messages and do nothing else; it cannot move coins or read the node. The box's key tool
bakes it beside the gateway's other keys (`sign.macaroon` in the gateway's key folder). A node that
will not bake it leaves the other keys alone: the shop then sells over its web address only, and
the Sell page says why its link is not reachable.

On StartOS, Lightning Fork's app grant gives the wallet its key and no gateway keys; the gateway's
keys, the sign key among them, are pasted on the Sell page until the node package grants them.

### One shop, several link keys

A gateway serves on several link keys at once (`link.endpoints`, 4 unless set; 1 to 8), all
leading to the same gateway, and the transport document names each, each vouched for by the node
the same way. The reason is relays: a relay carries each key over one connection and limits each
connection on its own (our relay: 6 MB/s, about 48 Mbit/s). A shop on one key that buyers can only
reach through a relay shares that one connection among all of them; on four keys it has four.

- **A buyer** checks every link in the document (the receipt key's signature, then the node's word
  for each key) before it sends a byte, then orders the keys by a hash of its own key, the shop
  and each link key, and uses the first. Buyers spread evenly; each keeps to the same key; a key
  that does not answer within 8 seconds is passed over for the next. Adding or removing a key
  moves only the buyers it takes or had.
- **Relays:** with no relays named, every key uses ours (four connections there). With relays
  named, each key has another one of them first, as its home.
- **Keys** are kept in the state directory: `link.key` (the key a gateway on one key always had,
  so it stays the first) and `link-2.key` onward.
- **Apps from before** take the first link of the document, which still works.
- **Cost:** a few hundred bytes of the document per key, one Nostr event per key, one node
  signature per key every 20 days, and one relay connection per key.

What it does not raise: the seller's own upload. When the home link is full, more keys do not help.

### The seller's side of the relay connection (BBR)

The bytes a shop sends through a relay leave over its own TCP connection to the relay, so the
congestion control on the seller's machine decides how fast that leg goes, not the relay's. Most
systems use cubic, which slows down on long or lossy paths. The app cannot change it (it is a
setting of the whole system, and the app runs without the right to), so it is the owner's choice:

- **Linux:** the same commands as for a relay server (`docs/RUN-A-RELAY.md`, "Faster single
  connections"). They apply to every program on the machine.
- **Umbrel:** the same, over SSH to the Umbrel box. An Umbrel update may undo it.
- **StartOS:** not offered; leave it as it is.

Several keys help either way: each is a connection of its own, with its own congestion window.

## What the seller sees

Sell → Your shop → **How buyers reach you**:

- **Directly, through the app** (the default, and recommended): no web address, no certificate,
  no port forward. The page shows the shop key to share, with a Copy button, and whether the node
  vouches for the link.
- **Private** (a switch under it): the link always goes through a relay, so buyers never learn the
  box's internet address. A little slower.
- **Advanced: use my own https address instead**: today's way, a tunnel or a proxy of one's own.

The seller adds services as before: a local address (`http://192.168.1.20:8096`), a name, a price.
The gateway serves them over its link as it serves them over https.

## What the buyer sees

Sellers → **Seller's address or shop key**: a web address or an `npub`. With a key, the app asks
its Nostr relays for that key's listings only, checks them, and keeps the shop's `transport/1`
beside its services. **Allow this seller to be paid** reads the shop's node from its link. Shops
are shown by their key with a **Direct link** mark. Paying, and a seller's web app opened through the link, are unchanged.

## Privacy

- **What a relay sees:** both ends' internet addresses, when and how much is sent. Never what: the
  link is encrypted end to end between the two gateways (TLS 1.3 in QUIC, keyed to the endpoint
  keys).
- **Direct paths** show each end's internet address to the other. **Private mode** keeps the shop
  on relays only, so buyers never see it.
- **What no mode hides:** that encrypted traffic flows, how much, and when.
- Unpaid traffic gets nothing: the gateway answers 402 until paid, over a link as over https.

## Packaging

- **Umbrel and StartOS:** the gateway reaches relays over https and peers over UDP, out through
  the containers' usual network; nothing is forwarded or published to the internet. A direct shop's
  gateway listens on the app's private network, where the app reaches it; its port is published
  nowhere. UDP 33512 is kept for the link's own socket, for a later option to let buyers on the
  same LAN connect without a relay.
- **Linux:** host networking, so the link uses the host's UDP directly; a direct shop's gateway
  listens on loopback, beside the app.
- **Relays:** the app names `https://iroh.lazarus-xbt.xyz` unless the seller chose others. A relay
  is needed when both ends sit behind routers that do not allow hole punching (many do not, and a
  VPN's exit often does not).

## Where it is

- `crates/xbt402/src/shop.rs`: shop names, npub, parsing what a person types.
- `crates/xbt402/src/transport.rs`, `crates/xbt402/src/claim.rs`: the document and the node's
  statement.
- `crates/xbt-nostr/src/market.rs`: the transport tag, and a shop listed only by its own key.
- `crates/xbt-signer/src/policy.rs` (`normalize_dest`): a key typed into the rules.
- `crates/xbt-wallet-ui`: the Sell and Sellers pages, `shops.json`, the sign key (`node_keys.rs`).
- Where the shops live: the app writes `run/shops/shops.json` (`XBT_SHOPS_FILE`; public data only: each
  shop's receipt key and signed transport document). The connector and the MCP read it, by the
  signer's group, and hand a shop's document to the signer in each call to that shop
  (`xbt_wallet_mcp::wallet::with_transport`). The signer never mounts it; it checks the document
  it is given before a byte goes.
- `crates/xbt-iroh-link` and the gateway and signer seams: the link.
