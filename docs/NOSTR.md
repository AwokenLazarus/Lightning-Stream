# Nostr in Lightning Stream

Nostr is how a buyer's app finds sellers without anyone running a directory. The rest of the
work stays where it already is:

| What | Carried by | Why |
| --- | --- | --- |
| Finding sellers: who sells what, at what price | **Nostr** (this document) | Anyone can publish and anyone can read. No site of the seller's own is needed to be found, and no directory decides who is listed. |
| The bytes a buyer pays for (video, files, API answers) | **HTTP**, to the seller's gateway | Relays are built for small signed notes, not streams. A gateway serves ranges, seeks and keeps a stream going at the speed the buyer pays for. |
| The money | **Lightning** (tickets, `docs/TICKETS.md`) | It settles as the pieces arrive, and nobody holds anyone's money. |
| Wallets reached by other apps | **Nostr**, as NIP-47 (`docs/NWC.md`) | Already built: the app is an NWC wallet service for its owner's own node. |
| Hashrate (planned) | A direct encrypted link between the two apps | Mining needs low latency and a steady connection. Nostr would only list the offers. |

## A listing on Nostr

A seller's listing is the signed `listing/0` or `listing/1` document of `docs/LISTINGS.md`, the same one its
gateway serves at `/.well-known/lightning-stream.json`. On Nostr it goes out as a **NIP-99
classified listing**: kind `30402`, one addressable event per Nostr key and seller.

### Why NIP-99 and not NIP-15

NIP-15 (kinds `30017` stall and `30018` product) models a shop of physical goods. It has stalls,
stock counts, shipping zones and a checkout over encrypted direct messages. None of that fits a
service paid by the piece, and its checkout would be a second payment path beside the tickets.
NIP-99 is one event per listing, with a title, a summary, a price and Markdown text, which is what
we have to say. It is also, as far as we know, what current Nostr marketplaces build on: Shopstr
reads kind `30402`, and the newer Gamma market spec builds its products on it. So a seller's
listing shows up in an ordinary classifieds client as well as in ours. We may be wrong about which
clients read what. The event is a plain NIP-99 listing either way, and our own reader needs
nothing else.

### The event

| Field or tag | Value |
| --- | --- |
| `kind` | `30402` |
| `d` | The seller's canonical origin (`https://media.example`). One listing per seller and Nostr key: a new one replaces the old. |
| `title` | The listing's `name` |
| `summary` | `video over Lightning Stream: 20 sat a MiB` |
| `price` | `["price", "20", "SAT", "MiB"]`: the first price of the listing, in sats, and its unit (`request`, `MiB`, `second`, ...) |
| `t` | `lightning-stream`, and the listing's kind (`video`, `files`, `api`). Readers ask relays for `#t: lightning-stream`. |
| `r` | The seller's URL |
| `published_at`, `alt` | As NIP-99 and NIP-31 ask |
| `xbt402-listing` | The signed `listing/0` or `listing/1` document, compact JSON |
| `xbt402-bind` | Hex of the receipt key's DER signature binding this Nostr key to this seller (below) |
| `content` | Markdown for people: the name, the price, the items (the first 50), the licence, the credits and the seller's URL |

Everything a classifieds client shows (the tags and the Markdown) is written from the signed
document. Our reader takes nothing from them: it reads the signed document only.

An event is at most 60 KiB, because many relays refuse events above 64 KiB. A listing with too many
items to fit is refused at publish time, with a message saying so.

### The binding

The Nostr key that signs the event is not the receipt key. It is a separate key the gateway keeps
(`nostr.key` in its state directory), so the receipt key never signs anything but receipts,
listings and this binding. The receipt key binds the two by signing a tagged hash:

```
tag    xbt402/nostr-bind/0
field  the Nostr public key, 32 bytes (x-only)
field  the seller's canonical origin, UTF-8
```

Each field is length-prefixed, as in a request digest (`docs/TICKETS.md`). The signature is ECDSA
over the 32-byte digest, DER, in hex.

With the binding, only the seller can publish its listing. Anyone can copy a genuine listing into an
event of their own, but the binding then names the wrong Nostr key and the reader refuses it. A
seller that moves to a new Nostr key binds the new one too. Readers keep the newest event per
receipt key and seller, whichever key signed it.

### What a reader checks

A buyer's app keeps an event only when all of these hold:

1. The event's id and BIP-340 signature hold (NIP-01).
2. It is kind `30402`, tagged `t: lightning-stream`, at most 60 KiB, and dated no more than ten
   minutes ahead of the reader's clock.
3. The `xbt402-listing` document verifies under the receipt key it names (`listing/0` or `listing/1`).
4. `d` is that listing's seller origin.
5. `xbt402-bind` is that receipt key's binding of the event's author to that seller.

Of each receipt key and seller, it keeps the newest event.

### Unvetted, and the Check

The steps above prove that one key signed the listing and chose this Nostr key to publish it. They
do not prove that the key belongs to the seller at that URL. Anyone can make a key, sign a listing
naming `https://media.example`, and publish it. A listing read from Nostr is therefore **unvetted**.

The app shows such listings on their own page (Browse, then Nostr), marked unvetted. Its **Check
with the seller** button asks the seller's own address: it fetches the listing from the well-known
URL, and the 402 terms from one of the seller's priced URLs. It passes only when those terms name
the same receipt key (`xbt402::listing::fetch`). A payment made without the check still keeps to
the owner's policy and budgets, as every payment does.

## Running it

**Seller (the gateway).** Off unless the config says so, and only with a `listing` section:

```json
"nostr": {"relays": ["wss://relay.example"], "publish": true, "republish_s": 21600}
```

The gateway publishes at start and every `republish_s` seconds (six hours by default; from 600 to
604800). It reads nothing from relays. A relay that refuses the event or is down is logged, and is
tried again at the next republish. At most ten relays; `ws://` is accepted only to this machine.

**Buyer (the wallet UI).** `XBT_UI_NOSTR_RELAYS`: the relays to read, comma-separated. Unset (the
default): Browse has no Nostr page, and no relay is ever asked. When it is set, the relays are
asked only when the owner opens the Nostr page, for up to 200 listings each, with eight seconds per
relay. The answer is kept for two minutes.

The programs set no relay by default on either side: which relays to use is the owner's choice. The
packages choose for a new install, and the owner can change it: the Umbrel app and the Linux package
use `wss://relay.damus.io`, `wss://nos.lol` and `wss://relay.kilombino.com` for what the wallet UI
reads (`XBT_UI_NOSTR_RELAYS`) and for the hashmaker's and hashtaker's `--relays`; on Linux,
`LS_RELAYS` in `.env` sets them all. The gateway's `nostr.relays` above is set in its own config. The StartOS packages don't use Nostr yet.

## Planned, not built: small messages over Nostr

Nothing below exists yet. It is written down so that what comes next fits what is here.

Some of a session's small messages could go over Nostr instead of HTTP. That would let a buyer
reach a seller with no public HTTP address for anything but the data itself, such as a seller
behind Tor, or one whose gateway is reached only through a relay:

- **Terms:** the 402 terms of a route, asked for and answered as NIP-44 encrypted ephemeral events
  between the buyer's key and the seller's bound Nostr key.
- **Invoice exchange:** a lock (the buyer's payment hashes) and the gateway's held invoices back,
  and the release of a used ticket's secret. These are small, and they are the steps where the
  seller's gateway does not need to be reachable over HTTP.
- **Receipts:** the gateway's signed receipt for a piece, so that a buyer keeps them even when the
  data comes from a mirror.

The bytes themselves stay on HTTP, for the reasons in the table at the top. Before any of this is
built, it needs a measure of what a relay round trip adds to each ticket, against the gateway's
refill wait (`docs/TICKETS.md`): a ticket that waits for a relay must not stall the stream it pays
for.

## Limits

- Only listings are on Nostr today. Terms, invoices and receipts are HTTP, as before.
- A reader trusts its relays for completeness, not for truth. A relay can hide a listing or serve an
  old one, but it cannot forge one. Asking several relays narrows the first.
- The gateway keeps one Nostr key. Rotating it is deleting `nostr.key`. The old key's event stays on
  relays until they drop it, and readers prefer the newer event of the same receipt key and seller.
- Only kind `30402` is written. A NIP-15 shop client does not show these listings.
