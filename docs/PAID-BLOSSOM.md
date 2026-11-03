# Paid media on Blossom: encrypted blobs, keys sold through Lightning Stream

Status: design only. Nothing here is built. It builds on [NWC-BLOSSOM.md](NWC-BLOSSOM.md) (Blossom
by hash, built behind `XBT_UI_FILES_BLOSSOM`; `listing/2`; the plain-Lightning question) and on
the stream tickets of [TICKETS.md](TICKETS.md).

**The idea.** A creator encrypts a film once and publishes the ciphertext to Blossom servers. The
ciphertext is addressed by its SHA-256, so anyone can mirror it for free. What is sold is the key,
by the creator's shop, through Lightning Stream. Long video must stream and seek, so the key is
sold in parts as the fan watches.

Specs and prior work read (2026-11-03):

- Blossom BUDs, <https://github.com/hzrd149/blossom/tree/master/buds>: BUD-01 (`GET`/`HEAD
  /<sha256>`, ranges, CORS `*`), BUD-02 (upload, list, delete, kind 24242 auth), BUD-04 (mirror),
  BUD-06 (upload preflight), BUD-07 (`402` with `X-Lightning`/`X-Cashu`), BUD-08 (`nip94` in the
  blob descriptor). Summarized in NWC-BLOSSOM.md.
- NIP-94, <https://github.com/nostr-protocol/nips/blob/master/94.md>: kind 1063 with `url`, `m`,
  `x` (hash of the served file), `ox` (hash before the server transformed it), `size`, `dim`,
  `blurhash`, `thumb`, `image`, `summary`, `alt`, `fallback`, `service`.
- NIP-17 kind 15 (encrypted file messages), <https://github.com/nostr-protocol/nips/blob/master/17.md>:
  a whole file encrypted with `aes-gcm`, the `decryption-key` and `decryption-nonce` in tags of a
  sealed DM, `x` the ciphertext hash, `ox` the plaintext hash. One key and one nonce for the whole
  file: no random access, and the thumbnail and fallbacks share the key. It is a DM format, for one
  recipient; we borrow its tag names, not its layout.
- NIP-44 v2 (already used by `xbt-nwc`) for wrapping keys to a buyer.
- Paywall proposals: NIP-63 "exclusive content" (PR
  <https://github.com/nostr-protocol/nips/pull/2156>, open, unmerged) gates by membership lists
  (kind 1163) on relays and defines no encryption. Discussion around it describes encrypted media
  on Blossom with an `encrypted` imeta flag, a per-event key, and a gate server that returns an
  invoice and releases the key once paid. None of these defines chunking, seeking or partial sale.

## 1. Encryption format: `ls-pb/1`

**Choice: AES-256-GCM per fixed-size chunk, with a key per segment of chunks derived from one
content key.** Not XChaCha20-Poly1305: WebCrypto has AES-GCM and no ChaCha, and the browser player
must run without a WASM crypto library. AES-GCM's 96-bit nonce is safe here because nonces are a
counter under a key that is never reused (below), so the random-nonce limit does not apply.

**Keys.**

- `K`: the content key, 32 random bytes, made fresh for every encryption. It never encrypts
  anything itself. Encrypting the same film again makes a new `K` and a new ciphertext hash.
- `S_j = HKDF-SHA256(ikm=K, salt=file_id, info="ls-pb/1 seg" ‖ u32be(j))`: the key of segment `j`.
  HKDF is one-way: a buyer with some `S_j` learns nothing about `K` or other segments.
- `M = HKDF(K, file_id, "ls-pb/1 meta")`: seals the metadata record (below).

**Layout.** One file, one blob:

```text
[ header: 4096 bytes, plain                                   ]
[ chunk 0 | chunk 1 | ... | chunk n-1 ]   each = ciphertext ‖ 16-byte tag
```

Header fields (fixed offsets, rest zero padding): magic `LSPB`, version 1, algorithm 1
(AES-256-GCM), `chunk_size` (plaintext bytes, default 65,536), `seg_chunks` (chunks per segment,
default 256, so a segment is 16 MiB of plaintext, about 25 s of 5 Mb/s video), `plain_size`,
`file_id` (32 random bytes), `free_segments` (count of preview segments, see 2), and the sealed
metadata record (at most 3 KiB, AES-GCM under `M`, nonce 0): the inner MIME type, duration, the
plaintext SHA-256, and an optional time-to-byte index for containers without one.

**Each chunk `i`** (in segment `j = i / seg_chunks`) is AES-256-GCM under `S_j`, nonce =
`u96be(i)`, AAD = `SHA-256(header) ‖ u64be(i) ‖ last` where `last` is 1 for the final chunk and
0 otherwise. Binding the header and the index stops chunks being swapped or moved; the `last`
flag stops truncation (the STREAM construction's rule). Overhead is 16 bytes per 64 KiB (0.02%).

**Seeking.** Plaintext offset `p` is in chunk `i = p / chunk_size`, at ciphertext offset `4096 +
i × (chunk_size + 16)`. A player turns any plaintext byte range into one ciphertext range
(BUD-01 serves ranges), fetches it from any mirror, checks each tag, decrypts, and trims. It needs
`S_j` only for segments the range touches. Every chunk is authenticated on its own, which closes
the gap in NWC-BLOSSOM.md 3c (a whole-file hash cannot refuse a bad byte mid-stream): a mirror
that serves a wrong byte is caught at that chunk, and the player tries the next mirror.

**What is inside.** The plaintext is the creator's file, unchanged. The browser can seek it only
if it is an MP4 with the `moov` at the front (faststart) or a fragmented MP4; the Sell page checks
this and warns (2, 7). Byte segments, not HLS segments, keep one blob per film, one hash, one
1063 event, and make the format indifferent to the codec. HLS or DASH with CENC would need a
manifest and many blobs, and EME ClearKey in the browser, for no gain in what is protected.

## 2. What is published

- **The ciphertext SHA-256**, as the Blossom address, on the creator's box and on mirrors.
- **A kind 1063 event**, signed by the shop's Nostr key:
  - `x` the ciphertext hash, `size` the ciphertext size, `url` the shop's Blossom URL, `fallback`
    each mirror;
  - `m` = `application/octet-stream`, so a client that ignores the rest does not try to play it,
    and `["encryption", "ls-pb/1"]`, `["inner-m", "video/mp4"]`, `["duration", "<s>"]`, `dim`;
  - `thumb` and `image` as plain Blossom blobs, `blurhash`, `summary`, `alt`;
  - `["price", "<sat per segment>", "<sat for the whole>", "SAT"]`, advisory only, since kind
    1063 is not replaceable;
  - `["shop", "<npub or gateway origin>"]` and an `a` tag to the shop's listing (kind 30402,
    replaceable), whose `listing/2` item is the authoritative price and names the key route;
  - `["preview", "<S_0 ... S_k hex>"]` when the creator gives `free_segments` away (a trailer:
    the opening plays with no payment);
  - `t` = `lightning-stream`, `paid-media`.
- **Not published: the plaintext hash (`ox`).** It sits in the sealed metadata record, for the
  buyer. Published, it would let anyone check that a leaked copy is exactly this item (it helps the
  leaker's audience more than the creator), would link the item to plain copies of the same file
  anywhere, and gives the buyer nothing that the per-chunk tags do not. NIP-94 makes `ox` a
  server-transform hash, not a promise, so leaving it out breaks nothing.

## 3. Selling the key

The shop answers `POST /keys/<sha256>` with `{"from": j0, "to": j1, "to_key": "<buyer key>"}` on
its gateway, a paid route like any other. The body of the answer is the requested `S_j` (or `K`),
wrapped with NIP-44 v2 to `to_key`. The signed receipt's `bodyHash` covers that body, so the buyer
holds the shop's signature over exactly the key bytes it delivered: if they do not open the
chunks, the receipt plus the public ciphertext prove it.

| Model | What one payment unlocks | Seeking and partial watch | Shop online at play time | Leak | Wallets |
|---|---|---|---|---|---|
| A. Pay once, whole `K` | everything, forever | free after purchase | no (once bought) | one 32-byte key frees the film | any (one BOLT 11) |
| B. Per-segment keys as paid | the segments paid for | pays only what is watched; seeking buys the segment landed on | yes, every ~25 s of new video | a leaker must post every `S_j` (a list of a few hundred keys), no harder in practice, but a buyer who watched half can leak only half | ticket wallets natively; others per segment (6) |
| C. Per-buyer, time-limited wrap | as A or B | as A or B | as A or B | the same: a key cannot expire once known | as A or B |

C is not a third model but how A and B deliver: every key is wrapped to the buyer. "Time-limited"
can only mean the shop stops re-delivering; a key once unwrapped is a key forever. Wrap to a
**per-session key** the player makes (not the buyer's main `npub`), which costs nothing and keeps
purchases unlinked to an identity (8).

**Recommended default: B, per-segment keys over stream tickets.** It matches what Lightning Stream
already is (pay as it arrives, stop when it stops, within the owner's spending rules), seeking
works, an abandoned film is not paid in full, and a scam seller selling bad keys for someone
else's ciphertext takes one segment's price before the tag check stops the player. The price
rule is a new terms field, `keyMsat` per segment, beside `requestMsat` (TICKETS.md section 1); the
meter counts segments, not bytes, since the bytes come from mirrors.

**Option: A, buy the whole film**, priced below the sum of the segments. For downloads, offline
play, gifting, and mainstream Nostr wallets that make one payment and not a stream of them. The
answer is `K`; the buyer derives every `S_j` itself.

## 4. What it can and cannot protect

There is no DRM, and this design does not pretend to have any. A paying fan can always re-share the
decrypted file, a screen recording, `K`, or the list of `S_j`. Once a key is posted beside its
hash, the ciphertext on every mirror is as good as plain.

What it does protect:

- **Casual free-riding.** The file on a mirror is useless without paying. Most people pay rather
  than look for a leak, the same bet every paid stream makes.
- **Hosting cost and resilience.** The creator pays for one copy; mirrors carry the bytes, and a
  shop that goes offline loses sales, not the film (with A, past buyers keep watching).
- **Platform lock-in.** The film is a hash, the price a signed event, the key a Lightning
  payment. No platform can delist it from mirrors it does not run, nor take a cut.
- **Integrity.** Every chunk is authenticated; a mirror cannot alter a frame.

How creators should think about it: price for the honest majority, release previews freely, and
treat a leak as marketing they did not choose. If a key leaks, the only remedy is to re-encrypt
(new `K`, new hash) and publish a new event; old mirrors keep the old ciphertext and the leaked key
still opens it. Tracing who leaked needs different ciphertext per buyer, which defeats mirroring;
a later option is two variants of a few segments (A/B), so that the set of variant keys a buyer
gets identifies a leaked key list (not a leaked file), at the cost of doubling those segments.

## 5. The player

**Lightning Stream wallet, player link.** `/r/<token>` (FILES.md) becomes a local decrypting
server: VLC, mpv or a TV asks it for plaintext ranges; the app fetches ciphertext ranges from the
shop or any mirror (free, CORS `*`), buys `S_j` through the connector and signer under the owner's
policy, checks tags, and answers plaintext. It buys one or two segments ahead of the read position
so no frame waits on Lightning, and keeps bought keys (sealed at rest, per file) so replay and
seeking back cost nothing. Downloads work the same way into a plain file.

**Web app (visit path).** A Service Worker serves a virtual URL (`/pb/<sha256>`) to a plain
`<video>`. It maps each `Range` request to chunks, fetches the ciphertext from a mirror, decrypts
with WebCrypto AES-GCM, and asks the page for keys, which the page buys through the connector as
a visit does today: a limit in sats, credit kept ahead, stop on demand (SELLER-APPS.md). The keys
live in the worker's memory for the session.

**Other Nostr clients.** A client that reads the 1063 event and the `ls-pb/1` spec can do the same
with model A (one BOLT 11, one key) or B through NWC (6). A client that knows none of this sees an
`application/octet-stream` blob with a thumbnail, a price and a shop link: the fallback is "open in
Lightning Stream".

## 6. Payments and interop

- **Ticket wallets (XBT, bit 512).** The key route is a gateway route; tickets, receipts and the
  meter apply unchanged. This is the default and needs no answer to the open question.
- **Mainstream Nostr wallets (BTC, plain BOLT 11).** This is NWC-BLOSSOM.md's open question 1 again,
  but cheaper to answer for keys than for bytes: a key sale is one small invoice per segment or per
  film, not a stream of slices, so a shop could take BTC through a modest receive path (its own BTC
  node, or an LNURL/NWC receive wallet it trusts) without changing the ticket rail. If the owner
  says no, model B stays for Lightning Stream wallets only, and outsiders can only buy through the
  web app.
- **Pay-to-unwrap (option, BTC or XBT).** The shop sends `E = S_j ⊕ HKDF(r)` and a BOLT 11 whose
  payment hash is `SHA-256(r)`; paying reveals `r` to the buyer's wallet, which hands it to the
  player (WebLN and NWC `pay_invoice` both return the preimage). Delivery is then atomic with
  payment and needs no receipt round trip. `E` travels only to the buyer, because routing nodes
  learn `r` when the payment settles. The buyer cannot check `E` before paying, but a bad one costs
  one segment and fails the tag check.
- **BUD-07.** It fits the key route, not the blob: `GET /keys/<sha256>?seg=j` answers `402` with
  `X-Lightning`, and the retry with the preimage gets the wrapped key. The blob itself stays free
  on every mirror, which is the point.
- **NWC.** The box as an NWC wallet service is a buyer-side helper (a TV app paying from the box's
  budget), not a sales channel: it refuses `make_invoice`. As an NWC client paying the buyer's
  outside wallet (NWC-BLOSSOM.md 2b), segments of ~25 s suit the 0.3 to 2 s relay round trip far
  better than per-byte slices: buy two segments ahead and nothing stalls. It is still BTC, so it
  waits on the same open question.
- **Zaps (NIP-57)**, considered and not recommended: the zap receipt is made by the creator's LNURL
  provider, a third party the shop would trust to say who paid, and delivery would be a DM after
  the fact.

## 7. The creator's flow and the Sell page

A new offer kind, **Paid media**, beside Files:

1. Pick a file from the Files folder. The page checks the container (MP4 faststart or fragmented
   for the browser; others play in the wallet's player link only, and the page says so).
2. Set the price: per minute (converted to `keyMsat` per segment from the duration) and for the
   whole film; the number of free preview segments.
3. Choose a thumbnail (an image the owner adds; frame extraction comes later).
4. **Encrypt.** The app makes `K`, writes the `ls-pb/1` blob to the app-owned blob store
   (NWC-BLOSSOM.md 3b), hashes it, and keeps `K` in the secrets directory like the signer's keys,
   with a backup reminder: losing `K` loses the product, and leaking the box leaks every `K` (not
   money).
5. **Mirrors.** A list of Blossom servers (defaults chosen by the owner; none preset): the app
   uploads with BUD-06 preflight and BUD-02 signed by the shop key, or asks them to pull from the
   box with BUD-04. Each success becomes a `fallback`.
6. **Publish.** The kind 1063 event and the `listing/2` item (hash, size, price, key route), signed
   by the shop key.

The item's page shows sales by segment and by whole film, and a **Re-encrypt** action for a leak
(new `K`, new hash, new event; the old event is deleted with NIP-09, which mirrors may ignore).

## 8. Risks

- **Key-leak economics.** One buyer can free a film for everyone; per-segment sale does not
  prevent this, it only stops a partial payment from unlocking the whole. Pricing, previews and
  re-encryption are the tools; tracing is a later, costly option (4).
- **Mirror liability.** Mirrors hold only ciphertext and a hash: they cannot see the content, and
  the creator, not the mirror, sells it. Two caveats: the 1063 event publicly describes what the
  ciphertext is, with a plain thumbnail that must follow the mirror's rules; and once a key is
  posted, the mirror is hosting the content in effect. The box itself sells keys, so the creator
  carries the liability for what it sells.
- **Metadata privacy.** The shop sees which segments a session buys and when: who watched what,
  how far, and where they skipped. Wrapping to a per-session key and paying by ticket keep the
  buyer's identity out of it; direct links or Tor hide the address. Mirrors see an address
  fetching a public hash. Buying a few segments ahead in batches blurs the timeline a little.
- **Key-route spam.** An unpaid key request costs the shop one `402`; the gateway's existing caps
  (unpaid invoices per address, `prepaid_first`) apply.
- **Fake sellers.** Anyone can publish a 1063 event for someone else's hash and sell garbage keys.
  Clients trust only the shop named by the event's signer (and the listing it signs); the per-chunk
  tag check bounds the loss to one segment.
- **Mirror spam and cost.** Mirrors are the creator's choice and pay terms; the box's own blob
  store stays owner-only.
- **Crypto mistakes.** Nonce reuse would be fatal: `K` is never reused across encryptions, and the
  encryptor refuses to write into an existing blob. Test vectors and an outside review come before
  any release.

## 9. Plan

| Phase | Piece | Effort |
|---|---|---|
| 1 | `ls-pb/1` spec with test vectors; encryptor and decryptor in Rust (wallet UI), round trip and tamper tests | M |
| 1 | Sell page **Paid media**: encrypt into the app blob store, `K` in secrets, served by hash (built route) | M |
| 2 | Key route on the gateway: `keyMsat` terms, NIP-44 wrapped answer, receipt over it | M |
| 2 | Wallet: player link and download as a decrypting proxy, segment prefetch, key cache | M |
| 2 | Kind 1063 per item and the `listing/2` fields (with NWC-BLOSSOM.md phase 2/3) | S |
| 3 | Web app Service Worker player (WebCrypto), via the visit's limit | M |
| 3 | Mirror upload (BUD-02/06) and pull (BUD-04) to owner-chosen servers | M |
| 3 | Whole-film purchase (model A) | S |
| 4 | BTC BOLT 11 sale of keys (pay-to-unwrap, BUD-07 on the key route), if the owner says yes | L |
| 4 | NWC client paying keys from the buyer's outside wallet | M (after the BTC decision) |
| 5 | Leak tracing by A/B segment variants | L |

## 10. Open questions for the owner

1. **BTC for keys.** Accept plain BTC Lightning for key sales (a small receive path, per segment or
   per film), even if Blossom bytes and tickets stay XBT-only?
2. **Segments by bytes or by time.** 16 MiB byte segments are simple and codec-blind, but a minute
   costs more at 4K than at 480p. Is that acceptable, or price per minute and size segments by the
   container's index?
3. **Plaintext hash.** Agree to keep `ox` sealed, not published?
4. **Who holds `K`.** Only the box (so sales stop when it is offline), or may a creator hand keys to
   an always-on seller they trust?
5. **Free preview** by default, and how many segments?
6. **Containers.** MP4 only for the browser player, or add an optional remux step (ffmpeg) on the
   Sell page?
7. **Default mirrors.** Ship none, or a short list the owner vets?
8. **Listing.** Paid media as a `listing/2` item, or its own offer kind in the listing?
