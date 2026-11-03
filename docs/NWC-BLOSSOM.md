# Nostr Wallet Connect and Blossom: design

Status: design (Phase 1). One piece is built, behind a flag that is off by default: a Files
service's folder answers a file by its SHA-256 (Blossom BUD-01), sold by the existing route and
meter ([Built so far](#built-so-far-phase-1)). Nothing else here exists yet.

Specs relied on (read 2026-11-03):

- NIP-47 core: <https://github.com/nostr-protocol/nips/blob/master/47.md>. The core is now
  `pay_invoice`, `make_invoice`, `lookup_invoice`, `get_balance`, `get_info`, the info event
  (kind 13194, `encryption` and `extensions` tags), requests 23194 and answers 23195. Everything else
  moved to numbered extensions in <https://github.com/nostr-wallet-connect/nwc>.
- NWC extensions used here: NWC-02 notifications (kind 23197, `payment_received`, `payment_sent`),
  NWC-04 keysend, NWC-05 transaction history (`list_transactions`), NWC-08 client-made connections
  (`nostr+walletauth://`, with `max_amount`, `renewal_period`, `request_methods`, `expires_at`,
  `isolated`), NWC-09 payment lookup, NWC-12 BOLT 12 offers, NWC-13 connection budgets (`get_budget`).
  `multi_pay_invoice` is no longer in the core.
- Blossom BUDs: <https://github.com/hzrd149/blossom/tree/master/buds>. BUD-01 (`GET`/`HEAD
  /<sha256>[.ext]`, `Access-Control-Allow-Origin: *`, ranges, `X-Reason` on errors; authorization
  for `GET` is now BUD-11's), BUD-02 (`PUT /upload`, `GET /list/<pubkey>`, `DELETE /<sha256>`, the
  blob descriptor, kind 24242 authorization), BUD-04 (`PUT /mirror` with a URL), BUD-06 (`HEAD
  /upload` with `X-SHA-256`, `X-Content-Length`, `X-Content-Type`), BUD-07 (`402` with one
  `X-<method>` header per way to pay: `X-Lightning` a BOLT 11 invoice, `X-Cashu` a NUT-24 request;
  the retry carries the preimage or a `cashuB` token in the same header; applies to `GET /<sha256>`
  and `PUT /upload`, and `HEAD` only says that payment is needed), BUD-08 (a `nip94` field of NIP-94
  tags in the blob descriptor).

## 1. What exists today

**NWC: the box is a wallet service, not a client.** `crates/xbt-nwc` (`docs/NWC.md`) answers NIP-47
requests (NIP-44 v2 only) for apps the owner connects on the wallet UI's **Connected apps** page
(`crates/xbt-wallet-ui/src/nwc_pages.rs`). It answers `pay_invoice`, `get_balance`, `get_info`,
`lookup_invoice` and `list_transactions`. It refuses `make_invoice` (the signer has no receive path),
keysend, `multi_pay_*`, BOLT 12 through `pay_invoice`, NIP-04, and any invoice without feature bit
512. Nothing in the app is an NWC *client*: it never pays through somebody else's wallet.

**Spending rules: both layers already exist.** Each connection has a rolling 24-hour budget in sats,
an expiry, an allowed-method list and a request rate (60 a minute). A payment is booked against the
connection before the signer sees it, then sent as the signer's `ln_pay` with `max_sats` set to the
connection's remaining budget, so every rule of the owner's signed policy applies on top (daily and
weekly budgets, per-transaction and per-counterparty caps, allowlist, velocity, the human threshold
with the owner's ed25519 approval, the rail's exposure cap). A payment above the human threshold
waits on the Approvals page. Revocation is immediate. So the third PoC suggestion ("make the NWC
service enforce per-connection budgets") is already done.

**What is missing on the NWC side:**

- It does not ship. `xbt-nwc` is built (it shares the wallet MCP's image) but neither the Umbrel nor
  the StartOS package runs it, nor sets `XBT_UI_NWC_SOCK`, so the page says it is not enabled. It has
  been tested in-process only: never against a public relay, a real NWC app, or a Lightning node.
- The budget is a rolling 24 hours only. NWC-08/13 speak of `max_amount` per `renewal_period`
  (`never`, `daily`, `weekly`, `monthly`, `yearly`), in msat.
- No `get_budget` (NWC-13), no notifications (NWC-02), no `extensions` tag, no NWC-08 flow (an app
  asks for a connection with the budget it wants; the owner approves).
- Relays that ask for NIP-42 authentication are not served.

**Nostr elsewhere.** Shops publish their listing as kind 30402 with `t=lightning-stream`
(`crates/xbt-gateway/src/nostr.rs`, `docs/NOSTR.md`); stream relays announce themselves as kind
30078 (`crates/xbt-nostr`); paid announcements under their own topic are on the 0.3.0 branch
`feat/030-paid-relays`.

**Files today.** The Sell page's **Files** offer shares a folder. The wallet UI serves it on a
private address (`crates/xbt-wallet-ui/src/files.rs`) that only the gateway reaches, with the files
key the gateway's route adds. The gateway's `/files/` route (`strip_prefix`) sells it per byte with
the ticket meter; ranges are served, so a player that seeks pays for what it reads. The listing
(`listing/1`, kind `files`) names each file by title and URL. A buyer downloads through the
connector or opens a player link (`/r/<token>`) the wallet app makes. Nothing names a file by its
content: a listing item has `title`, `url`, `year` and `credit`, and the parser refuses any other key.

## 2. NWC

### 2a. Other apps paying through the box (wallet service)

The service exists; what it needs is to ship and to speak today's NWC.

- **Ship it, off by default.** Add the `xbt-nwc` process to the Umbrel and StartOS packages, on a
  toggle on the Connected apps page; no connection exists until the owner makes one.
- **Budgets per renewal period.** Change the connection's `budget_sats_per_day` into
  `{max_msat, renewal: never|daily|weekly|monthly|yearly}`, keeping today's rolling day as the
  default for old state files. Fixed periods renew at the period boundary, which is what NWC-13's
  `renews_at` expects. Add `get_budget` and advertise `extensions: 05 09 13` (and `02` once
  notifications exist).
- **How it maps onto the spending rules.** The two layers stay separate and only ever narrow:

  | NWC (per connection) | Lightning Stream (signed policy, per wallet) | Result |
  |---|---|---|
  | `max_amount` per `renewal_period` | daily and weekly budgets | each payment must fit both; `get_budget` reports the connection's, `get_balance` the smaller of the two and the channels |
  | `request_methods` | none | the connection's method list |
  | `expires_at` | none | the connection's expiry |
  | (none) | per-transaction, per-counterparty, allowlist, velocity | the signer refuses; the app gets `RESTRICTED` or `QUOTA_EXCEEDED` |
  | (none) | human threshold | `QUOTA_EXCEEDED` with a message, then paid on retry after approval (as today) |

  The owner's policy can also say *how much of it* NWC as a whole may use: one new policy field,
  `nwc_share` (a cap over all connections together), signed like the rest, so an owner can hand out
  many connections without the sum of their budgets mattering.
- **NWC-08 (client-made connections).** An app sends the owner a `nostr+walletauth://` link with the
  budget and methods it wants; the wallet UI shows it as a request (name, methods, budget, expiry)
  that the owner approves with the same login and CSRF as today. The spec's rule fits ours: grant
  every required method and the exact budget, or decline; never silently weaken. Owner approval is
  required for every new connection; there is no auto-approve.
- **Agents.** An MCP agent key and an NWC connection are the same idea: a key with a budget under the
  owner's policy. The design keeps them as one table in the UI ("Connected apps and agents") so an
  owner sees every spender and its remaining budget in one place, and gives each MCP agent key an
  NWC-style `{max_msat, renewal}` budget as well (today agents have only the policy).
- **Notifications (NWC-02), later.** `payment_sent` is easy (the service sees the result).
  `payment_received` needs the receive path the signer does not have yet.
- **Receiving (`make_invoice`).** Stays refused until the signer has an invoice-only macaroon and a
  method that makes and books invoices. Selling over NWC (a shop taking payments through an NWC
  wallet) depends on it.

### 2b. Lightning Stream paying through the buyer's own NWC wallet (client)

For a buyer with no node: the connector would hold a connection string to the buyer's wallet
(Alby Hub, a phone wallet, Primal, a custodial wallet) and send `pay_invoice` for each slice of a
stream.

- **Custody.** The box holds no money and no wallet key, but it holds a *spending secret*: whoever
  reads the connection string spends up to its budget. It is kept like the signer's keys (secrets
  dir, 0600, never logged, shown once), and the design asks the buyer to give it a budget at the
  wallet (NWC-08 `max_amount`), so the wallet enforces a cap the box cannot raise. Whether the money
  behind it is custodial is the buyer's wallet's business; the app says so in plain words.
- **What the signer's policy can and cannot do.** The signer still checks each payment against the
  buyer's policy before it is sent (the NWC client becomes one more rail beside `ln_pay`), but it
  cannot see the external wallet's balance or channels, and cannot stop the wallet from paying a
  different amount. Preimages prove each payment.
- **Streaming cost.** Stream tickets pay in small slices; each is one NWC round trip over a relay
  (typically 0.3 to 2 s) and some wallets rate-limit. Hold invoices (NWC-03) are optional and rare,
  so the held-ticket flow does not carry over. The fit is: pay per larger part (say 4 MiB or one
  minute), with the meter's grace sized to the round trip, and accept a coarser stop.
- **Bit 512.** The ticket rail pays XBT Lightning invoices (feature bit 512). An outside NWC wallet
  pays Bitcoin Lightning. So the client only makes sense for a seller who also accepts plain Bitcoin
  Lightning, which Lightning Stream does not do today. This is the main blocker, and an owner
  question (below).

## 3. Blossom

### 3a. Sellers: Files offers as Blossom blobs

- **Address by content.** Each listed file gets its SHA-256. The listing names it, so a buyer can
  check what arrives and a seller cannot swap the content behind a URL. Because `parse_item` refuses
  unknown keys, an item with a new `sha256` key would make every older wallet refuse the whole
  listing. So: add `sha256` (and `size`, `type`) as an *optional item key in a `listing/2`*, or as a
  per-service `blobs` map beside `items`, which older parsers also refuse. Either way it is a new
  listing version, read by new wallets and published alongside `listing/1` until old ones are gone.
- **NIP-94 metadata (BUD-08).** For each file the shop can publish one kind 1063 event (`url`, `m`,
  `x` = sha256, `size`, `alt`, and a `t=lightning-stream` tag) signed by the shop's Nostr key, so
  any Nostr client that understands file metadata finds it, with the shop's Blossom URL. These are
  public announcements: the key-keeping rule for test boxes applies.
- **Two ways to sell a blob.**
  1. **Stream tickets (built):** `/files/<sha256>.<ext>` through the gateway, priced by the route's
     per-byte meter, as by name. A Lightning Stream wallet already knows how to pay this. A plain
     Blossom client does not: it gets Lightning Stream's own `402`, not BUD-07's.
  2. **BUD-07 per blob:** the gateway answers a Blossom client's `GET /<sha256>` with `402` and an
     `X-Lightning` BOLT 11 invoice for the whole blob (size times the route's byte price, rounded
     up), and serves the blob when the retry carries the preimage in `X-Lightning`. One payment per
     blob, no meter, no seeking. This is the only way to sell to the existing Blossom ecosystem, and
     it needs (a) a receive path (an invoice per request: the gateway's node already makes ticket
     invoices, so it can reuse that), and (b) a Bitcoin-Lightning invoice if the buyer's wallet is
     not an XBT one (the same bit-512 question). Cashu (`X-Cashu`) is out of scope: Lightning Stream
     has no mint.
  "Per byte" in BUD-07 terms is just the invoice amount computed from the size; true pay-as-you-go
  is the ticket meter, which only Lightning Stream wallets speak.

### 3b. The box as a Blossom server

- **GET/HEAD by hash (built, flag off).** Served from the Files folder through the gateway route, on
  the shop's web address or its iroh link, with CORS `*` and ranges.
- **Mirroring (BUD-04)** lets the owner pull a blob from another Blossom server into the shop
  (`PUT /mirror` with a URL): the box downloads it, checks the hash, stores it. This is owner-only
  (signed kind 24242 with the shop owner's key, or the wallet UI's login), never open to the public:
  an open mirror is free hosting for anyone.
- **Upload (BUD-02, BUD-06) for the owner.** Same rule: the owner's key only, via the UI. The Files
  folder on Umbrel and StartOS is read-only to the app; uploads go to a separate app-owned blob store
  (`<data dir>/blobs/<sha256>`), which the files server serves beside the shared folder.
- **`GET /list/<pubkey>`** is a listing of the owner's blobs; it can stay off (the signed listing is
  the catalog).

### 3c. Buyers: fetch by hash from anywhere

- The wallet gets a `blossom_get(sha256, servers[])`: try the seller's own URL first, then any
  Blossom server the listing or the buyer names; hash the bytes as they arrive; keep them only if
  the SHA-256 matches; stop and refuse otherwise. Paid servers are paid through the connector (ticket
  meter) or, for BUD-07, by paying the `X-Lightning` invoice under the buyer's policy (one payment,
  amount checked against the listing's price ceiling before paying).
- **Integrity of streamed and ranged reads.** A whole-file hash cannot be checked until the end, so
  a player link (`/r/<token>`) streaming a film by hash cannot refuse a bad byte mid-stream. The
  wallet can check the whole file for downloads; for playback it is checked after the fact (and the
  seller's server, built here, refuses to send a whole file that no longer matches). Chunk hashes
  (a Merkle tree or BLAKE3 outboard) would fix this but are not in Blossom.
- **MCP.** A `blossom_get` tool for agents with the same budget model as 2a: an agent key spends only
  its own `{max_msat, renewal}` under the owner's policy.

### 3d. Paid Blossom hosting (a shop sells storage)

A shop sells space per GB-month to other Nostr users, who upload with their own key (BUD-02, kind
24242). Payment: BUD-07 on `PUT /upload` (an invoice for size times months), or a prepaid credit per
pubkey, like the paid relays' credit API on `feat/030-paid-relays` (bytes per key, a balance, expiry).
The latter reuses that branch's metering and credit code and fits better: a buyer tops up once and
uploads many times. Storage is a quota per key, expiry deletes, and the shop's listing names the
price as a new kind (`storage`). This is the largest piece and carries the hosting risks below.

## 4. Fit with the rest

| Piece | How it fits |
|---|---|
| Listings (kind 30402, `listing/1`) | a `listing/2` adds `sha256`, `size`, `type` per item; kind 1063 events per file, both signed by the shop key |
| Player links `/r/<token>` | unchanged; they can point at `/files/<sha256>.ext` once the listing names hashes |
| MCP tools | `blossom_get`; per-agent-key `{max_msat, renewal}` budgets, shown with NWC connections |
| Paid relays (0.3.0) | the credit-per-key model and metering are the template for paid hosting; a Blossom server can be announced the way relays are (kind 30078 under its own topic) |
| Signer | NWC client as a new rail (if ever); a receive path for `make_invoice` and BUD-07 |

## 5. Risks and abuse

- **NWC connection secret leaks.** Whoever has the string spends up to its budget. Mitigations in
  place: a budget and expiry per connection, the owner's policy on top, the human threshold,
  immediate revocation, the secret shown once and never kept. To add: a default expiry (30 days) and
  a default budget, a "last used" and a per-connection payment list on the page (data exists), an
  alert (Nostr DM or the UI) on a payment from a connection idle for a long time, and `nwc_share` so
  many connections cannot add up past one cap.
- **External NWC wallet (client).** The box then holds a spending secret for the buyer's wallet;
  the wallet-side `max_amount` is the real cap. A compromised box spends up to it.
- **Hosting liability.** Serving the owner's own folder is the owner's content, as today. Mirroring
  and paid uploads make the box host other people's files, under the owner's name and IP: copyright
  notices, illegal content, and the owner's legal exposure. Mitigations: off by default, owner-only
  mirror and upload until paid hosting is a deliberate choice; a delete-by-hash and a deny list of
  hashes (shared lists exist in the Blossom ecosystem); a clear warning on the page; size and type
  limits (BUD-06 lets the server refuse before upload).
- **Spam uploads.** Never open uploads for free: every upload is signed (kind 24242) and paid or
  within a prepaid quota; per-key size and count limits; BUD-06 preflight refuses early.
- **Hashing cost.** Hashing a large folder is disk-heavy. The built piece hashes on one thread, at
  most every 30 s on a miss, only changed files (by size and mtime), and never in a request.
- **Content swap after hashing.** A file changed in place keeping its size and mtime: the built
  server re-hashes whole-file answers as it sends them and cuts the body short on a mismatch; ranged
  reads are not checked, which is why buyers check too (3c).
- **Linkability.** Content hashes are global: anyone can see which shops serve the same file.

## 6. Phased plan

| Phase | Piece | Effort |
|---|---|---|
| 1 (done here) | BUD-01 GET/HEAD by hash on the Files folder, flag off, tests | S |
| 2 | Ship `xbt-nwc` in Umbrel and StartOS behind the page's toggle; run it against a public relay and one real NWC app | M |
| 2 | Budgets per renewal period, `get_budget` (NWC-13), `extensions` tag | S |
| 2 | `listing/2` with `sha256`, `size`, `type` per item; Sell page computes them with the index built here | M |
| 2 | Wallet: verify by hash on download; show hashes on a Files page | S |
| 3 | NWC-08 client-made connections with owner approval | M |
| 3 | Per-agent-key `{max_msat, renewal}` budgets in MCP; one table for apps and agents; `nwc_share` in the policy | M |
| 3 | Kind 1063 (NIP-94) per file, signed by the shop key | S |
| 3 | `blossom_get` in the wallet and MCP, any server, hash-checked | M |
| 4 | Receive path in the signer: `make_invoice`, NWC-02 notifications | L |
| 4 | BUD-07 `X-Lightning` per blob at the gateway (needs the receive path) | M |
| 4 | Owner-only upload and mirror (BUD-02, -04, -06) into an app-owned blob store | M |
| 5 | Paid Blossom hosting per GB-month, on the paid relays' credit model | L |
| 5 | NWC client: pay through the buyer's external wallet | L (blocked on bit 512) |

## 7. Open questions for the owner

1. **Plain Bitcoin Lightning.** BUD-07 buyers and external NWC wallets pay Bitcoin Lightning
   invoices, not XBT (bit 512). Should a shop accept plain Lightning for Blossom downloads, or is
   Blossom only for Lightning Stream wallets (ticket meter)?
2. **Ship NWC now?** It has only run in-process. Is a relay and real-app trial (Phase 2) wanted
   before 0.3.0, and which public relays may a shop's NWC use by default?
3. **Listing version.** Is a `listing/2` acceptable, or should hashes go only in kind 1063 events so
   the signed listing stays at `listing/1`?
4. **Hosting other people's files.** Is mirroring and paid hosting something Lightning Stream should
   offer at all, given the legal exposure for box owners? If yes, default deny lists?
5. **Agents and NWC as one.** Merge MCP agent keys and NWC connections into one list with one budget
   model?
6. **Budget default.** What default budget and expiry should a new NWC connection have?
7. **Flag name and placement.** Keep `XBT_UI_FILES_BLOSSOM` as an env variable, or move it to the
   Sell page's Files offer as a per-shop switch?

## Built so far (Phase 1)

`XBT_UI_FILES_BLOSSOM=1` (unset by default) makes the Files folder's server also answer
`GET`/`HEAD /<sha256>[.ext]` (`crates/xbt-wallet-ui/src/blossom.rs`, used from
`crates/xbt-wallet-ui/src/files.rs`). Through the gateway that is `/files/<sha256>.mkv`, on the same
route, key and per-byte price as by name; nothing about the gateway changes.

- A name is tried first, as before; a path of 64 hex digits with at most one extension is then looked
  up by hash. The content type is the file's own, not the URL's extension (BUD-01).
- Hashes come from an index of the listed files only (no hidden names, no links out of the folder),
  checked against size and mtime at every lookup, built on its own thread at start and again (at most
  every 30 s) on a miss. A request never waits for hashing.
- Answers by hash carry `Access-Control-Allow-Origin: *`; a hash it does not have is a `404` with an
  `X-Reason`. Ranges are served as by name.
- A whole-file `GET` by hash is hashed again as it is sent; if the bytes are not the hash's, the last
  part is held back so the body ends short (the client sees a cut answer), and the hash is forgotten.
- Not done: `OPTIONS` preflight (the gateway route answers `GET` and `HEAD` only), BUD-07, the listing
  naming hashes, the wallet checking them.
