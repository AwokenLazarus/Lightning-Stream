# Limits

What this software does not do, or does only up to a point. Read this before you rely on any part
of it.

Status: test networks only. An external review in October 2026 found critical and high-severity
issues. Six rounds of fixes followed, and four audits of those fixes by the project itself. Nobody
outside the project has reviewed the fixes. The history, with counts, is in the review summary; the
reasoning behind each rule is in the engineering notes (`docs/ENGINEERING.md` in the published
tree).

Direction, decided on 2026-10-11: Lightning Stream is being rebuilt on Lightning. It adds stream
tickets to ordinary XBT Lightning channels (in design, not built). The hub was retired on that
day and its code removed. The on-chain one-way channel is **frozen**: kept in the tree and
tested, off the main path, with no new work. Sections about it are marked "frozen" below.

This file has three parts:

- **Stated limits**: behaviour we know about and have decided to state instead of change. One
  sentence each, grouped by area. A limit that an audit test pins is marked *(test)*: that test is
  named `limit_...`, passes while the limit holds and fails when someone lifts it.
- **Open items**: defects we have not fixed. Each has a test that still asserts the right
  behaviour and is marked `open:` in the code.
- **Not reviewed by anyone**: parts of the tree no review or audit has covered.

"The provider" and "the seller" are servers; "the payer", "the client" and "the wallet"
are the paying side. XBT is Bitcoin on BLAKE2b proof of work; "the SHA-256 chain" is the other
chain. Numbers are the shipped defaults unless a sentence says otherwise.

## Stated limits

### Retired with the hub

The hub, the hub beside a Lightning node and the routed client were retired on 2026-10-11 and
their code removed; the 59 limits stated for them here went with them. Lightning's own routing
does what the hub did. The code and those limits are in the git history, last at commit
`a548fb0`. What the removal leaves behind:

- A wallet policy that still has a `routing` section loads; the signer ignores the section and
  says so in a warning.
- A wallet channel record that an earlier version left with a pending routed lock keeps it: the
  signer signs no plain state below the locked amount, and has no method left to complete or give
  up the lock. The channel is refunded at its expiry.
- A provider ledger that still holds a channel a hub funded treats it as an ordinary channel: it
  is closed at the close margin with the best signed state, and a routed lock recorded on it is
  not waited for.
- The signer socket no longer answers `xbt402_sign_state_adaptor`, `xbt402_resolve_lock`,
  `xbt402_void_lock`, `xbt402_adopt_lock`, `xbt402_recover_lock` or `routing_status`; the Python
  wallet reference still has them.

### Stream tickets (in design)

Nothing in this section is shipped code. A ticket is a small Lightning payment locked along a
route to a hash whose secret only the buyer knows (a hold invoice on the seller's node); the
buyer releases it by putting the secret in a paid request. Each sentence below comes from the
design's lab measurements: three Lightning Fork nodes on regtest, buyer and seller one routing
node apart, default node settings. None comes from a wallet or a seller built on tickets.

- Money moves a ticket at a time (1,000 sat by default, 1 sat at the least). Pieces inside a
  ticket are metered, and the unused part of the ticket in use is trusted to the seller.
- The buyer can lose one ticket: a secret is spent when it leaves the wallet, and a seller can
  take it and serve nothing.
- Unused tickets stay locked until the seller cancels them or they expire. Measured with 40-block
  tickets: 25 blocks with a seller that neither settles nor cancels, 51 blocks through one hop
  with a seller that went offline.
- The seller needs a Lightning node with inbound capacity, and must stay online while tickets are
  locked: a seller offline when locked tickets expire had its channel force-closed (measured), and
  a ticket not settled 18 blocks before its expiry is cancelled by the seller's own node.
- Tickets are held payments. A cancelled ticket pays routing nodes nothing for the capacity and
  the slot it held, which is the behaviour Lightning's jamming defences are designed against; so
  tickets have to stay few, small and short-lived.
- BOLT 11 hold invoices only. The Lightning Fork's BOLT 12 offers have no hold path.
- One hop was measured, on one host. Two or more hops, real network latency, mainnet routes and
  fees, a direct channel, and a force close with many tickets were not.
- The Core Lightning fork is untested, as a seller, a buyer or a hop. It has no hold-invoice call
  of its own.
- Every hop sees the same hash, so hops that collude can link a ticket along its route, and a
  ticket cannot be partly released.

### Lottery tickets (in design)

Nothing in this section is shipped code, and no script in this tree reproduces its numbers. A
lottery ticket pays for a piece worth less than a ticket by a fair roll: a piece wins a payment
of one fixed size (64 sat in the examples) with probability price ÷ that size, so the average
paid is the price. There are two forms. In **pay after a win** nothing is locked ahead and the
buyer pays an ordinary invoice for each win. In **the win that pays itself** the buyer locks one
ticket with the seller and each roll gives the seller a small chance of obtaining its secret.
Each sentence below comes from the design's measurements: Lightning Fork nodes on regtest (five
for pay after a win, three for the win that pays itself), one routing node between buyer and
seller, one host; up to 200 sellers were sessions spread over three seller nodes. A sentence
marked *(simulated)* involved no node.

- Income is uneven. A seller earning 4,096 sat in a day with 64-sat wins is paid 80% to 120% of
  it nine days in ten, and 96% to 104% over a month; a seller earning 1,000 sat a day, 58% to
  141% on a day and 92% to 108% over a month; a seller earning 100 sat a day gets no win on 21%
  of days. *(simulated)*
- A smaller win is steadier and costs more in fees: a routing node charged 1 sat for each win,
  which is 6.25% of a 16-sat win, 1.6% of 64, 0.4% of 250 and 0.1% of 1,000, per hop, at the
  forks' default policy.
- A buyer's cost is uneven. A download priced at 1,638 sat (16,384 pieces at 0.1 sat, 64-sat
  wins) costs 1,152 to 2,176 sat nine times in ten, and its owner must allow 2,795 sat, fees
  included, for it to stall on an unlucky run no more than once in a thousand. *(simulated)*
- In pay after a win the seller goes first by about one win's worth. A buyer that does not pay
  is served one win's worth on average before the seller sees an unpaid win and stops, and about
  three times that one time in twenty. *(simulated)* Where a seller earns less than one win from
  a buyer, a buyer that never pays gets everything free. Nothing in the design makes that buyer
  pay; it is a way for buyers who mean to pay to do so, not enforcement.
- A seller a buyer touches only briefly cannot be forced to be paid: the win that pays itself
  needs a ticket locked with that seller first, which is too much for a few pieces, so such
  sellers are paid after a win.
- The win that pays itself is not reviewed and not built. It rests on an argument of this
  project's own (that a cheating buyer fails the seller's check on at least half of its rolls;
  measured at 49.9% to 50.2% over 200,000 rolls) that no cryptographer has reviewed. It will not
  be built before such a review.
- On hash locks the win that pays itself also needs one proof per locked ticket that the hash
  and the rolls hide the same secret. The one measured (254 ms to make, 1.35 ms to check, 192
  bytes, one host) needs a setup that must not be trusted to one party; a proof without one was
  not measured, and nothing was measured on a small board. Point locks would remove the proof;
  neither XBT Lightning fork has them.
- The prototype of the win that pays itself uses the simple form of one building block (the
  extension of oblivious transfers), which is safe only against a seller that follows the
  protocol; a product needs the hardened form, which was not built or measured.
- The win that pays itself holds one ticket and one channel slot per seller, with every limit of
  a ticket above. A locked ticket below the channel's dust limit (354 sat on the lab) cannot be
  claimed on chain, so a win is lost if the seller's own channel peer stays away until the
  ticket expires (reasoned, not run).
- The fairness of the roll treats SHA-256 as a random function. Nobody outside the project has
  reviewed that argument either.
- A win is not proof to a third party, in either form.
- Sellers cannot pool wins as miners pool blocks: a piece served is not proof of work, so a
  seller and a buyer it controls can invent pieces at no cost. *(simulated)* The protocol has no
  pool.
- One hop was measured, on one host, with requests as calls inside one program. Separate seller
  machines, two or more hops, real network latency, requests over HTTP, mainnet fees and a
  buyer that does not pay, on real nodes, were not.

### Channel and transport (library client) (frozen)

The on-chain one-way channel. Frozen: these limits stand as written and get no new work.

- The open preflight is the seller's word: a seller that says yes and then refuses the funded open
  locks the buyer's capacity until the channel's expiry, at most 4,032 blocks, and the client can
  sign no close for such a channel.
- A funded channel the seller refuses to open blocks that seller until its record is removed, also
  after the refund; the MCP wallet has no tool for that. *(test)*
- A payer's book has one channel per seller origin. It reads as one origin every spelling that
  differs only in letter case, a default port or a user name. A URL whose host two URL parsers
  could read differently is refused before anything is paid or sent: a backslash, a host with
  percent-encoding or non-ASCII letters, the short, decimal and hexadecimal forms of an IP
  address. A trailing dot on a name is a separate origin, so a seller reached under both
  spellings can be funded once per spelling, up to the payer's budget. *(test)*
- With the shipped payers a payer has 1,007 blocks, about a week, to come back for a channel its
  signer funded and whose confirmation it did not wait for; a payer built on the library's default
  of 1,008 blocks has 144, about a day. After that the coins wait for the refund at the expiry, up
  to 1,009 blocks, and that seller cannot be paid through that signer meanwhile. *(test)*
- A payer that keeps no ledger (`xbt-signer-payer`) can take up a channel its signer funded only
  until it is attached; after that it must keep a ledger, or the owner closes the channel through
  the signer, which works only once a state has been signed on it.
- One signer serves one payer per seller: a second payer started while the first one's funding is
  unconfirmed takes that channel and the first is refused from then on; two that both hold it
  break each other's calls. No coin can be taken. *(test)*
- Payer and signer are upgraded together: a payer of this version asks the signer what it funded
  on every open, and an older signer answers `unknown method`, so the open fails with nothing
  funded. A third-party signer that funds channels must answer that question too.
- A payer that takes up a channel its signer funded does not apply its own budget, capacity or
  expiry settings to it: the signer's policy approved that funding. *(test)*
- With a wallet whose funding call can fail after it sent and that cannot list its sends, every
  retry pays the channel again, the client holds a refund for one output only, and its budget
  counts one; neither wallet shipped here is such a wallet. *(test)*
- A paid request that gets no receipt is paid for if the provider later says it charged it: the
  provider is believed for one call's price for every such request, on an unsigned message. So a
  provider that answers errors, anyone who can alter answers on the way, or a payer process that
  stopped after a request left, can make the payer pay for each such request; measured, 1,650 sat
  signed for 150 sat of service. A caller that retries on errors should set a daily budget.
  *(test)*
- A refusal is not signed: whoever can answer in a provider's place can hide a served answer
  behind a forged refusal. The payer absorbs one such charge in a channel's life; after the
  second, every call on that channel is refused until its owner closes it and removes its record.
  *(test)*
- The library client does not watch the chain; after a rollover answered with an error the
  embedder must find the rollover and adopt it.
- Records of rollover attempts that were never adopted stay in the client's book and ledger until
  the embedder removes them; at 16 for one channel the client signs no further rollover of it.
- Earlier scripts of an open that was never funded are kept, 16 per seller; past that the oldest
  script's terms are forgotten and its key is kept.
- How long a channel lasts is at least the seller's own floor and at least 144 blocks (or the
  owner's wish if smaller), and at most 4,032 blocks unless the owner raises it; an offer outside
  that is refused before anything is funded.
- A program that uses these crates' HTTP client from another workspace does not compile until it
  adds the patched `ureq` to its own manifest, and `cargo deny` reports no advisory for the patched
  copy; advisories for `ureq` are looked up by hand.
- `LocalSigner` keeps its keys in memory: a process that restarts with one has lost them.
- A close is bumped by a child that spends only the provider's own output of that close, up to
  10,000 sat, so fees above about 37 sat/vB for the whole 144-block margin, or a provider output
  too small to pay, still let the buyer's refund win; no shipped binary has a setting for the bump
  ceiling.
- A receipt covers the request, the answer's status and its body, not its headers; a body sent
  with neither Content-Length nor chunking ends when the connection does, so only the receipt's
  body hash shows it was cut.
- A payment is bound to the method, scheme, host, port, target and body as the request states
  them, so a TLS proxy that does not set `X-Forwarded-Proto` makes every payment fail.
- A server takes 64 connections in all and 48 from one address; a public listener needs a reverse
  proxy with its own limits.
- The ledger lock is on the path as given; a symlink or hard link to the ledger file is a second,
  unlocked way in.

### Agent wallet (`xbt-signer`)

The sentences here about channels, rollovers, closes and refunds are about the frozen on-chain
channel; the rest (policy, approvals, keys, the socket) holds for every rail.

- Channel funding is not a budget item: up to the per-channel cap plus the close fee can sit in
  one channel per allowlisted seller, and on-chain fees are outside every budget.
- A seller's terms can lock a channel's coins for up to `max(channel_expiry_blocks, 4032)` blocks,
  whoever names it. The 144-block floor on a channel's life holds for channels the pay tool opens on a seller's offer; the socket's `open_channel`, `fund` and rollover
  refuse only an expiry inside the refund margin (6 blocks).
- After an answer is lost the wallet pays the next call with one new state on the seller's
  unsigned word that it holds the last one. A seller that serves nothing, or anyone who can answer
  in its place, can so be signed one call's price for every call the agent makes, inside the call's
  `max_sats` and the budgets; those calls report a charge of 0. A request lost before the seller
  saw it is paid for as well when the next call costs more. *(test)*
- On a postpay channel the seller is owed one call per lost answer until the close. (Buying a
  streamed result on such a channel is an open item, below.)
- After a close the wallet opens no new channel to that seller until the close is in a block; if
  the close is never mined, not until the old channel's expiry. "In a block" means one
  confirmation; a reorganisation that removes a close or a refund is not followed.
- If a rollover the wallet attached from the mempool is never mined, the channel it would have
  spent is no longer watched and no wallet method refunds it; its key is kept, and the owner must
  restore the record by hand. No new channel to that seller can be opened meanwhile. *(test)*
- A channel's rollovers may be signed into at most eight different next channels while none is
  attached; after that it must be closed.
- The next channel of a rollover the seller broadcast after refusing it is refunded by the watcher
  only while the rolled channel is still the wallet's record for that seller; if the rolled
  channel was marked closed and a new one funded first, the next channel's coins stay in its
  script past its expiry, with its key kept. *(test)*
- A human-signed operation runs once, as long as the file of used signatures is neither deleted
  nor restored from before the signature was used; a missing file is read as an empty one. A
  human-signed operation run while the host clock is far ahead fixes that time in the wallet:
  later signatures that expire before it are refused, policy changes included, until the owner
  resets the file, which also forgets every used signature. *(test)*
- Every socket-level finding needs a process that can open the signer socket; an agent held to the
  MCP tool list cannot reach those methods. A process on the socket can ask for payer keys without
  limit, and can ask which channel the signer funded for any seller.
- The one-time enrolment code protects the first approval key only when the socket and the
  signer's directory belong to different users, as in the container layout.
- A payment or funding whose fate the node did not report stays counted and is kept; if it can
  never confirm, its seller stays blocked until the node can name, in a block, another transaction
  that spent one of the funding's inputs within the last 4,032 blocks, and otherwise until an
  operator removes the record.
- A crash between holding an approval and paying costs the approval with nothing paid; the same
  holds for a human signature, which is used up when its operation starts.
- The backup export's signature does not name the passphrase the backup is sealed under; an
  expired approval can be dismissed without a signature; a key blob without a recorded cost opens
  at scrypt 2^15 and is re-sealed only when its file is next written.
- Key wiping covers long-lived copies in the Rust signer only.
- Stream chunks are paid without a signed receipt; each is bound by a Merkle proof or a hash lock.
  An answer of 400 or above is handed to the agent without a receipt.
- One payment at a time: the wallet holds one lock for a whole `xbt402_pay`, the seller's answers
  included, so a slow seller delays every other payment, approval and refund for as long as it
  answers.
- A watcher step that panics is reported and skipped, and the next tick tries again; in a
  `release-small` build a panic ends the signer process, and whatever supervises it restarts it.

### Pay with work

- The pay-with-work specification (XBT-053), its Python reference and its vectors are not
  published; the Rust crate is the reference, and the Python reference has none of the audit rules
  below.
- Credit is released only by sats that reach the provider's address in a coinbase under a
  statement that passes the audit, valued at the provider's own price from its own node; a
  Prime's signatures decide only whether it is distrusted.
- A Prime that gives no statement for a block is never failed for it, whatever the block paid; a
  Prime that never pays costs the provider the cap on unpaid credit, once: 900 calls at exact
  pricing, 1,000 under a fixed amount per call.
- Balances are kept in work units, so credit taken and held unspent buys more calls if the
  difficulty then falls, in proportion: twice the cap's calls after a halving, four times after
  two. *(test)*
- Credit that is unpaid when a provider is upgraded to this version is counted at the difficulty
  of the first start after the upgrade; if the difficulty rose while it was unpaid, part of the
  cap is served once more (half of it after a doubling). *(test)*
- What the caps count is rounded up for each grant, so credit granted in very small pieces can
  fill the cap early after the price moves. *(test)*
- Work a payer mines after the provider's caps are full is held and cannot be spent until the
  Prime pays; if the Prime never pays, the payer has lost it.
- Cover is shared across payers, oldest credit first: honest payers' work is paid for at about 11%
  more than their credit costs, and that surplus pays off older credit nobody mined, about one
  call for every nine honest calls. *(test)*
- The provider's library has no caps unless `WorkConfig::shipped` or a cap rule is set; the binary
  sets them.
- A block that pays the provider nothing and has no statement leaves no verdict, because the
  provider cannot tell the Prime's block from another pool's; the optional stop after N such
  blocks lifts only at a block that pays its share of a window holding all the unpaid credit.
- Every coinbase output to the provider's address counts as payment, so the address must be used
  by one provider, with one Prime, for nothing else.
- Fraud proofs convict only for a checker who already knows the Prime's terms; distrust of a Prime
  is permanent, and nothing in the software clears it. *(test)*
- `audit_chain` without a node never fails a Prime for a window start that goes backwards, and
  such a statement removes the earlier audit together with the carry the Prime signed for it;
  `xbt-work-provider` uses the form that asks its node. *(test)*
- The audit believes the provider's own node: a node that is behind makes the provider undo audits
  above its tip and do them again when it catches up, and payers can be refused at the caps in
  between; a block the node reports with impossible values is not audited, and no later block is,
  until the node answers correctly.
- A payout counts as paid at 6 confirmations although the coins are locked for the coinbase
  maturity, and a reorganisation deeper than 144 blocks is not undone.
- The provider carries the pool's luck: when the pool finds few blocks, credit waits at the caps.
- An invoice with no work on it ends at its expiry; work on an invoice of this provider is
  credited whenever its payer first presents it.
- The provider keeps a record for every invoice the Prime ever signed work for, for as long as it
  keeps its state: about 650 bytes each, and one audit entry per pool block with a statement.
  Nothing prunes them, and the whole state is written on every paid call and whenever a receipt
  changes it; an older receipt still on the relay can cause one write per invoice after each
  audited block. The provider never answers 429. *(test)*
- The provider's relay pull asks for every invoice with a record and the 64 newest every 3
  seconds; the relay as shipped answers one client 10 requests a second, so past about 30 invoices
  the same ones are not pulled, and their work is credited only when their payer calls. *(test)*
- An invoice identifier shows when the invoice expires; its 4-byte check only tells this
  provider's identifiers from others'.
- Losing the provider's state file loses every balance and every invoice not yet used; two
  providers started from copies of one state file both honour the same balances. *(test)*
- A state write whose directory sync fails is reported as failed although the new file is in
  place: the paid call answers an error and the debit is written again.
- A loop of the work provider that panics in every round is reported in its log and the service
  goes on answering, but that loop does nothing more: if it is the audit, no later block is
  audited and credit stops at the caps until an operator restarts it past that block. The health
  endpoint does not show it; a `release-small` build ends the process instead.
- The provider reads the block value and difficulty from its own node every few seconds and
  believes them. While the node cannot be read, calls stay priced at the last values it gave; the
  provider does not start without a first answer.
- The admin endpoints need a bearer token kept in a file in the data directory; the provider
  refuses a token file that group or others can read, but does not check who owns it or who can
  write the directory.
- A lost answer costs the payer that answer; the payer's check of what it has spent is
  bookkeeping, because the provider's payment response is unsigned.
- The payer fetches receipts only from its own relay or receipt URL or the provider's own origin.
- A work payer whose session file holds two sessions for one seller under different spellings of
  its address does not start until its owner removes one; neither is dropped.
- The pay-with-work rail binds a payment to no host; run it over TLS.

### Light client and consensus

- The light client believes a chain only once it reaches Knots' block 964264 and Knots' minimum
  chain work; above that block, a client all of whose servers lie can be shown a fake confirmation
  for the cost of one real-difficulty block each.
- Setting `B2_ELECTRUM_CHECKPOINT` at or above the pinned height replaces the pin and the minimum
  work with the operator's own block.
- A script with more than 10,000 history entries, or a transaction above 1,000,000 bytes, is not
  answered by the light backend, and anyone can push a script over that bound by paying dust to
  it; for a channel's funding script that also stops the light wallet's refund of that channel.
- If every Electrum server you configured hides a transaction, or one hides it while the others
  have not seen it yet, the light client reads it as absent; it never books a channel as closed
  on that, only on a proven spend, and coins it cannot see come back when a server shows them.
- A "not there" answer needs every configured server to answer, so one server that is down or
  silent makes those answers, and scans of your coins, fail until you remove it; what the wallet
  proves keeps working. The wallet never drops a server by itself.
- One slow server can hold a lookup for the call deadline (four request timeouts, one minute)
  plus a header sync before it and one inside it (up to a minute each).
- A server that sends a number no integer or float holds is hung up on for that line, so its
  other answers in that call are lost with it: a "not there" answer then fails as it does beside
  any server that did not answer.
- In a scan, a server that lists a coin and answers "busy" for its transaction fails the scan.
- The search for a spend does not wait for every server: when the honest server misses a scan's
  one history request, coins that only a lying server lists as unspent are listed, and the scan
  still says every server answered. Such a coin fails at broadcast. *(test)*
- A first scan of an address with N coins asks each server for N proofs, 16 at a time; a server
  that needs more than one timeout for 16 answers is dropped for that call and the other servers
  decide.
- A lookup made while a header sync is in flight and a block has just arrived can fail with "not
  known" for that block's transactions, for at most one sync round.
- A request given up at a call's deadline is forgotten once 16 newer ones are kept on the same
  connection; a late, large answer to a forgotten one closes that connection.
- `min-servers` counts servers the wallet is connected to, not servers that answered: a server
  that accepts the connection and answers nothing else counts.
- The light client recognises "no such transaction" from the server's own words (bitcoind's,
  electrs', ElectrumX's and Fulcrum's, tested against electrs and simulators); another wording
  counts as no answer.
- Nothing the light client proved is kept across a restart: every proof is asked for again.
- A light wallet's coin scan says whether every server answered, but the wallet does not read
  that: a coin only the missing server shows is counted at a later reconcile.
- On the light backend a funding that can never confirm holds its destination for good.
- The provider needs a full node: on the light backend "not shown" would read as
  "spent".
- A light hot wallet cannot spend coinbase coins. The light client supports mainnet and regtest
  only. A server that keeps refusing to give its tip is connected to again on every header sync,
  with no back-off.
- On the light backend the fee estimate shown in a quote is the first answering server's word,
  unverified; the wallet's own transactions use fixed fees. A wake-up for a watched script can be
  late by one polling interval (10 seconds).
- The annex and codeseparator sighash vectors were generated with Knots' Python and not executed
  against its C++; the retarget vectors are recorded from the project's own Python. Funding sent
  through the node wallet is replay-protected only if that node does not run `-walletoldsigs`.

### Lightning rail

- The rail's policy binds only what goes through the wallet: anyone holding a broader macaroon for
  the node bypasses it.
- The rail trusts its own Lightning node for everything but the proof of a settled payment: its
  fee figure, its "failed" and its "no such payment" are taken as given; a payment the node
  reports failed and later settled is not booked.
- The macaroon allowlist applies on mainnet only, at payment time, after the node has been shown
  the macaroon.
- A booking released as never sent that settles late is detected and halts the rail; it is not
  prevented.
- For a BOLT 12 payment the Lightning node, not the wallet, limits how long funds can be locked;
  the wallet watches for the node's default limit (2016 blocks) plus a day, and an owner who
  raised the node's limit must raise `ln.node_max_cltv_blocks` too.
- A channel's funding proof reads signature types from the owner's own node and does not verify
  signatures.
- A channel is used only if its funding descends, within 256 transactions searched breadth first,
  from a coin taken to exist on XBT alone: a coinbase mined after the split, or a coin spent from
  a legacy (P2PKH) address with an XBT signature. Channels funded from coins that only moved
  between segwit addresses since the split are refused and must be closed and reopened.
- The coinbase half of that rule is not guaranteed by XBT's consensus: a coinbase names its height
  and nothing else that tells the chains apart, so until the SHA-256 chain has passed that height
  a miner with a block on each chain can make the same coinbase exist on both. The wallet has no
  node of the SHA-256 chain to check this with.
- A BOLT 12 payment is refused while any open channel of the node fails the funding proof, because
  the node, not the wallet, chooses the channels it leaves through. Anyone who can open a channel
  to the node can cause that; the cure is the owner's (close it, or have the node refuse inbound
  channels). A channel that opens while a payment is in flight is not checked. BOLT 11 payments
  are confined to the proven channels and go on.
- Chain separation between XBT and SHA-256 chain Lightning rests on feature bit 512 and on the
  Lightning Fork's unified signatures; the funding proof is a second line behind them.

### Build

- Release builds check every integer addition, subtraction and multiplication in every crate; a
  missed overflow stops the request it is in with a `500`, and nothing of that request is kept.
- A panic in one watcher tick or loop round is caught and the next one runs, in the
  provider binaries, the signer and the work provider; what a panic that repeats every round does
  is in each area above.
- A binary built with the `release-small` profile aborts the whole process on any panic; the
  shipped images are not built with it, and it must not be used for a server.
- The wallet MCP over stdio ends on a panic in a quick tool and has to be started again by its
  client.
- A payer that sends a request `seq` of 2^64 - 1 has spent every later request on that channel; it
  can still close it.
- The images and size tables under `dist/` were built before overflow checks were turned on.

### Python references

The two Python references state the same rules where they have the code. What differs there, and
the limits of the Python agent wallet and its forward rail, are in `docs/LIMITS.md` of each
reference's own repository:
[Lightning-Stream-py-channel](https://github.com/AwokenLazarus/Lightning-Stream-py-channel) and
[Lightning-Stream-py-wallet](https://github.com/AwokenLazarus/Lightning-Stream-py-wallet).

## Open items

Not fixed. Each is marked in the code with the text in brackets, on a test that asserts the right
behaviour; searching the trees for `open: AGP-102` and `open: AGP-111` finds exactly these. The
`AGP-111` ones are checks of `scripts/failure_interop.sh`, which runs the release binaries: the
script prints them as `FAIL (open item)` with what it observed, and goes on.

The three `AGP-111` items are all on the frozen on-chain channel's pay rail. They stay listed
and get no fix unless the channel is kept.

- **A streamed result cannot be bought on a postpay channel that is one call behind**
  (`open: AGP-102 list 1 item 13`; Rust wallet, two tests; Python wallet, one). A stream's last
  state gets no receipt, so after the first stream on a channel, or after one lost answer, the
  wallet is one call behind for the life of that channel; every later stream ends at its first
  chunk, and the wallet has paid for the manifest and got no data. Nothing is signed past the
  call's `max_sats` or a budget. No seller in these trees sells streams. Do not rely on buying
  streams on a postpay channel.
- **Forward rail of the Python wallet (off by default): a lot recovered after its channel was
  replaced** (`open: AGP-102 list 1 item 5`; Python wallet, three tests). After such a recovery the
  next channel to that market signs states that are not booked and not checked against the
  policy, up to the recovered lot's total, and the daily and weekly budgets do not fill; and a
  recovery from a close that is then never mined ends that channel's refund watch. It needs the
  rail turned on, an allowed market and the agent's own calls. Do not turn the forward rail on.

- **On the signer's own pay rail, a call whose answer was lost is not paid at the close**
  (`open: AGP-111 item 1`; `scripts/failure_interop.sh`, checks A1.2, A3.2 and D2.4). The wallet
  signs each call's state before the call; when the answer is lost it sends that same state with
  the next call, the shipped provider serves that call on credit, and from then on the wallet is
  one call behind. Its cooperative close signs what it has signed so far, so the seller is short
  one call's price and its close report says `debt`: measured, 900 sat paid for 7 calls of 150 sat
  served, and the same after a signer killed with a signed request on the wire. Two answers lost
  in a row leave the seller one call short as well, not two. The payer never pays twice, and the
  library client (the wallet's `local` payer) pays every served call exactly once in the same
  runs. This is what "the seller is owed one call per lost answer until the close" above comes
  to: the close does not settle it. A seller should not extend credit it needs back.
- **A signer policy that leaves out `per_counterparty_cap_sats` cannot pay the shipped provider**
  (`open: AGP-111 item 2`; `scripts/failure_interop.sh`, check S1). The built-in cap is 30,000,000
  sat and the wallet funds a channel of that capacity; the provider's built-in maximum is
  10,000,000 sat, so the open is refused, before anything is funded. The example policy sets
  100,000 sat and is not affected. Set the cap in your policy.
- **With the wallet MCP's `local` payer, a seller's refusal text reaches the agent as the wallet's
  own `reason`** (`open: AGP-111 item 3`; `scripts/failure_interop.sh`, check E2.4). When a seller
  refuses an open (or any request the library client posts) with an error and a `detail`, the
  tool result is `{"verdict": "deny", "rule": <the seller's code, if it is a plain one>, "reason":
  <the seller's detail, verbatim>}`: text the seller chose, outside
  `untrusted_provider_response`, where an agent reads it as its wallet speaking. The signer's own
  rail (the default payer) reports its own words there and no seller text. Use the default payer
  where the agent must not be steered by a seller.

## Not reviewed by anyone

Neither the external review nor any of the project's four audits covered:

- the packaging and the container images: everything under `packaging/` (the StartOS and Umbrel
  packages), the image definitions and `dist/`;
- the wallet's web interface (`xbt-wallet-ui`);
- the anchor witness and the vault code;
- `xbt-svc` and `xbt-init`, and the scripts under `tools/`;
- any server built with the `release-small` profile, and any hostile input against a release
  build: the audits attacked debug builds, and release builds ran the ordinary paths only;
- the macaroon reader the Lightning rail uses (`xbt402::macaroon`): written after the last audit;
- the removal of the hub itself (2026-10-11): what was cut from the provider, the client library
  and the signer, and how records of the removed features are treated;
- anything on a real network: no mainnet node, no public Electrum server and no Lightning node
  outside a test rig was used, and every "blocks" figure was measured on regtest blocks mined at
  once.

The cross-implementation scripts run the ordinary path. `scripts/failure_interop.sh` runs these
failure paths through the release binaries on regtest, and no others have been run that way: an
answer lost on a direct channel (the signer's rail and the library client); a provider that stops
answering; one hostile Electrum server among two honest ones (silent,
hiding the wallet's transactions, sending malformed numbers); a kill and restart of the provider
and the signer in the middle of a payment; and a seller that refuses a funded open. Its
faults are injected on loopback by a proxy and by signals: a slow or lossy network, a full disk,
a clock that jumps and two faults at once were not tried.
