# Limits

What this software does not do, or does only up to a point. Read this before you rely on any part
of it.

Status: test networks only. An external review in October 2026 found critical and high-severity
issues. Six rounds of fixes followed, and four audits of those fixes by the project itself. Nobody
outside the project has reviewed the fixes. The history, with counts, is in the review summary; the
reasoning behind each rule is in the engineering notes (`docs/ENGINEERING.md` in the published
tree).

Direction, decided on 2026-10-11: Lightning Stream is being rebuilt on Lightning. It adds stream
tickets to ordinary XBT Lightning channels (the wallet's ticket book and the seller's gateway are
built and have run on regtest; the binding of the wallet to paid HTTP requests is not). The hub was retired on that
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

### Stream tickets (the design's measurements)

The sentences of this section are about tickets as such, whoever builds on them. A ticket is a small Lightning payment locked along a
route to a hash whose secret only the buyer knows (a hold invoice on the seller's node); the
buyer releases it by putting the secret in a paid request. Each sentence below comes from the
design's lab measurements: three Lightning Fork nodes on regtest, buyer and seller one routing
node apart, default node settings. The wallet's ticket book and the seller's gateway have their own sections below.
A sentence marked *(with Core Lightning)* comes from a later lab run with three nodes of the XBT
Core Lightning fork (v26.06.9-blake2b.7, the released binaries) beside three Lightning Fork
nodes, two of the Core Lightning nodes started with the values that binary has by default on
mainnet; its driver is not in this tree. `docs/TICKETS.md`, section 11, has the table.

- Money moves a ticket at a time (1,000 sat by default; a ticket that is held is at least 546
  sat by the design's rule, and a node carries nothing below 1 sat). Pieces inside a ticket are
  metered, and the unused part of the ticket in use is trusted to the seller.
- A held ticket takes one HTLC slot of every channel on its route, and a channel's slots are
  shared by everyone who uses it. A channel carries 483 each way between Lightning Fork nodes
  and 30 where either end is a Core Lightning node at its default. *(with Core Lightning)* Of 40
  tickets offered to a Core Lightning seller on one channel 30 locked and 10 failed, and an
  ordinary payment over that channel then failed too; two buyers through one Core Lightning hop
  held 20 and 10 between them.
- At a full channel a Lightning Fork buyer is told `INSUFFICIENT_BALANCE`, not that the slots
  are gone, and a full remote hop answers as a hop short of balance does. A buyer cannot know a
  remote channel's slot count before it fails against it.
- The design's defaults are therefore 2 tickets a session and at most half of a channel's slots
  in held tickets (15 of 30). One buyer holds tickets with 7 sellers at 2 each, or 15 at 1 each,
  from one 30-slot channel. The earlier figure of 200 sellers from one channel (400 tickets) was
  measured on 483-slot channels and holds only where every channel on the way has 483.
- A ticket below a channel's dust limit has no output in that side's transaction: 354 sat on a
  Lightning Fork node, 546 sat on a Core Lightning node. *(with Core Lightning)* With tickets of
  400, 600 and 1,000 sat held, a Core Lightning node's force close had outputs for 600 and 1,000
  only. Such a ticket cannot be claimed on chain and goes to the miners if that channel is
  force-closed while it is held. On a channel without anchors the limit also rises with the fee
  rate (computed, not run: the forks open anchor channels by default).
- A node caps the dust it carries per channel: Core Lightning at 50,000 sat, Lightning Fork at
  500,000 sat with the channel's fee. *(with Core Lightning)* On a Core Lightning channel opened
  with 483 slots, 100 tickets of 500 sat locked and the next 30 failed; the buyer's node then
  found no route to that seller for a 1,000-sat ticket either. Lightning Fork's cap was not
  reached with 483 tickets of 300 sat.
- Above the dust limit is not the same as worth claiming: a seller's claim of 3 tickets on
  chain cost 900 to 1,700 sat at 1 sat/vB, so at higher fee rates a single 1,000-sat ticket
  costs more to claim than it is worth.
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
- *(with Core Lightning)* A Core Lightning node needs nothing special as a buyer's node or as a
  hop (the buyer was the node's own `pay`; the wallet has no Core Lightning rail). As a seller it
  has no hold-invoice call. A ticket was held through its `htlc_accepted` hook by a lab plugin
  only: of the two published hold plugins, one makes invoices without feature bit 512, which a
  Lightning Fork buyer refuses, and the other keeps the secret on the seller's node. Locking and
  settling took the same time as with a Lightning Fork seller.
- *(with Core Lightning)* Nothing on a Core Lightning node cancels a held ticket before it
  expires. With a seller that neither settled nor cancelled, the buyer's own node force-closed
  its channel to the seller at the tickets' expiry.
- What XBT's mainnet nodes are set to (slots, channel types, fee rates) was not measured.
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
- The win that pays itself is not this project's idea: a win that enforces itself over
  Lightning was set out and built first by Gerhart, Taylor and Thyagarajan ("Probabilistic
  Atomic Swaps for Bitcoin and Friends", arXiv:2605.04975, May 2026), with a formal treatment.
  The construction here differs from theirs, and its parts (oblivious transfer and its
  extension, Gilboa's multiplication, a Groth16 proof) are other people's too;
  `docs/REFERENCES.md` lists them (44, 46 to 59).
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
  a ticket above: on a 30-slot channel a buyer holds such tickets with 15 sellers within the
  design's half rule. A locked ticket below a channel's dust limit (354 sat on a Lightning Fork
  node, 546 sat on a Core Lightning node) cannot be claimed on chain, so a win is lost if the
  seller's own channel peer stays away until the ticket expires (reasoned, not run). By the
  design's rule the locked ticket, and so the win, is at least 546 sat, which makes a small
  seller's income more uneven than the 64-sat examples above.
- Pay after a win holds no slot, but each win is a payment in flight for about a quarter of a
  second and wins of 16 or 64 sat are below the dust limits while in flight. Of 200 payments of
  64 sat sent 64 at a time over a 30-slot channel to a Core Lightning node, 139 failed; sent 8 at
  a time all 200 succeeded, 28 a second. A wallet has to pace them.
- The fairness of the roll treats SHA-256 as a random function. Nobody outside the project has
  reviewed that argument either.
- A win is not proof to a third party, in either form.
- Sellers cannot pool wins as miners pool blocks: a piece served is not proof of work, so a
  seller and a buyer it controls can invent pieces at no cost. *(simulated)* The protocol has no
  pool.
- One hop was measured, on one host, with requests as calls inside one program. Separate seller
  machines, two or more hops, real network latency, requests over HTTP, mainnet fees and a
  buyer that does not pay, on real nodes, were not.

### Seller gateway (`xbt-gateway`)

Regtest only. The gateway has run against Lightning Fork nodes on one host
(`scripts/gateway_regtest.sh`, with a test buyer; `scripts/ticket_e2e_regtest.sh`, paid by the
wallet) and against a stand-in node in its tests.

- It needs two macaroons of the seller's node: one with `invoices:read` and `invoices:write`,
  and one with `info:read`, because the first cannot read the block height. Each is refused on
  mainnet when it grants anything else; the check reads the macaroon and does not verify it, and
  on any other chain a wider one is taken with a warning.
- No secret is taken without a block height from the node that is at most 10 seconds old; such
  a request is answered 503 and the secret is good again later.
- The 24-block margin is checked against the height the node last reported, which is asked for
  twice a second: a block that arrived since is not counted.
- The gateway's defaults were sized for channels of 483 slots and it does not look at its
  node's channels. On a channel with a Core Lightning node at the other end, which carries 30,
  four buyers at the default of 8 tickets fill it, the 31st ticket's payment fails at the buyer
  with `INSUFFICIENT_BALANCE`, and nobody can pay the seller over that channel until tickets are
  released or cancelled (measured on the lab with a Core Lightning seller, not with the
  gateway). A runner whose node has such a channel sets `tickets.max_tickets` to 2 and
  `caps.max_held_tickets` to 15 for each 30-slot inbound channel. The gateway accepts a ticket
  size below the dust limits (from 1 sat), does not answer `slots_short`, and does not offer
  tickets settled on arrival (`docs/TICKETS.md`, section 11).
- With the default caps buyers can hold 240 tickets, 240,000 sat of the seller's inbound capacity
  and 240 of one channel's 483 HTLC slots, at no fee: for 1 minute by a session that never
  releases a secret, for 5 minutes after a session's last paid request, and again as soon as
  they are cancelled. One address can hold 4 sessions, 32,000 sat. Measured on the lab: a buyer
  that locked 8 tickets and released none held 8,000 sat for 16 s with the limit set to 15 s.
- The cap per address counts the socket's address: behind a reverse proxy every buyer has the
  proxy's, so the runner sets `sessions_per_address` to 0 and caps in the proxy.
- Whoever can reach the gateway from enough addresses can take every session place with locks
  it never pays, at no cost, a minute at a time: new buyers are refused meanwhile
  (`too_many_sessions`). Sessions that already hold tickets keep them and their balance, and can
  refill up to their own 8; a session with nothing locked at that moment waits for a place.
- Every lock makes invoices on the node, up to 240 at once with the default caps and each given
  up within 75 seconds if unpaid; the node keeps cancelled invoices in its database until it is
  set to collect them (`gc-canceled-invoices-on-the-fly`).
- One thread and one connection to the node per unreleased ticket: 240 with the default caps.
- A buyer's balance, the part of its released tickets it has not used, is trusted to the seller:
  it is kept for 24 hours after the session's last paid request and then forgotten.
- The gateway takes 64 connections in all and 48 from one address, one request per connection,
  and an answer that is being sent holds its connection: 64 answers at once. A client that takes
  no byte for 30 seconds is cut, and no answer stays open for more than 6 hours.
- A body priced per byte is charged when the gateway hands the bytes to the operating system,
  not when the buyer has them: a buyer that disappears in the middle paid for what was in the
  socket's buffers, at most its balance. A buyer that releases one ticket at a time is never more
  than one ticket ahead.
- A body priced per second is charged for every second it is open, also while the service says
  nothing (at most 10 seconds, then the answer ends) or the buyer reads slowly.
- A request is charged when the service answers with a status below 400. An error from the
  service is passed on (64 KiB of it) and not charged, so a buyer whose balance covers one
  request can make the service work on any number of requests that end in errors.
- The service is reached over plain HTTP only, must start its answer within 10 seconds, and is
  never followed through a redirect; a service that itself answers 402 is reported as 502.
- A request body is read whole before it is passed on (64 MiB at most, per route 0 unless the
  runner sets it); request bodies with chunked encoding are refused.
- Routes are matched on the decoded path, byte for byte. A service that reads two spellings as
  one resource (another letter case, a `;` parameter, a trailing dot, its own rewriting) can be
  reached under a spelling the runner did not price if another route covers that spelling; a path
  with no route is not passed on at all. A query string is passed on unchanged and takes no part
  in the match.
- A target with a backslash, a byte outside visible ASCII, an escaped `/`, `\`, `.` or `%`, or
  an empty, `.` or `..` segment is refused with 400, so a service whose paths need one of these
  cannot be sold.
- Of a buyer's headers only `Accept`, `Accept-Language`, `Content-Type`, `Range`, `If-Range`,
  `If-None-Match` and `If-Modified-Since` reach the service unless the runner lists more; a
  buyer's `Authorization` or cookie does not. The gateway adds `Via: 1.1 xbt-gateway`, asks for
  an unencoded body, and sets `Host` to the service's own address.
- Session counters are written to the journal with every answer and put on disk twice a second.
  A gateway that is killed loses at most half a second of the charges of answers still being
  sent. A power cut loses half a second of all counters: what was served in that time can be
  served again, and a buyer's next request is told which `seq` is expected.
- A state directory restored from a backup has the backup's counters: what a session spent since
  is not counted, sessions made since are unknown, and their locked tickets stay locked until the
  node cancels them 18 blocks before their expiry. What a session released is read from the node
  again and is right. A lost state directory loses every session, key and balance.
- The last receipt of an answer that was sent as it arrived is kept in memory, the last 8 per
  session, and is gone after a restart; the buyer then has the receipt of the answer's head and
  its own count of the bytes.
- A receipt covers the request, the answer's status and its body, not its headers. Nothing ties
  the receipt key to the node's id but the origin that served both.
- On a route marked `after-verify` the seller serves up to one ticket's worth before the secret
  arrives, and loses it when the buyer never sends the secret: once per session, 30,000 sat with
  the default caps and tickets. The gateway does not know what "checks out" means for the content.
- The list at `/services` is not signed. The operator's `health` view is given to loopback
  callers, which behind a reverse proxy on the same host is every caller; it shows counts and no
  secret.
- The gateway speaks plain HTTP: a public seller needs a TLS reverse proxy in front, and
  `public_url` set to the origin buyers use, or every payment fails its request binding.
- Not run: more than one routing hop, real network latency, mainnet, IPv6, a seller with several
  channels, and the Core Lightning fork.

### Stream tickets: the wallet's ticket book

The buyer's side, in the signer (`ticket.rs`, `ticket_rail.rs`): secrets, tickets locked through
the owner's node, and the booking. It is reached through six socket methods, and by the wallet's
own payer under `xbt402_pay` (the next section). Verify-before-release for checkable content,
prepaid tickets (`settle: on-arrival`), lottery tickets and admission by content hash are not
built. Run on regtest only (`scripts/ticket_book_regtest.sh`).

- The ticket book's defaults were sized for channels of 483 slots: a pool of 8 tickets with each
  of up to 8 sellers and 2 beyond that, 64 held tickets in all, and a smallest ticket of 64 sat
  where it chooses the size. It does not read its channels' slot counts or dust limits before a
  lock, and a lock that fails for lack of a slot is recorded on the ticket and nothing more. On
  a channel that carries 30 (any channel with a Core Lightning node at its default) the 31st
  held ticket fails, and a 64-sat ticket has no output in any channel's transaction. These are
  the owner's settings, with the earlier numbers as their defaults: `tickets.pool` (8) and
  `tickets.pool_many` (2) for the pool, `tickets.max_locked_tickets` (64) for all sessions, and
  `tickets.floor_ticket_sats` (64) for the smallest ticket the wallet chooses. An owner whose
  channels carry 30 sets the pool to 2, `max_locked_tickets` to 15 and the floor to 546
  (`docs/TICKETS.md`, section 11); nothing in the wallet does it for them.

- Tickets are off until the owner's policy turns them on (`tickets.enabled`) and names at least
  one task with a budget (`tickets.tasks`); with tickets on and no task, every session is refused.
- A secret that has left the signer is spent, also when the reply that carried it was lost on the
  way to the caller: it is not returned a second time. That costs at most one ticket, which is
  booked until the seller cancels it or it expires.
- Every start of the signer treats the tickets it finds locked as released: they are booked
  against the budgets at their worst case and never released, and every session is stopped. A
  restart therefore costs the use of the tickets that were locked (their sats stay locked until
  the seller cancels them or they expire, about 25 blocks for a 40-block ticket) and holds their
  worst case against the budgets for as long. The signer does this because it cannot tell a
  restart from a restore of an older copy of its files, after which a ticket its book shows locked
  may have been released. *(test)*
- After a restore the wallet finds the tickets its book lacks by a tag on each ticket payment in
  its node's payment list. It finds only what the node still lists: payments the owner deleted
  from the node, and a node whose own database was restored or lost, hide tickets from it, and
  what it cannot see it does not count. A ticket the node no longer lists after having shown it
  locked stays booked.
- The wallet locks and releases nothing between a start and the first complete read of its node's
  payment list (`ticket_sync`); with the node down that is until the node is back.
- For a moment after a ticket settles, `ticket_status` can show the node and the book as not
  agreeing: the node reports the payment settled before it has taken the HTLC off its channel.
- The seller's node receives a 32-byte tag with every ticket (a random nonce and a MAC). It tells
  the seller nothing about the wallet beyond what the payment hash already does.
- The ticket rail trusts its own Lightning node as the Lightning rail does: a ticket the node
  reports failed is no longer counted as spent, and a fee the node reports is the fee booked. A
  settle is believed only with the preimage of the ticket's hash, and is never booked below the
  ticket's size.
- A ticket that settles although this wallet's book never released its secret halts all Lightning
  payments until the human resumes them; it is booked, not prevented.
- The exposure caps (`max_locked_sats` and the per-seller and per-task ones) count a ticket at its
  face value. The routing fee of a locked ticket is locked on top of it, up to the rail's fee limit
  (10 sat and 0.5%: 15 sat on a 1,000-sat ticket).
- Nothing is locked that the budgets could not also release at that moment, but locked tickets
  are not booked: another payment of the wallet can use the budget meanwhile, and the tickets are
  then not released and stay locked until the seller cancels them or they expire.
- A release is one payment under every rule of the wallet. With the shipped `velocity_max` of 8
  an hour and no `tickets.velocity` in the policy, a wallet releases at most 8 tickets an hour,
  across all rails: an answer priced as it goes stops at the eighth ticket (8,000 sat with the
  default ticket). An owner who streams sets `tickets.velocity` to `"session"`: a session is then
  one payment for `velocity_max`, counted from its first release for as long as one of its
  releases is inside the window, and its releases are bounded by the budgets, the caps on locked
  funds and `max_sends_per_hour` (1,200). Under `"session"` the ninth session of an hour is
  refused when it opens. Releases to one seller inside `split_window_s` add up against
  `max_per_tx_sats` and the human threshold as any split payment does, under either setting.
- A ticket released before this version has no session in its ledger row and counts as one
  payment under either setting.
- No release can wait for a human: a session whose one ticket, with its fee limit, would reach
  `human_threshold_sats` is refused when it opens.
- The owner names a ticket seller by its node id: `ln:<node id>` on the allowlist, or an
  allowlisted origin whose `counterparties` entry gives the node id (`ln_node`). An origin alone
  names nobody. Under `xbt402_pay` the origin is the one the signer itself fetched the terms
  from; on the socket's `ticket_open` it is the caller's word.
- A seller the owner has not named is paid only under a task that admits any seller, and by
  default at most 2 tickets locked and 4 tickets' worth paid in the task's window. The cap is per
  node id, and node ids are free to make: what bounds a seller that takes a ticket and serves
  nothing, under as many node ids as it likes, is the task's budget.
- A task's budget is read over a rolling window of at most a week (a day by default), from the
  wallet's own ledger. Tickets found on the node after a restore count against the daily and
  weekly budgets and their seller's cap, and against no task's budget.
- One session per seller at a time; a session with no lock or release for 10 minutes is stopped,
  and no session survives a start of the signer.
- On the six socket methods the signer does not talk to sellers. It says how many hashes a pool
  wants (below half of the pool: back to the pool's size) and the caller fetches the invoices; a
  refill happens when the caller asks, and stopping a session only names the tickets to cancel.
  Under `xbt402_pay` the signer does all of this itself (the next section).
- A hash whose invoice the book refused (a cap was reached) keeps its place in the pool for 2
  minutes: the pool asks for no other hash in its place until then.
- A release does not ask the node whether the ticket is still locked. It relies on the last
  reconcile (every watcher tick, 10 s by default) and on the ticket's expiry height: a ticket the
  seller cancelled in between is released, booked, refused by the seller and un-booked at the
  next tick.
- A ticket with 25 blocks or fewer before its expiry at the seller is not released; it stays
  locked until the seller's node cancels it.
- One HTLC per ticket (`max_parts` 1): a ticket that would need two routes is not locked.
- A hash the seller sends no invoice for within 2 minutes is dropped; at most 64 hashes are
  offered or locked in one call; 5,000 payments of the node's list are read in one reconcile.
- A plain Lightning payment (`ln_pay`) holds the wallet's spend lock while the node routes it, up
  to its timeout: a ticket release waits for it. A ticket lock round holds no lock while the node
  routes.
- Tickets and sessions that ended more than a day ago leave the book. The wallet's backup holds
  the book and the sealed ticket seed while each is under the backup's 8 MiB limit a file.

### Stream tickets: the wallet pays a gateway (`xbt402_pay`)

The signer's own payer (`ticket_http.rs`, `ticket_pay.rs`): the rail choice, the session with a
seller over HTTP, the receipts. Run on regtest only: against the gateway in process
(`crates/xbt-signer/tests/ticket_pay.rs`) and against Lightning Fork nodes through one hop with the
release binaries (`scripts/ticket_e2e_regtest.sh`).

- The ticket rail exists only where the owner's policy turns tickets on, and an agent reaches it
  only where the operator starts the MCP server with `XBT_MCP_TICKETS=1`. With tickets off,
  `xbt402_pay` is the channel path as it was. With tickets on, a seller that answers without a
  402 is answered from the wallet's one unpaid request (`rule: free`, `rail: none`), and a seller
  paid by channel is asked twice without payment before it is paid.
- `max_sats` bounds what a call uses, by the wallet's own count of the bytes and seconds it
  received. It does not bound what the call books: a ticket is released whole, so a call that
  uses 3 sat can book one ticket and its fee limit (1,015 sat with the defaults). The rest is a
  balance with that seller, trusted to it.
- An answer the wallet stops at `max_sats` can be charged for what the seller had already sent:
  up to the balance, so less than one ticket more than the call's limit.
- The balance is given up whenever a session ends: `ticket_stop`, 120 s without a paid request, a
  seller fault, changed terms, a restart of the signer. Each costs less than one ticket.
- A seller can take one ticket and serve nothing; the wallet then stops the session. Node ids and
  origins are free to make, so under a task that pays any seller what bounds this is the task's
  budget and its cap per unnamed seller.
- The wallet sends a secret only in `release`. A seller that takes a secret only with the request
  it pays for cannot be paid; the gateway takes both.
- An entry that releases `after-verify` or settles `on-arrival` is not paid: the wallet passes it
  over and tries the next rail.
- No ticket is released until the seller's signed `status` shows it locked. A seller that never
  shows it is not paid (`ticket_not_ready` after 3 s), and its tickets stay locked until it
  cancels them or they expire.
- One paid request per seller at a time: a long answer delays every other call to that seller,
  and one session per seller node, so two origins of one node cannot be paid at once.
- The ticket rail needs https, or http to the wallet's own machine. The wallet does not pin a
  seller's certificate: it trusts the system's roots, as its HTTP client does.
- An answer priced as it goes is cut by the wallet after 50 s (`tickets.max_answer_s`), because
  whoever calls the signer's socket waits 60 s by default. An owner who streams longer raises
  both; if the caller's wait ends first, the caller sees an error while the signer goes on paying
  for the answer until `max_sats` or `max_answer_s`.
- An answer priced by the second is paid up to a fifth of a second early, and the wallet counts
  its seconds from before it sent the request, so it can pay for one second the seller did not
  charge.
- The last receipt of a long answer is asked for during 2 s. A seller that has not finished with
  the answer by then, or a gateway that restarted, leaves the wallet with its own count and the
  receipt of the answer's head. `bytes` and `complete` beside that receipt are not signed.
- An answer nobody signed ends the session unless it is a 5xx: whoever can answer in a seller's
  place can make the wallet give up a balance, once per session, and release nothing.
- An unsigned `bad_seq` is believed, twice per request.
- A wallet that starts again asks each seller on record to cancel, once. If the seller is
  unreachable then, those tickets stay locked, and booked against the budgets at their worst
  case, until the seller cancels them itself or they expire.
- The seller's session id and key are in the ticket book in the clear, as the book is. Whoever
  reads the book can spend a session's balance at the seller and cancel its tickets; no secret
  of a ticket can be had from it.
- A body longer than the preview is stored only when `B2_BODY_DIR` is set; otherwise the wallet
  hands on its first 12,000 bytes, its length and its hash. Stored files are never removed by
  the wallet.
- The single Lightning payment of a 402 (`scheme: "exact"`) pays first: an invoice that is paid
  and then not honoured is lost, once. No seller in this tree offers the entry and it was not run
  on the lab.
- The MCP's in-process payer (`XBT_MCP_PAYER=local`) pays channels only.
- Not run: more than one hop, real network latency, TLS to a seller, mainnet, the Core Lightning
  fork, more than one seller at once through this path, and a seller other than `xbt-gateway`.

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
- One payment at a time on the channel: the wallet holds one lock for a whole `xbt402_pay` on
  that rail, the seller's answers included, so a slow seller delays every other payment, approval
  and refund for as long as it answers. On the ticket rail the lock is held for each lock round's
  bookkeeping and each release, not while a seller answers.
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
- the seller gateway (`xbt-gateway`), the ticket wire module (`xbt402::ticket`) and the streamed
  answers of the shared HTTP server (`xbt_svc::http`): written after the last audit;
- the ticket book (`ticket.rs`, `ticket_rail.rs`, the held send and the payment list of the
  Lightning backend): written after the last audit, tested by the project only;
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
