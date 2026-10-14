# Limits

What this software does not do, or does only up to a point. Read this before you rely on any part
of it.

Status: test networks only. An external review in October 2026 found critical and high-severity
issues. Six rounds of fixes followed, and four audits of those fixes by the project itself. Nobody
outside the project has reviewed the fixes. The history, with counts, is in the review summary; the
reasoning behind each rule is in the engineering notes (`docs/ENGINEERING.md` in the published
tree).

Direction, decided on 2026-10-11: Lightning Stream is built on Lightning. It adds stream tickets
to ordinary XBT Lightning channels (the wallet's ticket book, its payer and the seller's gateway
are built and have run on regtest). The hub was retired on that day and its code removed. The
on-chain one-way channel was frozen on that day and removed in October 2026; "channel" in this
file means a Lightning channel unless a sentence says otherwise.

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
`0911cc0`. What the removal leaves behind:

- A wallet policy that still has a `routing` section loads; the signer ignores the section and
  says so in a warning.
- The signer socket no longer answers `xbt402_sign_state_adaptor`, `xbt402_resolve_lock`,
  `xbt402_void_lock`, `xbt402_adopt_lock`, `xbt402_recover_lock` or `routing_status`; nor does
  the Python wallet reference, which had them removed after this one.

### Removed: the on-chain one-way channel

The on-chain one-way channel (the x402 `batch-settlement` scheme on XBT), its provider and
library client, the wallet's channel rail, the light client (`xbt-electrum`) and the fair exchange
built on channel states were removed in October 2026. The limits stated for them here (the
sections "Channel and transport", "Light client and consensus" and the channel sentences of
"Agent wallet") and the three open items on the channel's path went with them. The code and those
limits are in the git history, last at commit `1ad0c48`. What the removal leaves behind:

- A wallet that was upgraded with channels on record cannot close or refund them: this version
  has no method for either and no watcher that refunds at expiry. It never writes the channel book
  (`channels.json`) or its sealed keys (`channel_keys.json`), reads the book once at start, lists
  the records under `channels` and `balance`, and says in its log, in `health` and on the UI's
  Channels page how many are not settled. Settling them needs the version at `1ad0c48`, run on the
  same data directory; until then the coins of an open channel stay in its script.
- A wallet policy that still has `channel_expiry_blocks`, `refund_enabled`, `refund_margin_blocks`,
  `open_wait_s`, `open_retry_s`, `close_fee_max_sats`, `channel_rail` or a `pay_to` under
  `counterparties` loads; the signer ignores them, whatever they hold, and says so in a warning.
  Every other policy key means what it meant.
- The signer socket answers `deny/removed` to `fund`, `open_channel`, `sign_state`, the
  `xbt402_sign_*` methods, `xbt402_new_key`, `xbt402_attach`, `xbt402_funded`,
  `xbt402_request_auth`, `xbt402_mark_closed`, `close_channel`, `xbt402_refund`,
  `tx_confirmations` and the `forward_*` methods. The MCP server no longer lists `close_channel`,
  `xbt402_refund`, `forward_status` or `forward_recover`, and refuses to start with
  `XBT_MCP_PAYER=local`. The Python wallet reference still has all of these.
- An approval that a channel payment asked for before the removal pays nothing: approving it
  drops it and says why.
- The hot key funds nothing any more. It is kept so that coins on it can be seen and swept by the
  owner; `hot_balance_cap_sats` only marks the key as over its cap in the wallet's status.
- The wallet pays a seller over Lightning only. The Umbrel and StartOS packages and the container
  stack wire no Lightning node into the wallet, so a packaged wallet pays no seller, and their
  tests no longer contain a paid call.
- A seller that offers only the channel is answered `no_rail` by `xbt402_pay`, with the reason.
- Content paid for chunk by chunk against a Merkle root with a hash-locked last chunk
  (`xbt402-merkle-v1`) can no longer be bought. The ticket wire has its own form of it
  (`docs/TICKETS.md`, section 5, `after-verify`), which the wallet does not do yet.
- Another program that linked the channel's provider or client from the `xbt402` crate no longer
  builds against this tree; it has to pin `1ad0c48` or pay another way.

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
- The defaults are therefore 2 tickets a session and at most half of a channel's slots in held
  tickets (15 of 30), in the wallet and in the gateway. One buyer holds tickets with 7 sellers at
  2 each, or 15 at 1 each, from one 30-slot channel; with the wallet's own rule (2 each with up
  to 4 sellers of a task, 1 each beyond) it is 11. The earlier figure of 200 sellers from one
  channel (400 tickets) was measured on 483-slot channels and holds only where every channel on
  the way has 483.
- The half rule is a rule of this software, kept on the numbers each side can read of its own
  channels. Nothing makes another buyer, another seller or a routing node keep it, and a remote
  channel's slots cannot be read by anyone but its two ends.
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

### The lottery: pay after a win

A piece that costs less than a ticket is paid by a fair draw: it wins a payment of one fixed
size (64 sat as shipped) with probability price ÷ that size, so the average paid is the price.
Nothing is locked ahead; the buyer pays an ordinary invoice for each win. The gateway and the
wallet build it (`docs/TICKETS.md`, section 9). Regtest only: `scripts/lottery_regtest.sh` runs
the shipped binaries on Lightning Fork nodes whose channels carry 30 pending payments, one
routing node between buyer and seller, one host, loopback. Its 100 sellers are 100 gateways
beside one seller node. A sentence marked *(simulated)* comes from the design's simulation and
involved no node.

- **The fairness of the draw rests on an argument of this project's own that nobody else has
  reviewed.** It treats SHA-256 as a random function: the seller commits to a hash chain before
  the session, the buyer gives a random value after the piece, and a hash of both decides. The
  draw has tests that neither side can steer it by its choice of seed, of value or of piece, and
  a second implementation agrees with it on every draw the lab made; neither is a proof.
- The seller goes first, and nothing makes a buyer pay. A buyer that gives values and never pays
  a win is served up to its first win and the seller's grace, and is then refused until the
  seller's node shows the wins paid. Measured with a buyer that never pays: with pieces of a
  quarter of a sat it was served 1.4 wins' worth on average (ten sessions; 64 sat a win; 0.8 to
  1.4 on average in four runs, 3.3 at the most in one session).
  With pieces of a quarter of a win it was served 3.9 wins' worth (ten sessions; 3.9 to 4.9 on average in four runs): the
  gateway bears two unpaid wins and serves 8 pieces ahead of the buyer's values.
- Where a seller earns less than one win from a buyer, a buyer that never pays has had
  everything free. A download split over 40 sellers at a tenth of a sat a piece is 41 sat a
  seller, which is less than a 64-sat win. *(simulated)* The lottery is a way for buyers who
  mean to pay to do so cheaply. It is not enforcement.
- A buyer that sends no values, or that names every piece as void, is served the seller's
  window (8 pieces) in every session it is given, and no more: a void makes no room in the
  window. The gateway caps sessions (64 in all, 4 from one address), keeps a session that never
  gave a value, or that was closed while it owed, in its place for a minute, and offers the
  lottery only for a route whose dearest piece is a quarter of a win or less. So one address
  gets 32 pieces a minute at the most, which is 8 wins' worth at the dearest price the gateway
  draws for, and 16 addresses that hold all 64 places get 128 wins' worth a minute (8,192 sat
  with 64-sat wins). Nothing but the caps bounds that: it is the price of serving first.
  (Until 2026-10-14 a void made room in the window and a session took 16 of them, so a buyer
  that voided every piece was served 24 pieces a session; a closed session gave its place back
  at once, so the rate had no bound; and any piece below a whole win was drawn for.)
- The cap on sessions from one address counts the socket's address unless the runner names a
  reverse proxy and the header it sets (`http.forwarded_address`, off by default). Behind a
  proxy without it, every buyer has the proxy's address: the cap holds everyone together to 4
  sessions, or is set to 0 and holds nobody, and the bound of the item above is then the 64
  sessions in all. With it, the gateway believes that header from the named addresses only and
  takes the last entry of a list; it cannot check that the proxy overwrites what a client sent,
  or that nobody reaches the gateway past the proxy from a named address. Either mistake lets a
  buyer write its own address. The same address is what a ticket session's place is counted
  under.
- An honest buyer pays for the window too. Each piece of an answer that was cut, or that the
  wallet stopped reading, stays counted for the rest of the session: one to a few pieces for a
  cut, the window at the most. After 4 voids (`max_voids`, half the window) the gateway ends
  the session (`too_many_voids`) and the wallet opens another; the one it left keeps its place
  for a minute, so a buyer whose answers are cut more than four sessions' worth in a minute is
  refused (`too_many_sessions`) until a place comes back. An answer priced by the second can
  cost the buyer a void by itself: the seller may have begun one second more than the wallet
  counted. Not measured; `scripts/lottery_regtest.sh` has no check that cuts answers.
- Income is uneven. A seller earning 4,096 sat in a day with 64-sat wins is paid 80% to 120% of
  it nine days in ten, and 96% to 104% over a month; a seller earning 1,000 sat a day, 58% to
  141% on a day; a seller earning 100 sat a day gets no win on 21% of days. *(simulated)* A
  seller that earns less than one win from a buyer is usually paid nothing by it.
- A buyer's cost is uneven. Measured: a file priced at 381.5 sat, bought five times, cost
  520, 780, 390, 260 and 325 sat with routing fees. A download priced at 1,638 sat on 64-sat wins costs 1,152
  to 2,176 sat nine times in ten. *(simulated)* `max_sats` bounds what a call uses by the
  wallet's own count of the pieces, not what it pays: a call stops asking for pieces when its
  wins come to more than its luck cap (for 1,000 sat on 64-sat wins, 1,848 sat), and only the
  task's budget holds whatever the draws do.
- A task budget below one win and its fee pays nothing by draws at all. The wallet refuses to
  open such a session and says so.
- A smaller win is steadier and costs more in fees: a routing node charged 1 sat for each win,
  which is 1.6% of a 64-sat win and 6% of a 16-sat one, per hop, at the forks' default policy.
  The wallet cannot know what a route will charge before it pays: it knows whether the seller's
  node is its direct peer, and the fee limit it gives its node. Its floor for a win (64 sat
  through a routing node, 4 sat over a direct channel) is a rule, not a measurement, and no
  direct channel and no second hop were run.
- A win is an ordinary payment, pending on every channel of its route until it settles
  (0.22 s at the median on the lab, 0.44 s with 8 on their way), and wins of 64 sat are below both dust limits while they are
  pending: one that is pending when a channel on its route is force-closed has no output there
  (reasoned, not run). The wallet keeps at most 8 payments on its way at once, tickets and wins
  together, in the order they were found, except that a win its seller's answer stands still
  for goes first. On one 30-slot channel that paid the wins of 100
  sellers of one buyer at 14 wins a second, with no payment failed; a buyer whose wins come
  faster than that keeps its sellers waiting: a seller serves on for its grace of 30 s, and an
  answer it is sending stands still for a payment for 10 s at the most before it is cut. Before the wallet kept a win inside that limit until it had settled, 24 payments were
  pending on the channel at once and 47 of 313 failed: found on the lab, and what the limit is
  for.
- What those two waits bound, reasoned from the lab's rate and not run beyond 100 sellers. A
  win no answer waits for takes its turn: with 100 sellers' wins waiting that is about 7 s at
  the lab's 14 wins a second, and a turn reaches the seller's 30 s at about 420 wins waiting;
  past that the seller serves that buyer nothing more until the win is paid. A win an answer
  stands still for (the third unpaid win of a session, or one that 64 pieces were served after)
  goes before those, so its wait is the next of the 8 places to come free, its own payment
  (0.44 s at the median on the lab), and the other wins of that kind ahead of it: some 140 of
  them at once would take the 10 s. Before the wallet did this, such a win took its turn with
  the rest, and on a busy host the turn passed 10 s: with 16 busy loops beside the lab a file
  was cut short in 12 of 15 runs of the 100-seller check, each time with every win paid
  afterwards, and in none of 5 with the wins in this order (`docs/TICKETS.md`, section 9.12).
  The wallet pays 8 at a time whatever the host: a slower host, or a slower route, has a lower
  rate, and these numbers shrink with it.
- An answer the wallet stops reading (its `max_sats`, the owner's `max_answer_s`, a piece that
  does not match) leaves up to the seller's window of pieces that it was sent and gives no value
  for: it names them as void. A seller takes so many voids a session (4 at the gateway, and
  each counts against its window); after that the wallet's next call opens another session. A
  buyer that voids pieces it did receive has had them free: the window's 8 a session at the
  most, voided or left open.
- A win whose payment fails (no route, a fee above the owner's limit) is not paid with the same
  invoice again. It is paid with the seller's next invoice for it, which the gateway makes when
  the first has lapsed (60 s); a seller whose grace is shorter has stopped serving by then, and
  serves again when it is paid.
- A wallet that starts again pays no win it found before the start: it cannot tell a start from
  a restore of older records, in which that win may be paid already; the seller has lost the
  wins that were unpaid at that moment (at most the 2 it bears). A gateway that starts again
  keeps its lottery sessions (`lottery.jsonl` in its state directory): each comes back with its
  chain, its draws, its open pieces and its unpaid wins, and a win paid while it was down is
  seen paid. Until 2026-10-14 a restart forgot them all, and with them the wins that were unpaid.
- The lottery's journal holds each session's seed. Whoever can read the state directory can work
  out every draw of every session to come, and a buyer that could would never win. It is
  written private to the gateway's owner, as the session keys and the receipt key are.
- What keeps a restart from taking a second value for a draw it revealed for is that draw being
  on disk first: every answer that reveals waits for the journal's sync (a few milliseconds on
  an SSD, more on a slow disk; not measured on the lab). A disk that cannot be written ends the
  session whose draw it was (`500 journal`, nothing revealed). Everything else is synced twice a
  second: a power cut can lose the last half second of pieces served and values voided, which
  the buyer then has free, and of seqs used up, which it is told again (`bad_seq`). A gateway
  that starts reads every session's chain again: `chain_draws` hashes each, about 64 times
  65,536 with the default caps.
- A buyer's node that is killed as it sends a win's payment can go on calling that payment in
  flight with nothing on its channel (the same behaviour as for a ticket, below). The wallet
  keeps that win booked as spent and does not pay it again, the seller is not paid for it, and
  the session with that seller ends; the next call opens another. Seen in each of the five
  runs of the lab's kill check that killed the buyer's node in the middle of a download, with one
  to three payments.
- For a seller the owner has not named, the wallet pays wins of 250 sat at the most and 32 wins
  in a task's window, beside the task's caps on what any one seller is paid. A seller that sets
  a high price can take that much before the caps stop it; nothing checks that a price is fair.
- The wallet checks the draw, not the delivery. It gives a value for every piece that arrived,
  and checks a piece's content only where its caller gave the piece's hash; that argument
  (`piece_sha256`) is the signer's and is not in the MCP tool, so an agent cannot pass it yet.
  A route's `release: "after-verify"` tells a buyer its pieces can be checked; the gateway does
  nothing different for it.
- Not built: the renewal of a session's chain (a session ends after 65,536 draws and the wallet
  opens another), several wins in one invoice, a seller-held ticket for content that cannot be
  checked, and a win that pays itself (next section). The wallet keeps a session's values in
  memory only.
- A win is not proof to a third party: the session key that authenticates a value is the
  seller's too.
- One hop, one host, loopback. Separate seller machines and nodes, two or more hops, real
  network latency, a Core Lightning node, and mainnet fees were not run. The 100 sellers shared
  one node: the buyer's channel, the hop and the seller's inbound channel carried what 100
  sellers' wins would, and the seller side was one node's worth of work.

### The win that pays itself (in design)

Nothing in this section is shipped code, and no script in this tree reproduces its numbers. In
this second form of the lottery the buyer locks one ticket with the seller and each draw gives
the seller a small chance of obtaining its secret, so that a win cannot be refused. Each
sentence below comes from the design's measurements: three Lightning Fork nodes on regtest, one
routing node between buyer and seller, one host. A sentence marked *(simulated)* involved no
node.

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
- Sellers cannot pool wins as miners pool blocks: a piece served is not proof of work, so a
  seller and a buyer it controls can invent pieces at no cost. *(simulated)* The protocol has no
  pool.

### Seller gateway (`xbt-gateway`)

Regtest only. The gateway has run against Lightning Fork nodes on one host
(`scripts/gateway_regtest.sh`, with a test buyer; `scripts/ticket_e2e_regtest.sh`, paid by the
wallet) and against a stand-in node in its tests.

- It needs two macaroons of the seller's node: one with `invoices:read` and `invoices:write`,
  and one with `info:read`, because the first cannot read the block height. Each is refused on
  mainnet when it grants anything else; the check reads the macaroon and does not verify it, and
  on any other chain a wider one is taken with a warning.
- A third macaroon, with `offchain:read`, is the runner's choice (`node.channels_macaroon`). With
  it the gateway reads its node's channel list before every lock of a held ticket that its caps
  on sessions let through: one call to the node for each, with a timeout of 15 seconds. A lock
  those caps refuse (`too_many_sessions`, `too_many_tickets`) is refused before the call, and a
  lock for an existing session is authenticated before it; a first lock is authenticated by
  nobody, so while session places are free anyone can make the gateway read the list once per
  request. The permission
  is wider than that one call: it also shows the node's channel balances, its payments and what
  it forwarded, to whoever has the gateway's files. Without it the gateway knows nothing of its
  channels and keeps to the numbers in its config.
- A cancel is two calls to the node: the cancel, and a lookup of the same invoice, because the
  gateway takes no cancel's success for the invoice's state. Whether the fork's node ever
  answers success to the cancel of a settled invoice was not checked in its source; the stand-in
  node of the tests is made to, and the gateway then credits the ticket and reports nothing
  cancelled.
- No secret is taken without a block height from the node that is at most 10 seconds old; such
  a request is answered 503 and the secret is good again later.
- The 24-block margin is checked against the height the node last reported, which is asked for
  twice a second: a block that arrived since is not counted.
- The margin rests on when the node cancels a held ticket by itself (lnd's
  `invoices.holdexpirydelta`), which no call of the gateway's macaroons can read. The gateway
  takes the runner's word for it (`node.hold_expiry_delta`, 18 as the Lightning Fork node ships)
  and refuses to start above 18. A runner who writes a smaller number than the node's has a
  margin that leaves less than 6 blocks for a settle that has to go on chain, and nothing
  notices.
- The gateway's defaults are sized for an inbound channel that carries 30 pending payments (a
  channel with a Core Lightning node at its default): a session holds 2 tickets, and all
  sessions together 15 (`caps.max_held_tickets`, half of `caps.inbound_slots`). A buyer beyond
  that is answered `slots_short` with a time to wait, before any invoice exists. Until 2026-10-13
  the defaults were 8 a session and 240 in all, sized for 483.
- The cap is one number for the whole node. The buyer's node chooses the channel a ticket
  arrives on, so on a node with several inbound channels 15 held tickets can all sit on one of
  them, and a runner who raises the cap for several channels (`caps.held_over_half`) has said
  that one channel may be filled past half. Unpaid ticket invoices count against the cap for up
  to 75 seconds: a buyer that asks for tickets and pays none keeps others waiting that long.
- The gateway's own count is of the tickets it issued. Payments pending on its node's channels
  for any other reason (the node's own routing, another program's invoices) are seen only with
  the channels macaroon; with it, no held ticket is issued while any active channel has half of
  its slots or more pending inwards, and the cap is half of the smallest active channel unless
  the runner set one. A channel list that cannot be read falls back to the config's cap and is
  reported on standard error, once per lock. A gateway whose channels macaroon does not work at
  its start does not start.
- With the default caps buyers can hold 15 tickets, 15,000 sat of the seller's inbound capacity
  and 15 slots, at no fee: for 1 minute by a session that never releases a secret, for 5 minutes
  after a session's last paid request, and again as soon as they are cancelled. One address can
  hold 2 sessions, 4,000 sat. Measured on the lab with the earlier caps: a buyer that locked 8
  tickets and released none held 8,000 sat for 16 s with the limit set to 15 s.
- A held ticket is at least 546 sat: a config that offers held tickets below that is refused.
  The gateway does not read its channels' dust limits; on a channel without anchors at a high
  fee rate a 1,000-sat held ticket can still be below the limit (`docs/TICKETS.md`, section 11),
  and nothing in the gateway notices.
- Prepaid tickets (`settle: "on-arrival"`, offered beside held ones unless `tickets.settle` says
  otherwise) are ordinary invoices, paid in full when they arrive. The buyer cannot have one
  back: what it bought and did not use is the seller's when the session is forgotten (24 hours
  after its last paid request, or at once when the balance is nothing). A session can have 2 of
  them issued and unpaid, beside its 2 held tickets; all sessions together 60 invoices with the
  default caps, each given up within 75 seconds.
- A prepaid ticket is credited when the node shows its invoice settled for the full amount:
  when the buyer presents the preimage, or by the janitor's sweep 75 seconds after it was issued
  if nobody did. An invoice paid short credits nothing, and the node keeps what arrived. The
  gateway makes each preimage, hands it to the node with the invoice and does not keep it.
- The gateway does not make a Core Lightning node a seller: it speaks to a Lightning Fork node's
  REST interface only, for prepaid tickets as for held ones.
- The cap per address counts the socket's address: behind a reverse proxy every buyer has the
  proxy's. The runner either names the proxy and the header it reports a buyer's address in
  (`http.forwarded_address`: believed from the named addresses only, the last entry of a list,
  and a request without one counted under the proxy's own address), or sets
  `sessions_per_address` to 0 and caps in the proxy. The cap on connections from one address
  (`http.per_address`) is taken before any header is read and always counts the socket.
- Whoever can reach the gateway from enough addresses can take every session place with locks
  it never pays, at no cost, a minute at a time: new buyers are refused meanwhile
  (`too_many_sessions`). Sessions that already hold tickets keep them and their balance, and can
  refill up to their own 2; a session with nothing locked at that moment waits for a place. With
  the default caps the 15 held places are taken first, by 8 sessions.
- Every lock makes invoices on the node, up to 75 at once with the default caps (15 held and 60
  prepaid) and each given up within 75 seconds if unpaid; the node keeps cancelled invoices in
  its database until it is set to collect them (`gc-canceled-invoices-on-the-fly`).
- One thread and one connection to the node per held ticket: 15 with the default caps. A prepaid
  ticket has neither; the node is asked about it when its preimage is presented and at the sweep.
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
- A `HEAD` of a route priced by the byte or the second costs nothing, and a `GET` the service
  answers 204 or 304 costs the request's price only. Neither is served to a ticket session with
  no balance. For honest buyers that means: a `HEAD` needs a session that has released a ticket
  and still has a balance (at least the request's price, one byte's and one second's); a buyer
  that only wants a length has to buy a ticket first, and keeps its balance. A session with any
  balance left can ask for as many such answers as it likes, and the service works for each.
  In a session of draws a `HEAD` of such a route is refused, so a buyer that pays by draws
  learns a length from the body's own head or pays that one request with tickets; and a 204 or
  304 reaches it without the service's headers, which still tells it, free, whether what it
  holds is current: one bit a request, by which a date could be found in about 30 of them. An
  error (400 and above) is passed on with its headers as before.
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
  callers, which behind a reverse proxy on the same host is every caller unless the runner named
  the proxy (`http.forwarded_address`): then the address the proxy reports decides. It shows
  counts and no secret.
- The gateway speaks plain HTTP: a public seller needs a TLS reverse proxy in front, and
  `public_url` set to the origin buyers use, or every payment fails its request binding. It
  refuses a config that listens off loopback (any address but `127.0.0.1` or `[::1]`, and any
  name) unless `public_url` is `https`. That is the runner's word that a proxy is there, and the
  gateway cannot check it: a runner who writes an `https` origin and runs no proxy serves
  session keys and paid answers in the clear.
- A config that names no chain is a regtest config. Mainnet takes two keys, `"chain": "main"`
  and `mainnet_ack` with a fixed sentence, and a gateway that starts there prints a short list
  of what is open, at every start. That is a guard against a mainnet start by omission and
  nothing more: the two keys make no part of the gateway fit for mainnet, and a runner who
  writes them has the limits of this file as they stand. The chain is also checked against the
  node's own at the start, as before.
- Not run: more than one routing hop, real network latency, mainnet, IPv6, a seller with several
  channels, and the Core Lightning fork. The channels macaroon was run against the stand-in node
  of the tests and on the lab against a Lightning Fork node whose channel was opened with 30
  slots; no Core Lightning node was in that lab.

### Stream tickets: the wallet's ticket book

The buyer's side, in the signer (`ticket.rs`, `ticket_rail.rs`): secrets, tickets locked through
the owner's node, and the booking. It is reached through six socket methods, and by the wallet's
own payer under `xbt402_pay` (the next section). Verify-before-release for checkable content
and admission by content hash are not built; the lottery is its own section above. Prepaid tickets are bought by the
payer only: no socket method buys one. Run on regtest only (`scripts/ticket_book_regtest.sh`).

- The defaults are sized for a channel that carries 30 pending payments: a pool of 2 tickets
  with each of up to 4 sellers of a task and 1 beyond that (`tickets.pool`, `pool_many`,
  `many_sellers`), 15 held tickets in all (`max_locked_tickets`, `max_sellers`), and no held
  ticket below 546 sat. Until 2026-10-13 they were 8, 2 beyond 8 sellers, 64 and 64 sat.
- **A policy written before 2026-10-13 that sets none of these now means the new numbers.** One
  that sets them keeps what it says, except in two places, each reported by `validate_policy` as
  a warning: `floor_ticket_sats` below 546 no longer lowers the floor, and `max_locked_tickets`
  above half of a channel's slots no longer raises what is held on that channel. And a policy
  without `tickets.velocity` now counts a session as one payment for `velocity_max`, where it
  counted every release (see "A release is one payment" below).
- Before every lock the wallet reads its node's channel list and keeps two rules on the channels
  the payment may leave on. The tickets to lock and the payments already pending outwards on a
  channel, whoever's they are, stay within half of the slots it carries; and the ticket is not
  below the larger dust limit of its two sides (`ticket_slots`, `ticket_dust`). A channel's
  slots are the smaller of the two `max_accepted_htlcs` the node reports, and 30 where the
  listing does not give both. With no channel list nothing is locked.
- These rules see the wallet's own channels only. A hop's or a seller's channel that is full, or
  that has a higher dust limit, is found by a payment failing, or not at all: a ticket that is
  dust on a channel further along the route is locked all the same, and can be lost by whoever
  offered it on that channel if the channel is force-closed while the ticket is held.
- The wallet's node chooses which of its usable channels a ticket leaves on. The wallet
  therefore takes the smallest of them for the budget and the fullest for the room, which on a
  node with a 30-slot and a 483-slot channel holds 15 tickets in all although the larger channel
  has room for more.
- On a channel that is not an anchor channel the dust limit is taken with the fee of the HTLC's
  own transaction at four times the channel's present fee rate. A rate that rises further while
  a ticket is held can still take the ticket below the limit. A channel type the wallet does not
  know by name is taken as one without anchors; one the listing does not name at all, as an
  anchor channel. The wallet does not read the dust the node already carries on a channel
  against the node's own cap on it.
- A lock that fails as a full channel does (the node reports `INSUFFICIENT_BALANCE`, `NO_ROUTE`
  or an error with no HTLC out) halves the session's pool, never below 1, and nothing is locked
  with that seller for 30 seconds, doubling with each failed round in a row up to 10 minutes.
  After the third round in a row no ticket is held with that seller for 10 minutes
  (`ticket_route_full`), and the first failed round after that is 10 more. A new session with
  the seller starts where the last one stopped. The wallet cannot tell a full channel from one
  that is short of balance or from a seller that is unreachable, and treats all three this way.
- The smaller pool stays for the rest of the session, also after the route has room again.
- A ticket that meets a full channel at a later hop is in flight on the wallet's node for a
  moment before the refusal is back (seen on the lab). In that moment the book shows it locked.
  The wallet releases a ticket only after the seller has shown it locked, so no secret leaves
  for it; a call that had chosen it takes the session's next ticket.
- With 2 tickets held, a buyer that uses tickets faster than one can be locked waits for locks:
  a 100 MB file of 20 tickets took 3.4 to 3.7 s on the lab, against 1.7 to 1.9 s with a pool of
  8 (`scripts/ticket_e2e_regtest.sh`, `stream`). The remedy is a larger ticket, which the owner
  allows with `tickets.max_ticket_sats`, and not a larger pool.
- At most 8 ticket payments are with the node's router at once, held and prepaid together, for
  all sessions of the wallet. Other payments of the node (`ln_pay`, the owner's own) are not
  counted, and a lock round of more than 8 tickets takes correspondingly longer.

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
- A ticket is locked for as long as the wallet's node says its payment is in flight. Seen on the
  lab: a Lightning Fork node killed in the instant it was sending a ticket's payment kept that
  payment `IN_FLIGHT`, with no HTLC on its channel, after it came back and after a further clean
  restart. The wallet counts such a ticket as locked, against its caps and its slot budget, until
  the node gives the payment up; how long the node takes was not followed. With a pool of 2 the
  next ticket is sent after every release, so a node that dies right after a paid request is
  more likely to be caught in that instant than it was with a pool of 8.
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
- A release is one payment under every rule of the wallet but one: for `velocity_max` a ticket
  session is one payment (`tickets.velocity: "session"`, the default since 2026-10-13), counted
  from its first release for as long as one of its releases is inside the window. Its releases
  are bounded by the budgets, the caps on locked funds and `max_sends_per_hour` (1,200), not by
  `velocity_max`: with the shipped 8 an hour, the ninth session of an hour is refused when it
  opens, and a session can release until a budget stops it. An owner who wants every release
  counted sets `"release"`: a wallet then releases at most 8 tickets an hour across all rails,
  and an answer priced as it goes stops at the eighth (8,000 sat with the default ticket). This
  was the meaning of a policy without the setting until 2026-10-13. Releases to one seller
  inside `split_window_s` add up against `max_per_tx_sats` and the human threshold as any split
  payment does, under either setting.
- A ticket released before this version has no session in its ledger row and counts as one
  payment under either setting.
- No release can wait for a human: a session whose one ticket, with its fee limit, would reach
  `human_threshold_sats` is refused when it opens.
- The owner names a ticket seller by its node id: `ln:<node id>` on the allowlist, or an
  allowlisted origin whose `counterparties` entry gives the node id (`ln_node`). An origin alone
  names nobody. Under `xbt402_pay` the origin is the one the signer itself fetched the terms
  from; on the socket's `ticket_open` it is the caller's word.
- A seller the owner has not named is paid only under a task that admits any seller, and by
  default at most 1 ticket locked and 4 tickets' worth paid in the task's window. The cap is per
  node id, and node ids are free to make: what bounds a seller that takes a ticket and serves
  nothing, under as many node ids as it likes, is the task's budget.
- A task's budget is read over a rolling window of at most a week (a day by default), from the
  wallet's own ledger. Tickets found on the node after a restore count against the daily and
  weekly budgets and their seller's cap, and against no task's budget.
- One session per seller at a time; a session with no lock or release for 10 minutes is stopped,
  and no session survives a start of the signer.
- On the six socket methods the signer does not talk to sellers. It says how many hashes a pool
  wants (with half of the pool or fewer left: back to the pool's size; with 2, when 1 is left)
  and the caller fetches the invoices; a
  refill happens when the caller asks, and stopping a session only names the tickets to cancel.
  Under `xbt402_pay` the signer does all of this itself (the next section).
- A hash whose invoice the book refused (a cap was reached) keeps its place in the pool for 2
  minutes: the pool asks for no other hash in its place until then. One refused for lack of a
  slot or for dust is given up at once, and the session's wait takes its place. Under `xbt402_pay` a round
  that never came to an invoice being judged (the seller's lock answer was lost or refused, or
  the wallet's own node could not be asked) gives its hashes up at once; on the socket's methods
  such hashes also wait their 2 minutes.
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
  `xbt402_pay` still asks the seller once without paying, and can pay only a single Lightning
  invoice (where the Lightning rail is on). A seller that answers without a 402 is answered from
  the wallet's one unpaid request (`rule: free`, `rail: none`). A call with `max_sats` 0 pays
  nothing: a 402 is refused (`max_sats`).
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
- An entry that releases `after-verify` is not paid: the wallet passes it over and tries the
  next rail.
- Held tickets are the wallet's first choice. It buys a prepaid ticket (`settle: "on-arrival"`)
  only when the seller's 402 lists that entry and no ticket can be held: the slot budget has no
  room, the ticket would be dust on the wallet's channel, a lock found no slot and the session
  waits, the seller answered `slots_short`, or the seller offers nothing else. Where none of
  these holds and the seller offers no prepaid tickets, the call is refused with the reason and
  the seconds to wait (`retry_after_s`), or the next rail of the 402 is tried.
- A prepaid ticket is spent when it is paid, used or not: the wallet books it in the ledger,
  under every rule of a release, before the payment is sent. The buyer's worst case is the same
  one ticket as with a held one, with two differences: an unused prepaid ticket never comes
  back, and a seller that takes the payment and then refuses the preimage keeps it. The wallet
  buys one at a time, when the balance does not cover the next piece, and never one ahead.
- Each prepaid ticket costs the answer a pause: the seller's invoice, the payment and the
  seller's word that it was credited, 0.21 s at the median through one hop on the lab
  (`scripts/gateway_regtest.sh`, `prepaid`) and 0.32 s a ticket through the wallet
  (`scripts/ticket_e2e_regtest.sh`, `slots`), where a held ticket that is already locked costs
  one request. An answer priced as it goes is slower by that much per
  ticket, and a seller that waits less than that for a refill would cut it.
- A prepaid payment whose fate the wallet's node cannot tell within the Lightning rail's
  `timeout_s` and 5 seconds stays booked as spent, and the session is stopped as faulty. The
  booking goes when the node shows the payment failed, or, for a payment the node never had,
  60 seconds after the timeout.
- The wallet keeps a prepaid ticket's preimage in memory until the seller has credited it. A
  signer killed in between has paid for a ticket whose balance it then gives up with the
  session, as it gives up any balance at a restart. The gateway credits the session all the
  same, 75 seconds after it issued the invoice.
- The slot and dust checks, the wait after a failed lock and the fallback run on the wallet's
  own node and on what the seller says. A seller that always answers `slots_short` is paid with
  prepaid tickets or not at all; it cannot make the wallet hold more, pay more, or pay sooner.
- After a lock round, the wallet asks the seller to cancel the invoices of that round that were
  refused or failed. The answer is not read; a seller that does not cancel them holds its own
  places until the invoices lapse.
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
- After an answer that the wallet stopped reading because its pool ran out, the next call to
  that seller waits until the seller has closed the answer: 3 s with the gateway's default wait
  for a refill, at most 5 s a call (`ticket_answer_open`, nothing released), and after 30 s the
  session is stopped and the next call opens another.
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
- Not run: more than one hop, real network latency, TLS to a seller, mainnet, the Core Lightning
  fork (no Core Lightning node was in the lab of these scripts: the 30-slot channel there is
  one a Lightning Fork node opened with `--default-remote-max-htlcs=30`, which bounds what its
  peer sends it and not, as a Core Lightning node does, what it sends itself), more than one
  seller at once through this path, and a seller other than `xbt-gateway`. An answer priced by
  the second was run against the gateway in process, not on the lab.

### HTTP: what every rail shares

- A URL whose host two URL parsers could read differently is refused before anything is paid or
  sent: a backslash, a host with percent-encoding or non-ASCII letters, the short, decimal and
  hexadecimal forms of an IP address. A payer reads as one origin every spelling that differs only
  in letter case, a default port or a user name; a trailing dot on a name is a separate origin.
- A receipt covers the request, the answer's status and its body, not its headers; a body sent
  with neither Content-Length nor chunking ends when the connection does, so only the receipt's
  body hash shows it was cut.
- A server takes 64 connections in all and 48 from one address; a public listener needs a reverse
  proxy with its own limits.
- A program that uses these crates' HTTP client from another workspace does not compile until it
  adds the patched `ureq` to its own manifest, and `cargo deny` reports no advisory for the patched
  copy; advisories for `ureq` are looked up by hand.

### Agent wallet (`xbt-signer`)

Policy, approvals, keys and the socket: what holds for every rail.

- The wallet has two rails off Lightning, and neither pays a seller's 402: `pay` sends coins on
  chain from the node's wallet to an address on the allowlist, under the budgets, and on-chain
  fees are outside every budget. A payment over the human threshold waits for the owner's
  signature; so does a Lightning payment (`ln_pay`), which is then paid when the agent asks again.
  Ticket and lottery payments are bounded by the task's budget and caps and never wait for a human.
- A human-signed operation runs once, as long as the file of used signatures is neither deleted
  nor restored from before the signature was used; a missing file is read as an empty one. A
  human-signed operation run while the host clock is far ahead fixes that time in the wallet:
  later signatures that expire before it are refused, policy changes included, until the owner
  resets the file, which also forgets every used signature. *(test)*
- Every socket-level finding needs a process that can open the signer socket; an agent held to the
  MCP tool list cannot reach those methods.
- The one-time enrolment code protects the first approval key only when the socket and the
  signer's directory belong to different users, as in the container layout.
- An on-chain payment whose fate the node did not report stays counted against the budgets: the
  node may have sent it.
- A crash between holding an approval and paying costs the approval with nothing paid; the same
  holds for a human signature, which is used up when its operation starts.
- The backup export's signature does not name the passphrase the backup is sealed under; an
  expired approval can be dismissed without a signature; a key blob without a recorded cost opens
  at scrypt 2^15 and is re-sealed only when its file is next written.
- Key wiping covers long-lived copies in the Rust signer only.
- The wallet's spend lock is held for each lock round's bookkeeping and each release on the
  ticket rail, not while a seller answers; an on-chain `pay` and a single Lightning payment hold
  it for the whole payment.
- A watcher step that panics is reported and skipped, and the next tick tries again; in a
  `release-small` build a panic ends the signer process, and whatever supervises it restarts it.

### What a seller wrote (tool results)

The rule: **nothing a seller wrote is in a tool result outside the field marked untrusted**, on
any payer and any rail. `untrusted_provider_response` holds a seller's answer and receipt; on the
Lightning rail `untrusted_ln_data` holds the node's and the invoice's text. Every other string of
a result is the wallet's own: its `rule` and its `reason` above all, which an agent reads as its
wallet speaking. A seller that refuses is reported in the wallet's words, and its answer is in the
untrusted field.

| payer and rail | where a seller's words reached the wallet's own fields | now |
|---|---|---|
| Lightning (`ln_pay`, `ln_status`) | a refused invoice's or offer's prefix (free text, under a checksum its writer computes) and an offer's currency were quoted in `reason`; the node's error message, which can repeat a payee's or an issuer's, was the `reason` of `ln_backend` and `ln_fetch_invoice`; `ln_status.recent[].failure` was the bare text | a refused string is described and not quoted; the node's message is under `untrusted_ln_data` (`node_message`), and so is each listed `failure`. Every result that reports an error of the node carries its message there, beside the wallet's sentence: at the top of an `ln_pay` refusal and of an `ln_status` that could not reach the node, and inside the part it is about (`chain_check`, `watchtowers`, a `reconciled` row; an unreadable channel or coin list under `node_messages`). A macaroon the node refuses is `ln_macaroon`, "the LN node refused the macaroon"; which refusal it was (a caveat, an expiry, a permission) is the node's message |
| stream tickets, the wallet's node (`ticket_lock`, `ticket_status`, a prepaid ticket or a win) | the node's error message was dropped: a refused invoice, a send with no answer, a reconcile row and `ticket_status.node` gave the wallet's sentence alone | each of those rows carries the node's message under its own `untrusted_ln_data` (`node_message`); a ticket whose send got no answer says so in `send_error` |
| stream tickets (`xbt402_pay`, `ticket_status`, `ticket_stop`) | refused terms were quoted in `rails_passed_over`; `offered` listed each entry's scheme and network; the seller's error code, by its shape, was in `reason`, `seller_code`, `seller_fault`, `ended` and a stopped session's `why`; a refused invoice's prefix was in `reason`; the last receipt of a streamed answer was the seller's whole object | terms are described; `offered` says `ticket`, `exact`, `batch-settlement` or `other`, on this wallet's network or `other`; a code is named only when it is the scheme's; the receipt is given as its numbers, and the seller's object as `untrusted_provider_response.last_receipt` |
| every rail's HTTP | the transport's error text went into `reason`: it quotes a status that is not a number (three characters) and, on the ticket rail, the URL with the seller's session path | a fixed sentence per kind of failure |

- A seller's error code is its words unless it is one of the protocol's own
  (`xbt402::ticket::PROTOCOL_CODES`). A code the shipped gateway adds later is not named by an
  older wallet: it reads as no code.
- Numbers are not words, and nor are hashes, keys, ids and signatures of a fixed hex shape: a
  result gives them as they are (`payment_hash`, a session id, a receipt's amounts).
- One character can still come through: a field that should be hex and is not is reported by the
  hex reader as `Invalid character 'x' at position n`, and where that is a seller's field the
  character is the seller's.
- What the agent itself passed is given back in the wallet's sentences: the origin of its URL
  (`destination not on allowlist: ...`), its task name. An invoice or offer the agent passes is
  the payee's string and is never quoted.
- The wallet's own Lightning node is trusted for what it reports as fields: a channel's
  `remote_pubkey`, `commitment_type` and `channel_point`, the watchtowers' addresses, its
  `identity_pubkey`. Its alias, its version and its error messages are under `untrusted_ln_data`.
- Records written before this change are read back as they were written: a stopped ticket
  session's `why` and the audit log that `history` returns can still hold a seller's error code
  that an earlier version let through by its shape. (A channel record an earlier version left is
  listed by its numbers and ids only.)
- The files an operator reads are outside the rule: the call log (`B2_CALLS_JSONL`) and the
  processes' own logs.
- The rule is held by reading the code and by tests that plant a marker in the strings a seller
  controls (`agp128` in the test names of `xbt402` and `xbt-signer`). It is not held by the type
  system: a new result field that copies a seller's string would break it, and only a test with
  that string would show it.

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

### Signature hash and replay

- The annex and codeseparator sighash vectors were generated with Knots' Python and not executed
  against its C++; the retarget vectors are recorded from the project's own Python.
- A payment sent through the node wallet (`pay`) is replay-protected only if that node does not
  run `-walletoldsigs`.

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
- A panic in one watcher tick or loop round is caught and the next one runs, in the signer and
  the work provider; what a panic that repeats every round does is in each area above.
- A binary built with the `release-small` profile aborts the whole process on any panic; the
  shipped images are not built with it, and it must not be used for a server.
- The wallet MCP over stdio ends on a panic in a quick tool and has to be started again by its
  client.
- The images and size tables under `dist/` were built before overflow checks were turned on.

### Python references

The two Python references still hold the on-chain channel that this tree no longer has: the
channel itself, and a wallet that pays over it. They have no tickets, no lottery and no gateway.
Their limits, the channel's among them, and those of the Python agent wallet's forward rail, are
in `docs/LIMITS.md` of each reference's own repository:
[Lightning-Stream-py-channel](https://github.com/AwokenLazarus/Lightning-Stream-py-channel) and
[Lightning-Stream-py-wallet](https://github.com/AwokenLazarus/Lightning-Stream-py-wallet).

## Open items

Not fixed. One item is open, and it is not in this tree's code: it is in the Python wallet
reference, on a rail the Rust wallet never had.

- **Forward rail of the Python wallet (off by default): a lot recovered after its channel was
  replaced** (`open: AGP-102 list 1 item 5`; Python wallet, three tests). After such a recovery the
  next channel to that market signs states that are not booked and not checked against the
  policy, up to the recovered lot's total, and the daily and weekly budgets do not fill; and a
  recovery from a close that is then never mined ends that channel's refund watch. It needs the
  rail turned on, an allowed market and the agent's own calls. Do not turn the forward rail on.

Three more items were open on the on-chain channel's path until it was removed, and are not open
here because their code is gone; the Python references, which keep the channel, still have the
first: a streamed result that could not be bought on a postpay channel one call behind
(`AGP-102 list 1 item 13`), a call whose answer was lost and that the close did not pay
(`AGP-111 item 1`), and a default per-seller cap above the shipped provider's maximum
(`AGP-111 item 2`). Whether the streamed-result item applies to tickets was checked: it does not.
It came from a channel state that got no receipt; on the ticket rail every answer has a receipt,
a streamed one at its head and in the session's `status`, and the wallet buys no content
`after-verify` at all (a stated limit above).

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
- the lottery: the draw and its fairness argument (`xbt402::lottery`), the gateway's sessions of
  draws and the wallet's payer for them: written after the last audit, tested by the project
  only, and the argument read by nobody outside it;
- the removal of the hub itself (2026-10-11): what was cut from the provider, the client library
  and the signer, and how records of the removed features are treated;
- the removal of the on-chain channel (October 2026): what was cut from the wallet, the MCP
  server and the web interface, what `xbt402_pay` does without a channel to fall to, the server
  and payer that pay with work was moved onto, and how channel records, policy keys and approvals
  an earlier version left are treated;
- anything on a real network: no mainnet node and no Lightning node outside a test rig was used,
  and every "blocks" figure was measured on regtest blocks mined at once.

Failure paths through the release binaries are run for the ticket rail and the lottery only
(`scripts/ticket_e2e_regtest.sh` and `scripts/lottery_regtest.sh`: a seller that lies, played by a
proxy, and a kill of each part with a payment in flight). The script that ran them for the
on-chain channel and the light client went with those. Faults are injected on loopback by a proxy
and by signals: a slow or lossy network, a full disk, a clock that jumps and two faults at once
were not tried. Pay with work has no such run.
