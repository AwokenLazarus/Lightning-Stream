# Lab reports

The reports the regtest scripts of this tree wrote on their latest runs, so that the measured
figures in `README.md`, `docs/TICKETS.md`, `docs/LIMITS.md`, `docs/DEMO.md` and
`crates/xbt-gateway/README.md` can be read against something other than prose.

**What these are, and what they are not.** They are our own runs, on one host, on an XBT regtest
chain, over loopback, between our own Lightning Fork nodes. Nobody outside the project produced
or checked them. They show what the scripts saw on that host on that day. They are not evidence
for a real network, for mainnet, or for a Core Lightning node: none was in these labs.

## The files

Each file is the JSON a script writes to `run/` when it ends: every check with its PASS or FAIL
(`ok`) and what it saw (`saw`, or `detail`), and the measured values under `measured`. All were
written on 2026-10-14 between 01:53 and 02:35 UTC, by the tree a few commits before the one that
added this folder. The reports do not record a commit id, so the exact commit cannot be read from
them.

| File | Written by | Checks | What it is |
|---|---|---|---|
| `ln_ticket_regtest.json` | `scripts/ln_ticket_regtest.sh` | 31 of 31 passed | Tickets as such, with no wallet and no gateway: lock, settle, cancel, expiry, a seller or a hop that goes away, the on-chain claim. The measurements of `docs/TICKETS.md`, sections 2 to 7 |
| `gateway_regtest.json` | `scripts/gateway_regtest.sh` | 51 of 51 passed | The seller gateway with a test buyer: latency, a metered download, a flood of lock requests, prepaid tickets, the channels macaroon, restarts |
| `ticket_book_regtest.json` | `scripts/ticket_book_regtest.sh` | 36 of 36 passed | The wallet's ticket book through the signer's socket: one seller, many sellers, the slot rules, a full channel, a lying seller, kills |
| `ticket_e2e_regtest.json` | `scripts/ticket_e2e_regtest.sh` | **33 of 34 passed, 1 failed** | The wallet paying the gateway through a routing hop with the release binaries. See the note below |
| `lottery_regtest.json` | `scripts/lottery_regtest.sh` | 30 of 30 passed | The lottery: a file bought by draws, 20 and 100 sellers at once, a buyer that never pays, a seller that lies, kills. The measurements of `docs/TICKETS.md`, section 9.12 |
| `ln_rail_regtest.json` | `scripts/ln_rail_regtest.sh` | 87 of 87 passed | The wallet's Lightning rail (`ln_pay`): invoices and offers, the wrong chain, macaroons, the funding proof |
| `demo_film.json` | `scripts/demo_film.sh` | 22 of 22 passed | The film demo of `docs/DEMO.md`: a film through one and two routing hops, pause, seek, a dropped connection, a restart, and the swarm paid by draws |

**The failed check.** In `ticket_e2e_regtest.json` the check `kill: ran to its end` failed with
`timed out after 30 s waiting for the pool locked and listed`. The kill part of that script kills
five parts in turn, each twice. The eight cases before it passed (the signer, the MCP server, the
gateway and the buyer's node); the run stopped before the two cases that kill the seller's node,
so this report has no result for them. A run of the same script on 2026-10-13 passed all its
checks; only its log was kept, and it is not here. The report is published as it was written,
with the failure in it.

## What was changed before they were put here

Three strings were replaced, and nothing else:

| In | Was | Now |
|---|---|---|
| `demo_film.json`, `ticket_e2e_regtest.json` | the absolute path of the checkout on the lab host, in six `saved_to` values | `<repo>/run` |
| `ln_rail_regtest.json` | the address of the lab's Docker network gateway, six times | `<lab-docker-gateway>` |
| `ln_rail_regtest.json` | the address of one lab node on that Docker network, five times | `<lab-docker-node>` |

Loopback addresses, the test addresses the scripts themselves use as inputs, node ids, payment
hashes and preimages of the regtest lab are left as they were: they are of a chain and of nodes
that hold nothing.

## Producing them again

```bash
scripts/ln_ticket_regtest.sh        # writes run/ln_ticket_regtest.json
scripts/gateway_regtest.sh          # run/gateway_regtest.json
scripts/ticket_book_regtest.sh      # run/ticket_book_regtest.json
scripts/ticket_e2e_regtest.sh       # run/ticket_e2e_regtest.json
scripts/lottery_regtest.sh          # run/lottery_regtest.json
scripts/ln_rail_regtest.sh          # run/ln_rail_regtest.json
scripts/demo_film.sh                # run/demo_film.json
```

Each needs Docker with compose and python3; all but the first build this tree's binaries and
need a Rust toolchain, and the demo also needs ffmpeg. The
first run fetches and builds the Lightning Fork lab under `run/`, which is why `run/` is ignored
by git and this folder is not. The head of each script lists its ports and settings. Times
differ from host to host, and the lottery's wins differ from run to run: a draw is random.

The tables in the documents were written from earlier runs of the same scripts, most of them on
2026-10-13, whose reports these runs overwrote. A figure that differs from run to run (a time,
or anything the lottery draws) is therefore not the same in a document and in its report here.
The documents have not been compared with these reports figure by figure.

A figure in the documents that is marked as measured before 2026-10-13, or as measured with the
Core Lightning fork, comes from an earlier run or from a lab whose driver is not in this tree,
and has no report here.
