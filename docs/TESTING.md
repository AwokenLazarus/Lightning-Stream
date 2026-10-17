# Testing Lightning Stream: a guide for a first outside tester

## What it is

Lightning Stream lets a buyer pay for a service piece by piece as it arrives, over ordinary XBT
Lightning channels, and stop at any moment owing nothing more. A seller puts a gateway
(`xbt-gateway`) beside an lnd-family Lightning node in front of any HTTP service; the buyer's
agent wallet (`xbt-signer` with its MCP server) pays it with stream tickets, which are hold
invoices on a hash the buyer chose, or by lottery draws for pieces worth less than a ticket. It
has run on regtest only, on one host, between the project's own Lightning Fork nodes.

## What we ask of a tester

1. **Now: a regtest run on your own machine.** Build the tree, run the tests and the regtest
   labs below, including the film demo, and tell us what failed, what was unclear, and what you
   could break. No real coins are involved: everything runs on a private regtest chain in Docker
   containers on your machine.
2. **Later, by invitation only: a small mainnet test** with the Umbrel or StartOS packages
   (`packaging/README.md`), a wallet app and a gateway app on a box with a Lightning Fork node.
   On mainnet neither app pays or sells until the owner types the mainnet acknowledgement, and
   both start with low caps (the wallet's starter policy: 2,000 sat a payment, 10,000 sat a
   day). **Mainnet testing has not started.** No package has been installed on a real box yet.
   What you could lose in such a test is the balance of the Lightning channel the wallet pays
   from, so open that channel small. Do not try mainnet before we ask; `docs/LIMITS.md` says why.

## The regtest run, step by step

What you need: a Linux machine (the steps below were run on Ubuntu 24.04, x86_64, 8 cores), about
20 GB of free disk (the toolchain, the build and the labs took 12 GB, and the Docker
images they use about 4 GB more), a network connection (the labs fetch code from GitHub and a film from a
mirror), and Docker with compose that your user may run. The numbers below are from one run on
one such machine, from a fresh clone; yours will differ.

```bash
sudo apt-get install -y git curl build-essential python3 ffmpeg
# Docker Engine and the compose plugin: https://docs.docker.com/engine/install/
# (or Ubuntu's own: sudo apt-get install -y docker.io docker-compose-v2)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
git clone https://github.com/AwokenLazarus/Lightning-Stream.git
cd Lightning-Stream
git rev-parse --short HEAD       # note it: your report needs it
ulimit -n 4096                   # the tests open many connections at once
```

| Step | Command | Took | What you should see |
|---|---|---|---|
| 1. Build and test | `cargo test --workspace --locked` | about 10 min the first time | Every `test result:` line says `0 failed` (707 tests at the commit we ran). At an open-file limit of 1024 about half of `ticket_pay.rs` fails with "Too many open files": raise it as above |
| 2. The wallet paying a gateway with tickets | `scripts/ticket_e2e_regtest.sh` | about 7 min the first time (it clones and builds the Lightning Fork lab under `run/`) | One `PASS` line for each check, then `ticket_e2e: 35 of 35 checks passed` and `ticket_e2e: OK` |
| 3. The lottery | `scripts/lottery_regtest.sh` | about 13 min | `lottery: 30 of 30 checks passed`, `lottery: OK` |
| 4. The film demo | `scripts/demo_film.sh` | about 7 min (it fetches the 276 MB film once) | `demo: 22 of 22 checks passed`, `demo: OK`, and a readout while the film plays |

Run one lab at a time: each takes a block of loopback ports and its own containers, and removes
its containers and volumes when it ends. The head of each script lists its ports, its settings
and its environment variables. The first lab also builds the chain node's image
(`knots-blake2b:final-zmq`) from source when it is not there yet: that took 4 minutes on four
cores, on top of the times above. The Jellyfin image (1.9 GB) and the Go image (1.3 GB) the labs
use were already on the machine of that run, so their download is not in the times either.

What each step writes, under `run/` (ignored by git):

- `run/ticket_e2e_regtest.json` and `.log`
- `run/lottery_regtest.json` and `.log`
- `run/demo_film.json`, `run/demo_film.log` and `run/demo-captures/`

The reports of our own latest runs are in `reports/` for comparison. `docs/DEMO.md` explains the
demo and what each of its numbers means.

## What to try breaking

The labs already run some failures: a seller that lies (another node id, tickets for another
payee, terms that change, inflated metering, no receipt, an answer cut in the middle), a buyer
that never pays a win, a seller that claims a win for a draw that lost, and a kill of each part
(the signer, the MCP server, the gateway, the buyer's node, the seller's node) with a payment in
flight. After each, what the buyer's node paid, what the seller's node received and what the
wallet booked must agree to the millisat. Things worth trying beyond that:

- **What the labs never tried** (`docs/LIMITS.md`, "Not reviewed by anyone"): a slow or lossy
  network between buyer and seller, a full disk under the signer or the gateway, a clock that
  jumps, and two faults at once.
- **The stated limits, checked against what you see.** `docs/LIMITS.md` lists each one. For
  example: a seller can take one ticket and serve nothing, and the buyer should lose at most that
  ticket; when a session stops, what is left of the last released ticket stays with the seller;
  a buyer that never pays a win is served about one win's worth before the seller cuts it off;
  held tickets never take more than half of a channel's 30 slots. A limit that turns out larger
  than the page says is a bug.
- **The owner's policy.** Budgets, per-seller caps, the allowlist, the cap for a seller the owner
  did not name, the human-approval threshold: try to make the wallet pay more, or pay someone,
  it should not.
- **The gateway's routes.** A path without a route must answer 404 through the gateway (the demo
  checks one). Try others.
- **Restarts and leftovers.** Interrupt a lab with Ctrl-C and run it again: it should start from a
  clean lab. `TICKET_E2E_KEEP=1`, `LOTTERY_KEEP=1` and `DEMO_KEEP=1` keep the containers for a look
  afterwards.

## How to report

Open an issue at <https://github.com/AwokenLazarus/Lightning-Stream/issues> with:

- the report file the script wrote (`run/<name>.json`) and, for a failure, the end of its `.log`;
- the commit id (`git rev-parse HEAD`): the reports do not record it;
- your OS and version, CPU architecture, and the output of `rustc --version`, `docker version`,
  `docker compose version`, `python3 --version` and, for the demo, `ffmpeg -version | head -1`;
- what you did, what you expected, and what happened instead.

**Never paste a macaroon, a seed, a private key, a password or an API key**, not even a regtest
one, and look through a log before you attach it. The regtest labs make their own throw-away
keys; a report file names checks and numbers, not secrets.

## What is not supported

- **A Core Lightning node as a seller's node.** It has no hold-invoice call, neither published hold
  plugin fits, and the gateway speaks to lnd-family nodes only (Lightning Fork). A Core Lightning node can be a
  buyer's node or a routing node (`docs/TICKETS.md`, sections 8 and 11).
- **A seller reached over Tor.** An onion address is plain http, and the wallet does not pay
  tickets over plain http.
- **A seller on plain http.** The ticket rail needs https, or http to the wallet's own machine
  (which is how the regtest labs run). The gateway itself speaks plain HTTP: a public seller puts
  a TLS reverse proxy in front of it.
- **Mainnet**, until we ask you (above). Everything here has been run on regtest only, and
  nobody outside the project has reviewed the fixes to the external review's findings.
