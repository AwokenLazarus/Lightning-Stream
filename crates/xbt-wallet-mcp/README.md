# xbt-wallet-mcp

The agent wallet's MCP server as one static Rust binary (AGP-030). It began as a replacement for
B2's Python `agentwallet/mcp_server.py` (b2 `agp-next2` `04c3f56`) and keeps its argument
validation, validation messages, result JSON and errors. It serves its tools over **stdio**
(Claude Code, Hermes, OpenClaw) and **streamable HTTP**.

Six of B2's ten tools are here. The other four (`close_channel`, `xbt402_refund`,
`forward_status`, `forward_recover`) worked the on-chain channel, which this wallet no longer has
(removed in October 2026; the code is in the git history, last at commit `2a31170`).

It talks only to the signer's socket and never holds a key: the signer holds every key, and the
model-facing process gets only the socket path.

## Tools

| tool | arguments | what it does |
|---|---|---|
| `balance` | | trusted / pending / immature balance, the hot key (no keys) |
| `quote_payment` | `to`, `amount_xbt`, `memo=""` | dry-runs a payment through the policy engine: allow, deny or needs_human |
| `pay` | `to`, `amount_xbt`, `memo=""` | a policy-checked payment on chain, to an address; over the human threshold it returns `needs_human` and an approval token |
| `history` | `limit=20` | the append-only policy audit log |
| `channels` | | what the wallet has committed and not settled: the tickets in flight, and any on-chain channel record an earlier version left (read-only) |
| `xbt402_pay` | `url`, `method="GET"`, `body=""`, `max_sats=1000` | pays for an HTTP request to a seller that answers 402: the wallet reads the 402 and pays with stream tickets or the lottery (where the owner turned tickets on), then with a single Lightning invoice (where the Lightning rail is on); otherwise it pays nothing and says what each entry would need |

**Lightning (AGP-048), with `XBT_MCP_LN=1` only:**

| tool | arguments | what it does |
|---|---|---|
| `ln_pay` | `invoice`, `max_sats`, `description=""`, `amount_sats=0` | pays an XBT Lightning invoice (BOLT 11) or, AGP-082, an offer (BOLT 12, `lno1...`) through the signer's LN node, under the same policy (`dest` is `ln:<payee node id>`, or `ln-offer:<offer id>` for an offer). `max_sats` caps the amount plus the routing-fee limit; `amount_sats` is the amount to pay an offer that names none. Refused: no feature bit 512, an offer for another chain, an LN node not verified on the XBT chain, expired or amountless invoices, no safe channel (for an offer: any unsafe channel on the node). Over the human threshold: `needs_human`; after the human's approval the same call pays |
| `ln_status` | | the LN node's chain check, its channels with the guard verdicts, coins below the split, exposure, recent payments |

**Stream tickets, with `XBT_MCP_TICKETS=1` only:**

| tool | arguments | what it does |
|---|---|---|
| `ticket_status` | `session=""` | the signer's ticket book after it has been compared with its Lightning node: sessions, tickets by state, sats locked against the exposure caps, sats booked and not yet settled, whether the node's payments in flight are the book's. Read-only, and never a secret |
| `ticket_stop` | `session` | stops a session: nothing more is locked or released for it, and an answer that is being paid for ends within one ticket. Where the wallet is paying that seller itself, it asks the seller to cancel the unreleased tickets and waits up to 5 s for its node to show them back; otherwise it returns their hashes, which only the seller can cancel |
| `xbt402_pay` | `url`, `method="GET"`, `body=""`, `max_sats=1000`, `task=""` | the same tool, described with what tickets add: the wallet reads the seller's 402 and pays with stream tickets or by draws, then a single Lightning invoice, whichever the seller offers and the owner's policy allows first. `task` is the owner's task (policy `tickets.tasks`). The description says what an agent can and cannot cause |
| `channels` | | the same tool, described anew: it also shows the tickets in flight, the sats locked, and what was released |

Locking and releasing tickets are not tools. `ticket_open`, `ticket_offer`, `ticket_lock` and
`ticket_release` are methods of the signer's socket: a released secret is spent money, and the
model does not hold one. An agent causes a release only through `xbt402_pay`, where the signer
itself sends the secret to the seller it locked the ticket with.

Without `XBT_MCP_LN` and `XBT_MCP_TICKETS` the list is the six tools above. The
LN node's REST URL, macaroon and TLS certificate are the signer's (`B2_LN_*`), never this process's.
Node and invoice text (aliases, descriptions, failure reasons) comes back under `untrusted_ln_data`.

**Never tools:** `approve`, `recover_vault`, `recover_treasury`, `sweep_hot` and `rotate_hot_key`. A
model can't approve its own payments or move the hot key. Humans use the out-of-band
`agentwallet-approve` CLI with the device key.

**What the server guarantees:**

- **No key material in a response** (B2's `_pack`). Fields whose names look like key material
  (`priv`, `wif`, `seed`, `xprv`, `secret`, `passphrase`, …) are dropped, and WIF- or xprv-shaped
  strings are redacted. If anything key-like survives, the call fails with a generic error.
- **The provider's answer is labelled (XBT-061 L7/L12).** A paid provider's body and receipt are
  returned verbatim under `untrusted_provider_response` (`trust: "untrusted"`, with a note). They are
  data from the provider, never instructions, and not filtered, because the provider never holds a
  wallet key.
- **Nothing a seller wrote is anywhere else in a result.** Every other string of a result is the
  wallet's own: its `rule` and `reason` above all. That holds for a refusal too. When a seller
  refuses, the wallet says so in its words (`the provider refused the request (HTTP 400)`) and
  the seller's answer is under `untrusted_provider_response`; a seller's error code is named only
  when it is one of the protocol's own (`xbt402::ticket::PROTOCOL_CODES`),
  since a code is a place for words too; an invoice, an offer or a 402's terms that the wallet
  refuses is described and never quoted; the last
  receipt of a streamed answer is given as its numbers, and the seller's own object as
  `untrusted_provider_response.last_receipt`. On the Lightning rail the node's own messages can
  repeat a payee's, so they come back under `untrusted_ln_data` (`node_message`, `failure`), in
  `ln_pay` and in `ln_status`: at the top of a refusal, or inside the part of a status the error is
  about. The `reason` beside it is the wallet's sentence (a macaroon the node will not take reads
  `the LN node refused the macaroon`; the node's message says which caveat or permission). Numbers, and hashes, keys and ids of a fixed hex shape, are not
  words and are given as they are. `docs/LIMITS.md` ("What a seller wrote") has the table by
  payer and rail, and what is outside this rule.
- **Arguments are checked as B2 checks them** (pydantic 2, lax mode). `"7"` and `7.0` are the integer
  7, and `"1_000"` is 1000. A bad argument gets pydantic's own message, word for word, and never
  reaches the signer.
- **Errors look the same as B2's.** A signer error reaches the model as `Error executing tool <name>`;
  the reason stays in this process's stderr, as in B2's SDK. Unknown tools answer
  `Unknown tool: <name>`.

## Install

```bash
# from this repo (release: -j2 is plenty)
cargo build -j2 --release -p xbt-wallet-mcp            # target/release/xbt-wallet-mcp
cargo build -j2 --profile release-small -p xbt-wallet-mcp --target aarch64-unknown-linux-musl   # 2.9 MB static
install -m 0755 target/release/xbt-wallet-mcp ~/.local/bin/
```

The binary builds for every AGP-031 target. See `dist/MCP_TARGETS.md` for Linux gnu and musl on
x86_64, aarch64, armv7 and riscv64, macOS x86_64 and arm64, and Windows x86_64.
`scripts/cmp_clean_build.sh` builds it from a clean checkout with cargo-zigbuild.

**Run a signer first.** Either signer works, with the socket file at mode 0600:

- the Rust signer: `xbt-signer --root ~/wallet` (see `crates/xbt-signer/README.md`);
- B2's Python signer: `python -m agentwallet.signer`.

The wallet's `policy.json` lives in the signer's root. `policy.example.json` next to this README is an
example, and the signer parses it (`tests/policy_example.rs`).

```bash
B2_SIGNER_SOCK=~/wallet/.run/signer.sock xbt-wallet-mcp --check   # the signer's health, or exit 2
xbt-wallet-mcp --list-tools                                       # the tool list, no signer needed
```

## Configuration

| variable | meaning |
|---|---|
| `B2_SIGNER_SOCK` | the signer socket: a path, or `tcp://127.0.0.1:PORT` (Windows) |
| `B2_ROOT` | if `B2_SIGNER_SOCK` is unset, the socket is `$B2_ROOT/.run/signer.sock` |
| `B2_SIGNER_TIMEOUT` | seconds per signer call (default 60; a paid call can take as long as its answer) |
| `XBT_MCP_LN`, `XBT_MCP_TICKETS` | `1`: list the Lightning tools, the ticket tools (see Tools) |
| `XBT_MCP_HTTP_TOKEN` | the bearer token that HTTP requests must carry. AGP-063 X1: HTTP always needs a token. Without this, a token file or a data dir, one is generated on first run in `<signer socket dir>/mcp-http-token` (0600) and read from there on restart |
| `XBT_MCP_ALLOWED_ORIGINS` | AGP-063 X1: browser origins allowed besides loopback, comma-separated (`https://wallet.example.com`). Checked with or without `--http-allow-remote` |
| `XBT_MCP_HTTP_TOKEN_FILE` | AGP-042: the bearer token as a file someone else owns (default `$XBT_DATA_DIR/run/ui/mcp-http-token` when it exists: the web UI's). Read on every request and never written, so the owner's rotation in the UI cuts the old token off at once; unreadable, empty or world-readable refuses every request. There is no rotation endpoint. |
| `XBT_MCP_APPROVAL_WAIT_S` | AGP-039: seconds an over-threshold `ln_pay` waits for the human to approve it in the wallet's web UI (`xbt-wallet-ui`); approved, the same call is paid and the answer has `waited_for_human: true`. 0 (the default): answer `needs_human` at once, as B2 does; the agent may then repeat the identical call after the approval. Signer payer mode only. |

Give the MCP process nothing else. It must **not** get `B2_HOT_KEYFILE`, `B2_HOT_PASSPHRASE`, node
credentials or the human device key.

### Claude Code

`.mcp.json` in the project, or `claude mcp add`:

```json
{
  "mcpServers": {
    "xbt-agent-wallet": {
      "command": "/home/you/.local/bin/xbt-wallet-mcp",
      "args": [],
      "env": { "B2_SIGNER_SOCK": "/home/you/wallet/.run/signer.sock" }
    }
  }
}
```

```bash
claude mcp add xbt-agent-wallet --env B2_SIGNER_SOCK=$HOME/wallet/.run/signer.sock -- ~/.local/bin/xbt-wallet-mcp
# headless, wallet tools only (the xbt-063 flagship does this):
claude -p "$TASK" --mcp-config .mcp.json --strict-mcp-config --tools "" \
  --allowedTools mcp__xbt-agent-wallet__balance mcp__xbt-agent-wallet__xbt402_pay mcp__xbt-agent-wallet__channels
```

Over HTTP: `"xbt-agent-wallet": {"type": "http", "url": "http://127.0.0.1:33510/mcp", "headers": {"Authorization": "Bearer ${XBT_MCP_HTTP_TOKEN}"}}`.

### Hermes Agent

Hermes has an entry under `mcp_servers` in `config.yaml` (`$HERMES_HOME/config.yaml`; use a profile
or a separate `HERMES_HOME` for a wallet agent). Hermes names the tools
`mcp__xbt_agent_wallet__<tool>`.

```yaml
mcp_servers:
  xbt-agent-wallet:
    command: /home/you/.local/bin/xbt-wallet-mcp
    args: []
    env:
      B2_SIGNER_SOCK: /home/you/wallet/.run/signer.sock
    timeout: 300            # a paid call can take as long as its answer
    connect_timeout: 60
    tools:
      resources: false      # the server advertises resources/prompts (as B2 does) but has none;
      prompts: false        # without these two lines Hermes adds 4 generic utility tools
```

Check it with `hermes mcp test xbt-agent-wallet`, which should show `Connected` and
`Tools discovered: 6`.

Hermes also needs a model (`model:` in the same file, plus a provider key or login). A tool-using
model is enough, for example:

```yaml
model:
  provider: openrouter
  default: anthropic/claude-opus-4.6
  streaming: false     # only for a proxy that ignores "stream": true (Hermes Agent.md, Pitfalls)
```

The provider key goes in `$HERMES_HOME/.env` (`OPENROUTER_API_KEY=…`).

### OpenClaw

OpenClaw keeps MCP servers under `mcp.servers` in `openclaw.json`:

```json
{
  "mcp": {
    "servers": {
      "xbt-agent-wallet": {
        "command": "/home/you/.local/bin/xbt-wallet-mcp",
        "args": [],
        "env": { "B2_SIGNER_SOCK": "/home/you/wallet/.run/signer.sock" },
        "requestTimeoutMs": 300000,
        "toolFilter": { "include": ["balance", "quote_payment", "pay", "history", "channels", "xbt402_pay"] }
      }
    }
  }
}
```

The same with OpenClaw's CLI:

```bash
openclaw mcp add xbt-agent-wallet --command /home/you/.local/bin/xbt-wallet-mcp --env B2_SIGNER_SOCK=/home/you/wallet/.run/signer.sock
openclaw mcp probe xbt-agent-wallet --json     # 6 tools
```

Over HTTP: `{"url": "http://127.0.0.1:33510/mcp", "transport": "streamable-http"}`.

### Streamable HTTP

```bash
XBT_MCP_HTTP_TOKEN=$(head -c 32 /dev/urandom | base64) B2_SIGNER_SOCK=~/wallet/.run/signer.sock \
  xbt-wallet-mcp --http 127.0.0.1:33510 [--path /mcp]
```

The endpoint takes one JSON-RPC message per POST.

- `initialize` returns an `Mcp-Session-Id`; later requests must carry it (400 without it, 404 for an
  unknown one).
- Requests get `application/json` answers; notifications get 202.
- GET is 405, because the server never pushes, and DELETE ends a session.
- A request whose `Origin` is not loopback or in `XBT_MCP_ALLOWED_ORIGINS` is refused with 403 (DNS
  rebinding), with or without `--http-allow-remote`. There is no same-origin exception: a rebound page
  has Origin equal to Host.
- Every request needs `Authorization: Bearer <token>` (AGP-063 X1). The token is
  `XBT_MCP_HTTP_TOKEN`, the token file, the data dir's `mcp-http-token` secret, or, with none of
  those, `<signer socket dir>/mcp-http-token`, generated 0600 on first run.

The server listens on loopback only. `--http-allow-remote` lifts that; a non-loopback listener with no
token is refused at start.

## Who pays

The signer does: `xbt402_pay`, `pay` and `ln_pay` are forwarded to its socket, and every key, every
policy check and every booking is there. `XBT_MCP_PAYER=signer` (or unset) says the same. The other
value it took, `local`, ran the on-chain channel's payer inside this process; it went with the
channel, and a start that still sets it is refused with the reason.

## Tests and conformance

```bash
cargo test -j2 -p xbt-wallet-mcp        # validation, JSON, sanitizer, both transports, the example policy
python3 scripts/mcp/mcp_conformance.py --py PYTHON_WITH_MCP_SDK --b2 PY_WALLET_CHECKOUT \
  --rust target/debug/xbt-wallet-mcp    # the protocol and every tool both wallets have vs B2's server, 0 diffs
python3 scripts/mcp/http_sdk_check.py --py PYTHON_WITH_MCP_SDK --b2 PY_WALLET_CHECKOUT \
  --rust target/release/xbt-wallet-mcp  # the official Python SDK over streamable HTTP vs B2 over stdio
scripts/mcp/verify_agp030.sh            # all of it, then an agent's xbt402_pay over tickets on regtest
scripts/mcp/build_targets.sh            # every AGP-031 target -> dist/MCP_TARGETS.md
```
