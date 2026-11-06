# Lightning Stream for StartOS

Technical reference for this package: the whole app in one package, as the Umbrel app is. The user guide is
`instructions.md` (and `docs/STARTOS.md`); the design, the tests and the choices are in `../../README.md` and
`../../DESIGN.md`, and the container standard in `docs/CONTAINER.md`.

## Containers

`startos/spec.ts` lists them as data; `startos/main.ts` turns that into StartOS daemons, and
`../test/startos_regtest.py` runs the same spec on Docker. Volume `main` is the data dir (docs/CONTAINER.md §1);
volume `startos` holds `store.json` (the node connection) and is mounted by nothing. A package's services
share one network namespace, so they reach each other on 127.0.0.1.

| daemon | image | user | mounts of `main` | ready |
|---|---|---|---|---|
| init (oneshot) | xbt-init | root | all | exits 0 |
| node-keys | xbt-wallet-ui | root | run/ln; Lightning Fork's public/ and apps/ (ro), only where it has the grant action | watches for the grant; idle (no command) without it |
| witness | xbt-anchor-witness | xbt-anchor-witness | witness, run/anchor | `xbt-anchor-witness healthcheck` |
| signer | xbt-signer, under xbt-supervise | xbt-signer | signer, run/signer, run/anchor (ro), run/ln (ro), run/enroll; public/ (ro) | `xbt-signer healthcheck` |
| mcp | xbt-wallet-mcp | xbt-wallet-mcp | mcp, run/signer (ro), run/ui (ro) | port 33510 |
| ui | xbt-wallet-ui | xbt-wallet-ui | ui, run/signer (ro), run/ui, run/ln, run/gateway, run/hashrate, run/enroll (ro); public/ (ro) | port 8482 |
| connector | lightning-stream | xbt-signer | run/signer (ro), run/signer/streams | port 8484 (loopback) |
| gateway | xbt-gateway, under xbt-supervise | xbt-gateway | gateway, run/gateway (ro); public/ (ro) | its health, or idle until a shop is saved (healthy) |
| hashmaker | xbt-hashlink | xbt-hashrate | hashrate, run/hashrate (ro) | `xbt-hashlink healthcheck` |
| hashtaker | xbt-hashlink | xbt-hashrate | hashrate, run/hashrate (ro), run/signer (ro) | none |

**The node's keys.** Where Lightning Fork has the `grant-app-access` action (`LF_GRANT` in spec.ts), the package
asks it for the wallet's key with a task. The owner approves it in Lightning Fork, which bakes a macaroon with
exactly the wallet's permissions (info:read, offchain:read, offchain:write, onchain:read) under a root key of its
own and keeps it in `apps/lightning-stream/access.macaroon`. node-keys watches that folder (the whole `apps`,
read-only), copies the key into run/ln, takes a new one when the owner grants again, and removes it when the
owner revokes it (the Your node page says so). That key can pay, so it is never given to the gateway; the shop's
keys (invoices only) are pasted on the Sell page until Lightning Fork grants a second key per package.

Not every Lightning Fork has the action, and its version does not tell: it is on Paul's `app-grants` pre-releases
(0.21.4-beta.21.1:2 and :4), not on the mainline releases after them (0.21.4-beta.21.1:3 to 0.21.6-beta.23:0). So
`grant.ts` asks the OS for the action itself (its input: the OS looks it up in Lightning Fork's list of actions
first and says "Not Found" without it), in init and in main, again when Lightning Fork restarts or is updated.
Without it the package makes no task (and clears one made before), mounts nothing of `apps` (a missing mount
source failed node-keys at every start in 0.2.14), runs no command in node-keys, and sets
`XBT_UI_LN_CONNECT_ADDRESS`: the Your node page then walks the owner through copying Lightning Fork's *REST LND
Connect* address in StartOS and pasting it. The UI uses the full-access key in that address once, in memory, to
have the node bake the wallet's key and the shop's (invoices, info, and SignMessage where the node bakes it), each
under a root key of its own, and keeps neither. main.ts also mounts `apps` before it starts node-keys, so a mount
that fails anyway makes the package run as without the grant. The dependency range (`LIGHTNING.minVersion`) asks
only for public/ (the certificate), never for the grant. No admin macaroon is mounted or kept, and a key the owner
pasted is never replaced by a grant.

Health checks: `wallet-ready` (the MCP's `/readyz`: 200 synced and unlocked; 503 loading, with the reason), and
the shop (healthy while it is not selling yet).

## Interfaces

| id | what | port |
|---|---|---|
| `ui` | the web interface | 8482, external 80 |
| `mcp` | agents' MCP server (path `/mcp`, masked) | 33510 |
| `gateway` | buyers reach the shop here; add a public domain to sell beyond the LAN (TLS by StartOS, http/1.1) | 8402, external 443 |
| `miners` | Stratum, for the miners rented out (LAN) | 23340, plain TCP |
| `link` | hashtakers' apps (Noise-encrypted; a port forward or a tunnel makes it public) | 23341, plain TCP |

StartOS terminates TLS and adds X-Forwarded-Proto, so the UI's cookie is `Secure` over https.

Links for the buyer's own player (`/r/<token>`, made on a Files page) stay on the `ui` interface: StartOS
puts no login of its own in front of a package's interface (umbrelOS does, hence Umbrel's port 33541), and
the UI lets a link through on its token alone, so no `XBT_UI_LINKS_BIND` port is needed here.

## Actions

| action | what |
|---|---|
| node-config | node RPC host, port, user, password, chain (a critical task until set). With Knots BLAKE2b installed and no node set, it offers `knots-blake2b.startos` and port 18443; the user and password come from Knots BLAKE2b's *Generate RPC User Credentials* action |
| ui-setup-code | the UI's one-time setup code (`main/ui/setup-code`), while no password is set |
| agent-connection | the MCP addresses and the bearer token (`main/run/ui/mcp-http-token`) |
| rotate-agent-token | delete the MCP token and restart: xbt-init makes a new one. The web UI Agents page rotates it with no restart (the UI owns the token; the MCP only reads it). |
| reset-ui-password | delete `main/ui/password.scrypt` and restart |

## Build

`../build.sh` (the pinned images, start-cli 2.1.0 and the `../tools/tar2sqfs` shim) writes
`dist/startos/lightning-stream_{x86_64,aarch64}.s9pk`. Publishing to a registry is a separate step
(`docs/STARTOS.md`); never `make publish`.

Installing from our registry (or by sideload), StartOS says *This service package isn't signed by anyone you
trust* and asks *Install untrusted software?*: that is every package from a registry other than Start9's; choose
*Install anyway*.
