# XBT Agent Wallet for StartOS

Technical reference for this package. The user guide is `instructions.md`; the design, the tests
and the choices are in `../../README.md` and `../../DESIGN.md`, and the container standard in `docs/CONTAINER.md`.

## Containers

`startos/spec.ts` lists them as data; `startos/main.ts` turns that into StartOS daemons, and
`../test/startos_regtest.py` runs the same spec on Docker. Volume `main` is the data dir (docs/CONTAINER.md §1);
volume `startos` holds `store.json` (the node connection) and is mounted by nothing.

| daemon | image | user | mounts of `main` | ready |
|---|---|---|---|---|
| init (oneshot) | xbt-init | root | all | exits 0 |
| witness | xbt-anchor-witness | xbt-anchor-witness | witness, run/anchor | `xbt-anchor-witness healthcheck` |
| signer | xbt-signer, under xbt-supervise | xbt-signer | signer, run/signer, run/anchor (ro), run/ln (ro); Lightning Fork's tls.cert (ro) | `xbt-signer healthcheck` |
| mcp | xbt-wallet-mcp | xbt-wallet-mcp | mcp, run/signer (ro), run/ui (ro) | port 33510 |
| ui | xbt-wallet-ui | xbt-wallet-ui | ui, run/signer (ro), run/ui, run/ln; Lightning Fork's tls.cert (ro) | port 8480 |

The rail: Lightning Fork's REST listener at its container address (port 8080), its `tls.cert` pinned, and the
macaroon the owner pastes on the UI's Lightning page (`run/ln/rail.macaroon`). The signer restarts when that
file or the certificate changes.

Health check `wallet-ready`: the MCP's `/readyz` (200: synced and unlocked; 503: loading, with the reason).

## Interfaces

`ui` (web UI, port 8480, external 80), `mcp` (API, 33510, path `/mcp`, masked).
StartOS terminates TLS and adds X-Forwarded-Proto, so the UI's cookie is `Secure` over https.

## Actions

| action | what |
|---|---|
| node-config | node RPC host, port, user, password, chain (a critical task until set) |
| ui-setup-code | the UI's one-time setup code (`main/ui/setup-code`), while no password is set |
| agent-connection | the MCP addresses and the bearer token (`main/run/ui/mcp-http-token`) |
| rotate-agent-token | delete the MCP token and restart: xbt-init makes a new one. The web UI Agents page rotates it with no restart (the UI owns the token; the MCP only reads it). |
| reset-ui-password | delete `main/ui/password.scrypt` and restart |

## Build

`../build.sh` (needs the images loaded by `scripts/oci_build.sh --load`, start-cli 2.1.0 and the
`../tools/tar2sqfs` shim) writes `dist/startos/xbt-agent-wallet_{x86_64,aarch64}.s9pk`. Never `make publish`.
