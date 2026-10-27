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
| node-keys | xbt-wallet-ui | root | run/ln; Lightning Fork's public/ and apps/ (ro) | watches for the grant |
| witness | xbt-anchor-witness | xbt-anchor-witness | witness, run/anchor | `xbt-anchor-witness healthcheck` |
| signer | xbt-signer, under xbt-supervise | xbt-signer | signer, run/signer, run/anchor (ro), run/ln (ro), run/enroll; public/ (ro) | `xbt-signer healthcheck` |
| mcp | xbt-wallet-mcp | xbt-wallet-mcp | mcp, run/signer (ro), run/ui (ro) | port 33510 |
| ui | xbt-wallet-ui | xbt-wallet-ui | ui, run/signer (ro), run/ui, run/ln, run/gateway, run/hashrate, run/enroll (ro); public/ (ro) | port 8482 |
| connector | lightning-stream | xbt-signer | run/signer (ro), run/signer/streams | port 8484 (loopback) |
| gateway | xbt-gateway, under xbt-supervise | xbt-gateway | gateway, run/gateway (ro); public/ (ro) | its health, or idle until a shop is saved (healthy) |
| hashmaker | xbt-hashlink | xbt-hashrate | hashrate, run/hashrate (ro) | `xbt-hashlink healthcheck` |
| hashtaker | xbt-hashlink | xbt-hashrate | hashrate, run/hashrate (ro), run/signer (ro) | none |

**The node's keys.** On first start the package asks Lightning Fork for the wallet's key with a task (its
`grant-app-access` action, `LF_GRANT` in spec.ts; Lightning Fork 0.21.4-beta.21.1:2 or later). The owner approves
it in Lightning Fork, which bakes a macaroon with exactly the wallet's permissions (info:read, offchain:read,
offchain:write, onchain:read) under a root key of its own and keeps it in `apps/lightning-stream/access.macaroon`.
node-keys watches that folder (the whole `apps`, read-only), copies the key into run/ln, takes a new one when the
owner grants again, and removes it when the owner revokes it (the Your node page says so). That key can pay, so
it is never given to the gateway; the shop's keys (invoices only) are pasted on the Sell page until Lightning
Fork grants a second key per package. No admin macaroon is mounted or read, and a key the owner pasted is never
replaced.

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

## Actions

| action | what |
|---|---|
| node-config | node RPC host, port, user, password, chain (a critical task until set) |
| ui-setup-code | the UI's one-time setup code (`main/ui/setup-code`), while no password is set |
| agent-connection | the MCP addresses and the bearer token (`main/run/ui/mcp-http-token`) |
| rotate-agent-token | delete the MCP token and restart: xbt-init makes a new one. The web UI Agents page rotates it with no restart (the UI owns the token; the MCP only reads it). |
| reset-ui-password | delete `main/ui/password.scrypt` and restart |

## Build

`../build.sh` (the pinned images, start-cli 2.1.0 and the `../tools/tar2sqfs` shim) writes
`dist/startos/lightning-stream_{x86_64,aarch64}.s9pk`. Publishing to a registry is a separate step
(`docs/STARTOS.md`); never `make publish`.
