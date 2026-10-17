# Lightning Stream Gateway for StartOS

Technical reference for this package. The user guide is `instructions.md`; the design is
`../../DESIGN.md`, the tests `../../README.md`, and the container standard `docs/CONTAINER.md`.

## Containers

`startos/spec.ts` lists them as data; `startos/main.ts` turns that into StartOS daemons, and
`../test/startos_regtest.py` runs the same spec on Docker. Volume `main` is the data dir.

| daemon | image | user | mounts | ready |
|---|---|---|---|---|
| init (oneshot) | xbt-init | root | all of `main` | exits 0 |
| ui | xbt-wallet-ui (`XBT_UI_ROLE=gateway`) | xbt-wallet-ui | ui, run/ui, run/gateway; Lightning Fork's tls.cert (ro) | port 8481 |
| gateway | xbt-gateway, under xbt-supervise | xbt-gateway | gateway, run/gateway (ro); Lightning Fork's tls.cert (ro) | `/x402/ticket/health` on 8402 |

The gateway starts once the setup page has written `run/gateway/config.json`, and again when the config, a
macaroon or the certificate changes. It reaches Lightning Fork's REST listener at Lightning Fork's container
address (port 8080), which its certificate names, and pins that certificate.

## Interfaces

`ui` (the setup page, port 8481, external 80) and `gateway` (an API, port 8402; StartOS adds TLS and
X-Forwarded-For). Both are LAN-only until the owner adds a public domain to `gateway`.

## Actions

| action | what |
|---|---|
| Setup page code | the one-time code the setup page asks for before its password is chosen |
| Reset the setup page password | forget the password hash; the service restarts and a new code is made |
