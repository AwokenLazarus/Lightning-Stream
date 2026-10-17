# Packages for node runners: design

A node runner with an Umbrel or StartOS box and an XBT Lightning node on it installs Lightning
Stream and can **buy** (the agent wallet pays sellers with stream tickets) and **sell** (a gateway
in front of a service of theirs takes stream tickets). Everything here is side-load only and has
been run on regtest only. This note says how the packages reach the box's Lightning node, what the
owner is asked, how buyers reach a seller, what mainnet takes, and what cannot be done yet.
`README.md` beside it is how to build and test them.

## 1. The Lightning node on each box

The XBT chain has one Lightning node app per platform, both from the Lightning Fork project (an lnd
fork for the BLAKE2b chain). No other XBT Lightning node is packaged for either platform.

| | Umbrel | StartOS 0.4 |
|---|---|---|
| Lightning node app | `paulscode-lightning-fork`, in its author's community store | `lightning-fork` |
| XBT chain node it uses | the `bitcoin` slot, filled by `paulscode-knots-blake2b` (`APP_BITCOIN_*`) | `knots-blake2b` (or a Knots on the BLAKE2b chain) |
| Its REST address for a dependent | `https://$APP_LIGHTNING_FORK_NODE_IP:$APP_LIGHTNING_FORK_NODE_REST_PORT` (exported) | `https://<its container address>:8080` (`getContainerIp`) |
| Its `tls.cert` | `$APP_LIGHTNING_FORK_NODE_DATA_DIR/tls.cert` | `tls.cert` at the root of its `main` volume |
| A narrow macaroon | its dashboard's **Macaroons** menu: chosen permissions, own root key, shown once, revocable alone | the same dashboard |

Both Lightning Fork packages are mainnet only: on a real box the packages here are on mainnet,
which is why section 5 makes mainnet a separate, deliberate step.

**Credentials.** Neither package ever holds an admin macaroon. The package mounts exactly one file
of the Lightning node's, `tls.cert`, read-only (Umbrel: a single-file bind mount that refuses to
create a missing path; StartOS: `mountDependency` with `type: 'file'`, which StartOS 0.4 refuses: see
section 6), and pins it. The owner bakes
the macaroons in Lightning Fork's own dashboard and pastes them (hex) into this package's setup page:

| for | permissions | file in the package's data |
|---|---|---|
| the wallet's rail | `info:read offchain:read offchain:write onchain:read` | `run/ln/rail.macaroon` |
| the gateway, invoices | `invoices:read invoices:write` | `run/gateway/invoices.macaroon` |
| the gateway, height | `info:read` | `run/gateway/info.macaroon` |

The wallet refuses on mainnet any rail macaroon that grants more than its four permissions; the
gateway does the same for its two. The easy route other apps take (mounting the node's data dir and
reading `admin.macaroon`) is not taken: it would put a credential that can spend everything into a
web-facing package for good. The cost is one manual step per macaroon. The smallest thing that would
remove it is a "grant a macaroon to an app" call in the Lightning node app (bake with a given
permission list on the dependent's behalf, write it into the dependent's data), which neither
platform's package offers today.

The REST address and the certificate path come from the platform; the owner never types them.

## 2. Two apps: the wallet and the gateway

| | Wallet (`lazarus-xbt-agent-wallet`, `xbt-agent-wallet`) | Gateway (`lazarus-lightning-stream-gateway`, `lightning-stream-gateway`) |
|---|---|---|
| does | the agent pays sellers (MCP for agents, a policy the owner signs) | sells a service of the owner's per piece |
| containers | init, witness, signer, MCP, UI | init, gateway, UI (gateway setup) |
| needs | the XBT chain node (funding proofs) and the Lightning node | the Lightning node only |
| macaroons | the rail's one | invoices, info |
| reached by | the owner (UI), agents on the LAN (MCP, bearer token) | the owner (UI); buyers through an https proxy |

Two apps rather than one: a buyer and a seller are different people with different risks, neither
needs the other, and each app then holds only its own macaroons (the gateway's cannot pay; the
wallet's cannot make invoices). Both use the same image set and the same data dir layout
(`docs/CONTAINER.md`).

**Setup pages (no terminal).** Both are pages of the existing web UI binary (`xbt-wallet-ui`); the
gateway app runs it with `XBT_UI_ROLE=gateway`.

- Wallet, **Lightning** page: shows the node's REST address and certificate the platform gave, and
  the rail's state from the signer; asks for the rail macaroon (hex). On mainnet it also asks for the
  acknowledgement of section 5. The policy page's starter template turns the Lightning rail and
  tickets on, with low caps. Sellers go on the allowlist with their node id (an existing policy field).
- Gateway, **Gateway** page: the service to sell (`http://host:port` on the box's network), the https
  origin buyers use, one price (per request, per MiB, or per second, in msat), the two macaroons, and
  the caps (low defaults). It checks the config with the gateway's own parser before it saves it, and
  shows the gateway's health.

A change applies without a restart by hand: `xbt-supervise` (a small process in the signer's and the
gateway's containers) restarts its child when a file it watches changes, and starts the gateway only
once its config exists.

## 3. How buyers reach a gateway

The wallet pays tickets only over https, or over plain http to its own machine (127.0.0.1, ::1,
localhost): on a plain connection a listener would learn the session key. It trusts only public
certificate authorities (the Mozilla roots built into it). The gateway enforces the same from the
other side: it refuses to listen on a non-loopback address unless `public_url` is an https origin.
So a seller needs an https name with a publicly trusted certificate in front of the gateway.

- **StartOS:** the gateway's buyer interface is a StartOS interface; the owner adds a public domain
  to it (StartOS 0.4 issues the certificate with ACME through a gateway or a port forward) and types
  that origin as the public URL. LAN-only by default; nothing is public until the owner does this.
- **Umbrel:** umbrelOS gives apps no https of their own. The owner points a TLS proxy they already
  run (a reverse-proxy app with Let's Encrypt, or a tunnel app) at
  `lazarus-lightning-stream-gateway_gateway_1:8402` on the box network. The package publishes no host
  port for buyers.
- **Tor:** both platforms can give the gateway an onion address, but it is plain http, so this
  wallet does not pay a seller there. Allowing http to `.onion` hosts (which Tor already encrypts and
  authenticates) is a change to the wallet, not to the packages.

Behind a proxy every buyer arrives from the proxy's address, so the page offers the proxy's address
as the one whose `X-Forwarded-For` the gateway believes (`http.forwarded_address`); without it the
per-address session cap is turned off and the total cap is the only bound.

## 4. What the owner is asked

Wallet: the UI password (Umbrel: the dashboard's; StartOS: a setup code), an approval key, a signed
policy (the template turns the rail on), the rail macaroon. Agents connect with the MCP endpoint and
token from the Agents page, as before.

Gateway: the UI password, the service, the public https origin (and the proxy's address), a price,
the two macaroons, and on a test chain its network id.

## 5. Mainnet: off by default, asked for, capped low

Off by default on both sides: the gateway config the page writes says `"chain": "regtest"` unless
the owner picks mainnet, and the wallet's Lightning page refuses to store a rail macaroon while the
signer's chain is `main` unless the owner types the acknowledgement.

- **Gateway:** choosing mainnet shows the gateway's own warning (the text it prints at every start)
  and needs the acknowledgement typed exactly (`mainnet_ack`); the page then writes low caps
  (4 sessions, 1 per address, 4 held tickets of 1,000 sat, 2 per session), which the owner can raise.
- **Wallet:** the page shows the same kind of warning; the starter policy on mainnet caps a payment
  at 2,000 sat and a day at 10,000. The acknowledgement is stored as `run/ln/mainnet-ack`, and both
  packages point the signer at it (`B2_MAINNET_ACK_FILE`): on mainnet the signer refuses tickets
  and draws without it, whatever the page did.

## 6. What cannot be done yet

- **Real boxes, regtest only.** On a real umbrelOS 2.0 box both apps installed from a community store
  through the dashboard's API, beside regtest stand-ins with the ids and export names of Paul's apps in
  a second store (`paulscode`): the dependency on `paulscode-lightning-fork` across stores and the
  `bitcoin` slot resolve as designed, and the wallet bought from the gateway with a ticket, again after
  a restart and a reboot. Paul's packages themselves were not run (they follow mainnet only).
- **StartOS mounts a dependency's directory, never one file.** StartOS 0.4 refuses file mounts of a
  dependency's volume (start-sdk 3.0 removed the option), so the single-file mount of Lightning Fork's
  `tls.cert` fails ("mount exited with exit status: 32") and neither package starts while Lightning
  Fork is installed. Lightning Fork keeps `tls.cert` at the root of its `main` volume, beside its
  macaroons and wallet, so mounting that directory would hand the packages the admin macaroon. A test
  profile with the certificate alone in a sub-directory, mounted as a directory, ran: the Lightning
  page showed the container address and the pinned certificate, and the rail was ready. The fix is
  Lightning Fork's (the certificate in a directory of its own) or a copy made at start; not decided.
- **One box cannot buy from itself, except through loopback.** On Umbrel the test profile puts the
  wallet's signer in the gateway's network namespace, as the off-box tests do. On StartOS each package
  is its own container and there is one Lightning node, so a buy needs a second box.
- **The certificate is read at start.** When StartOS reissues Lightning Fork's certificate (its
  container address changed), the pin fails until the watched file changes and the child restarts;
  the supervisor does that, but it was not exercised on StartOS.
- **No https on Umbrel without the owner's own proxy**, and no paying `.onion` sellers (section 3).
- **The Umbrel stand-in node** (`lazarus-xbt-knots`, amd64 only) stays in the store as a fallback;
  the wallet now takes the `bitcoin` slot first, which Paul's `paulscode-knots-blake2b` fills.
- **StartOS's XBT chain node** is still an external connection for the wallet (the Node connection
  action). Declaring `knots-blake2b` as Lightning Fork does is the next step.
- **Pi:** the images exist for arm64 and arm/v7 and the size and memory figures are from an x86_64
  host only. The Pi floor was not measured.

## 7. Choices for what is new and ships

| thing | chosen | against | why |
|---|---|---|---|
| gateway image | the static musl binary `FROM scratch`, as every other image | distroless, alpine | no shell or libc to patch, a few MB, one base layer shared by all images; arm images need no emulator |
| restart on a changed file | `xbt-supervise`, Rust (std and `libc`, already a dependency) | a shell loop (needs a shell in the image), tini or s6 (third-party, and neither watches files) | keeps the images shell-free; about 100 lines |
| setup pages | the existing UI binary, a role switch | a separate web app (Node, or a second Rust UI) | one login, one HTTP server, one hardening review; the gateway's own config parser checks the page's output |
| StartOS gateway package | TypeScript on start-sdk | none | the SDK is the platform's format |

The UI now depends on the workspace crate `xbt-gateway` (no new third-party crate): with it the
page validates a config exactly as the gateway will, and reads the gateway's mainnet warning from the
gateway itself instead of a copy.

## 8. Licences (flagged, not resolved)

- **umbrelOS** is under the PolyForm Noncommercial License 1.0.0. These apps are MIT or Apache-2.0
  and do not include umbrelOS code, but a node runner selling a service through the gateway on an
  Umbrel box is plausibly commercial use of umbrelOS, and any commercial offering built on Umbrel
  (a hosted box, a paid app listing) needs umbrelOS's terms read by someone who can decide. Umbrel's
  App Store has its own submission terms, not read here.
- **StartOS** is MIT; Lightning Fork's StartOS package is MIT. Lightning Fork's Umbrel app is forked
  from Umbrel's own Lightning app; its licence was not checked here.
