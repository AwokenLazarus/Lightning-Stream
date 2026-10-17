# The wallet and the gateway on Umbrel and StartOS

Side-load packages for node runners, built on the container standard in `docs/CONTAINER.md` and the one
image set `scripts/oci_build.sh` makes:

- **XBT Agent Wallet** (buy): the signer, the anchor witness, the MCP server for agents and the web UI. It
  pays sellers with stream tickets through the box's Lightning Fork node.
- **Lightning Stream Gateway** (sell): the seller gateway in front of a service of the owner's, taking
  stream tickets on the box's Lightning Fork node, and its setup page.

How they reach the Lightning node, what the owner is asked, how buyers reach a gateway, mainnet and what
cannot be done yet: `DESIGN.md`. **Local only:** nothing is pushed to a registry, and nothing is submitted
to the Umbrel App Store or the Start9 marketplace. That submission is the project owner's decision. Both
have run on regtest only. On a real umbrelOS 2.0 box both installed from a community store and the wallet
bought from the gateway with a ticket (`umbrel/realbox/`); on a real StartOS 0.4 server neither starts
beside Lightning Fork yet (below, and `DESIGN.md` section 6).

The hub was retired on 2026-10-11: payments between parties route over ordinary Lightning instead. Its
code is in the git history (last at commit 0911cc0). Its Umbrel app, its StartOS toggle and its tests are
gone from here.

```
packaging/
  DESIGN.md                   the design: the Lightning node, credentials, two apps, buyers, mainnet, limits
  regtest_lib.py              helpers shared by the drivers, among them the paid buy over tickets
  ln_lab.py, ln_lab.compose.yml   the Lightning side of the tests: two Lightning Fork nodes of the regtest lab
  umbrel/                     a local Umbrel community store (id "lazarus")
    umbrel-app-store.yml
    lazarus-xbt-agent-wallet/ the wallet: init + witness + signer + MCP + UI, app_proxy -> UI
    lazarus-lightning-stream-gateway/  the gateway: init + gateway + UI (gateway role), app_proxy -> UI
    lazarus-xbt-knots/        a stand-in XBT node (pruned Knots 29.4.2, amd64 only) that fills the bitcoin slot
    lint.py                   manifest + compose + hardening lint
    regtest/                  the off-Umbrel overlays and the driver (umbrel_regtest.py)
    test-umbrel-apps.sh       verify: lint, then install both apps from cold beside the lab and buy, twice
    bundle.sh                 side-load bundle: the store + docker-saved images (dist/umbrel/)
  startos/
    xbt-agent-wallet/         the wallet package (start-sdk 2.0.9, TypeScript); startos/spec.ts is its containers as data
    lightning-stream-gateway/ the gateway package, the same way
    build.sh                  tsc + the SDK's eslint + ncc + `start-cli s9pk pack` -> dist/startos/*_{x86_64,aarch64}.s9pk
    tools/tar2sqfs            a shim over mksquashfs -tar (pack needs tar2sqfs; this host has squashfs-tools)
    test/startos_regtest.py   both packages' own containers beside the lab, StartOS-shaped, with the paid buy
    test-startos.sh           verify: build, inspect the four .s9pk, then the regtest run
```

## Build and verify

```bash
scripts/oci_build.sh --load                # the seven images for amd64, arm64, arm/v7, loaded as <image>:0.1.0
scripts/container_test.sh --skip-build     # the images by env and data dir, with the paid buy (ports 23700-23799)
packaging/umbrel/test-umbrel-apps.sh       # RESULT PASS: lint + 2 cold regtest runs with the paid buy (ports 24000-24099)
packaging/startos/test-startos.sh          # RESULT PASS: build + inspect + regtest run with the paid buy (ports 24100-24199)
```

The three tests bring up the Lightning lab of `scripts/ln_rail_regtest.sh` (`scripts/ln_rail/lab.sh`, cloned
and built under `run/` when missing), each in its own compose project. In every one the buyer reaches the
seller on loopback: the wallet's signer shares the gateway's network namespace. That is the tests' one
departure from the packages, and the reason is the wallet's own rule: it pays tickets over https, or over
plain http to its own machine only, and trusts only public certificate authorities; a regtest has no https
name with such a certificate. On boxes the buyer and the seller are two machines and the buyer reaches the
seller's https origin.

The StartOS build needs `start-cli` 2.1.0 (`START_CLI`, by default `~/.local/opt/start-cli/start-cli`; from the
start-technologies releases) and a packaging workspace outside the repo (`~/.local/share/xbt-startos-ws`; its `.startos/` holds
the key that signs the package, so it is never committed).

## What the apps do on a box

Both platforms run the same containers, from the same images. The wallet:

| container | image (user) | mounts (sub-dirs of the data dir) | network |
|---|---|---|---|
| init (one-shot) | `xbt-init` (root, CHOWN/FOWNER/DAC_OVERRIDE only) | the whole data dir | none |
| witness | `xbt-anchor-witness` (10002) | `witness/`, `run/anchor/` | none on Umbrel |
| signer | `xbt-signer` (10001), under `xbt-supervise` | `signer/`, `run/signer/`, `run/anchor/` ro, `run/ln/` ro, Lightning Fork's `tls.cert` ro | the node's RPC, Lightning Fork's REST |
| MCP | `xbt-wallet-mcp` (10003) | `mcp/`, `run/signer/` ro, `run/ui/` ro | 33510, bearer token |
| UI | `xbt-wallet-ui` (10005) | `ui/`, `run/signer/` ro, `run/ui/`, `run/ln/`, `tls.cert` ro | 8480 behind the box's proxy |

The gateway:

| container | image (user) | mounts | network |
|---|---|---|---|
| init (one-shot) | `xbt-init` (root) | the whole data dir | none |
| gateway | `xbt-gateway` (10007), under `xbt-supervise` | `gateway/`, `run/gateway/` ro, `tls.cert` ro | Lightning Fork's REST; 8402 for buyers, through an https proxy |
| UI | `xbt-wallet-ui` (10005), `XBT_UI_ROLE=gateway` | `ui/`, `run/ui/`, `run/gateway/`, `tls.cert` ro | 8481 behind the box's proxy |

The UI writes `run/ln/rail.macaroon` (group `xbt-ln-rail`: the signer and the UI, never the MCP) and
`run/gateway/{config.json, invoices.macaroon, info.macaroon}` (group `xbt-gateway`), each 0640.
`xbt-supervise` restarts the signer when the rail macaroon or the certificate changes, and starts the
gateway once its config exists and again when it or a macaroon changes. The Lightning node's REST address
comes from the platform (Umbrel: Lightning Fork's exports; StartOS: its container address); the owner
types only the macaroons, baked in Lightning Fork's dashboard. No admin macaroon is mounted or kept.

`init` gives each sub-dir to its uid (Umbrel bind mounts arrive owned by uid 1000, StartOS volumes owned by
root), writes the node credentials, and makes the MCP token once, as the UI's `run/ui/mcp-http-token`
(0640; the MCP reads it by group and never writes it). The owner reads it on the UI's **Agents** page. That page is how a box with no terminal
connects an agent. The owner never needs a shell:

- **Umbrel:** log in with the password the dashboard shows (`${APP_PASSWORD}`, `deterministicPassword`).
  Then Setup: enrol the approval key (it stays in the browser; the signer's one-time enrolment code is in
  the app's log) and sign a policy (the starter template turns Lightning and tickets on with low caps).
  Then Lightning: paste the rail macaroon. Then Agents: copy the MCP endpoint
  `http://umbrel.local:33510/mcp` and the token. If the token leaks, rotate it on that same page (no
  terminal, no restart). The gateway app: log in the same way and fill in its one page.
- **StartOS:** run the *Node connection* action (a critical task until done). Start the service. *Web UI
  setup code* gives the one-time code; in the UI, choose a password (only its scrypt hash is kept). Then
  the same Setup, Lightning and Agents steps; *Agent connection* also shows the MCP addresses and token. The
  UI and the MCP are StartOS interfaces, on the LAN by default; the owner can add a Tor address to either.
  The gateway package: *Setup page code*, then its one page; to sell beyond the LAN, a public domain on its
  *Gateway for buyers* interface.

### Readiness and health

- **Umbrel:** each container has its image's HEALTHCHECK (liveness).
- **StartOS:** each daemon's `ready` is its port listening, or the image's own `healthcheck` subcommand
  for the socket-only witness and signer. A `wallet-ready` health check reads the MCP's `/readyz`: success
  when the node is synced and the keys are unlocked, otherwise "loading" with the reason (node not
  reachable, syncing, witness down).

### Backups

- **StartOS:** backs up the `main` volume (sealed keys and their wrapping key, anchors, ledgers, the ticket book,
  the UI's hash) and `startos` (the node connection). The backup is encrypted with the server's master
  password. After a restore, `init` puts the owners back.
- **Umbrel:** backs up `${APP_DATA_DIR}` the same way.
- **The wallet's own export:** the encrypted backup on the UI's Keys page, signed by the human, is still
  the portable one.

## Choices and comparisons (the stack rule)

**Bind-mount owners: an init one-shot (chosen)**, one uid for everything, an umbrelOS pre-start hook, or
named volumes. See `docs/CONTAINER.md` §8. Only the init one-shot keeps the witness/signer/MCP/UI
separation on both platforms (Umbrel bind mounts, StartOS root-owned volumes) and after a restore. It is
also the only one that runs identically in plain compose. Its language is Rust: a 0.5 MB static binary
sharing the uid table with the services, `FROM scratch`, on all three architectures.

**Node dependency.**

| option | chosen? | why |
|---|---|---|
| depend on the `bitcoin` slot, falling back to this store's stand-in (`APP_BITCOIN_*`, else `APP_XBT_KNOTS_*`) | yes, Umbrel | the node Lightning Fork already uses: one node per box, no second sync |
| bundle a node in the wallet app | no | a second node on a box that runs one |
| a light client in place of a node | no | this tree has none, and the rail's funding proof reads the chain |

On Umbrel the slot is filled by Paul's `paulscode-knots-blake2b` (the node Lightning Fork depends on), or
by the stand-in `lazarus-xbt-knots`, which reuses `xbt-a3-knots:29.4.2` and is **amd64-only**. StartOS has
no XBT node dependency in this package yet: the node is an external connection (the *Node connection*
action). Declaring `knots-blake2b`, as Lightning Fork does, is the next step.

**Lightning dependency.** Lightning Fork, the only XBT Lightning node packaged for either platform:
`paulscode-lightning-fork` (another community store; umbrelOS resolves dependencies by installed app id)
and `lightning-fork` on StartOS. Only its `tls.cert` is mounted; the macaroons are the owner's, pasted
(`DESIGN.md`, section 1).

**UI login.**

| platform | chosen | why |
|---|---|---|
| Umbrel | `${APP_PASSWORD}`, provisioned as a file by `init` | the password the dashboard already shows, behind Umbrel's own login at `app_proxy` |
| StartOS | the UI's own first-run setup code, shown by an action; the owner then chooses the password | only the scrypt hash is stored, as the StartOS recipe asks for app logins |

On StartOS, a generated password returned by an action was the alternative. It would keep a cleartext
password on a volume. The OS proxy's basic auth would also lock out the MCP's bearer clients if it were
applied there.

**Testing without the platforms.**

- **Umbrel:** umbrelOS's dev environment needs privileged Docker, not rootless, so `test-umbrel-apps.sh`
  reproduces umbrelOS's install instead:
  - the app folder is copied into `app-data/<id>` as the box user;
  - `docker compose --compatibility -p <id>` gives the `<id>_<service>_1` names;
  - one shared network;
  - `exports.sh` is sourced with a `derive_entropy`;
  - `${APP_PASSWORD}` and `${APP_SEED}` are set;
  - a reverse proxy adds X-Forwarded-*.
- **StartOS:** needs a VM (no KVM for this user). `test-startos.sh` builds and inspects the real `.s9pk`
  files, then runs each package's own container spec (`startos/spec.ts`, the data `main.ts` uses) on
  Docker as StartOS runs it:
  - one root-owned volume per package, mounted by sub-path;
  - Lightning Fork's `tls.cert` as the one dependency file (a read-only bind of the lab node's);
  - one shared network namespace (here shared by both packages: the buyer reaches the seller on loopback);
  - init as a one-shot;
  - image users.
- **Lightning Fork** is played by the regtest lab's nodes (`ln_lab.py`), not by Paul's packages: lf1 is the
  wallet's box's node, lf2 the gateway's.
- **Real boxes:** `umbrel/realbox/realbox_umbrel.py` installs, sets up, buys with, restarts and removes both
  apps on a real umbrelOS 2.0 box through its own API, beside regtest stand-ins for Paul's apps (a second
  store, `paulscode`, with his app ids and export names); `startos/realbox/realbox_startos.py` does the same on
  a StartOS 0.4 server with a Lightning Fork stand-in. Both on a LAN test box, regtest only.

## Side-load (a pilot, when the project owner approves)

- **Umbrel:** `packaging/umbrel/bundle.sh` writes `dist/umbrel/`: the store folder, `images-amd64.tar`,
  `images-arm64.tar` and `SHA256SUMS`. See its README.txt. umbrelOS 2.0 pulls every image of an app when it
  installs it, so the images must be in a registry the box can pull from (`REGISTRY=host:port bundle.sh`
  names them by it); `docker load` alone ends in "pull access denied". It adds community stores by git URL
  (smart HTTP), and lists only apps whose id starts with the store's id.
- **StartOS:** in the StartOS UI, System → Sideload a service, with `dist/startos/xbt-agent-wallet_x86_64.s9pk`
  and/or `dist/startos/lightning-stream-gateway_x86_64.s9pk` (or `_aarch64`). The packages are signed with the
  workspace's developer key, not a Start9 registry key.

## Size and memory

Hardware: the floor is a Raspberry Pi 4 (arm64) running umbrelOS beside a pruned Knots node and Lightning
Fork; the top is an x86_64 server. Pass lines, set before measuring:

| what | pass line | how measured |
|---|---|---|
| each image, amd64, compressed | at most 10 MB | `dist/oci/IMAGES.md` (the OCI archive's layers) |
| the wallet app's images, amd64, compressed | at most 15 MB | the sum of init, witness, signer, MCP, UI |
| the gateway app's images, amd64, compressed | at most 6 MB | the sum of init, gateway, UI |
| the wallet app idle | at most 64 MiB | `docker stats --no-stream` memory of its four services, after the paid buy and 60 s idle |
| the gateway app idle | at most 32 MiB | the same for the gateway and its UI |

Measured on 2026-10-17 on the x86_64 build host (images of commit 37e844a; memory from the two cold Umbrel
runs of `test-umbrel-apps.sh`, which checks the lines itself):

| what | measured | pass |
|---|---|---|
| largest image, amd64, compressed | xbt-signer 4.16 MB (gateway 2.10 MB, UI 0.68 MB, MCP 0.52 MB, witness 0.38 MB, init 0.28 MB) | yes |
| the wallet app's images | 6.02 MB (arm64: 5.72 MB) | yes |
| the gateway app's images | 3.06 MB (arm64: 2.95 MB) | yes |
| the wallet app idle | 4.96 and 5.01 MiB (signer 1.9, UI 1.2, MCP 1.0, witness 0.9) | yes |
| the gateway app idle | 2.45 and 2.44 MiB (gateway 1.7, UI 0.8) | yes |

`docker stats` reports the cgroup's memory less its page cache. The `.s9pk` files: the wallet 6.9 MB (x86_64)
and 6.6 MB (aarch64), the gateway 4.0 MB and 3.9 MB. The Pi floor was not measured: no Pi was reached; the
arm64 and arm/v7 images were built and inspected only.

## What a packaged wallet and gateway can do, and cannot

They can, on regtest, with the images of this tree:

- the wallet pays a seller with stream tickets through the box's Lightning node, under the owner's signed
  policy: one `xbt402_pay` call of an agent buys a priced page from a packaged gateway, the seller's node
  settles the ticket, and a second call is paid from the ticket's balance. It still does after a restart of
  the app and (StartOS) after a backup is restored into a new install;
- the gateway sells a service of the owner's per request, per MiB or per second, set up on its page;
- neither holds an admin macaroon, and the wallet's MCP cannot read the rail macaroon.

They cannot, yet:

- start on StartOS beside Lightning Fork: StartOS mounts a dependency's directory only, never one file, and
  Lightning Fork keeps tls.cert at the root of its volume beside its macaroons (`DESIGN.md`, section 6);
- buy from a gateway on the same box, except through the test profile's shared loopback (Umbrel): the wallet
  pays tickets over https with a publicly trusted certificate, or to its own machine;
- be installed from a store by an outside tester on Umbrel until the images are in a registry the tester's box
  can pull from;
- reach a seller over Tor: an onion address is plain http, which the wallet does not pay tickets over;
- give a gateway https on Umbrel by themselves: the owner runs the TLS proxy;
- pay or sell on mainnet with anything but low caps and the owner's typed acknowledgement, and the wallet's
  acknowledgement is the page's alone until the signer reads it (`DESIGN.md`, section 5).

## Not done, and gaps

- Paul's Lightning Fork and Knots packages were read, not run: the real-box runs used regtest stand-ins with
  their ids, addresses, ports and export names. The StartOS build targets StartOS 0.4 (`osVersion`
  0.4.0-beta.10 in the manifest, start-sdk 2.0.9); the test server ran 0.4.0.1.
- The XBT node:
  - on Umbrel, the `bitcoin` slot (Paul's Knots BLAKE2b Companion, or the stand-in, **amd64-only**);
  - on StartOS, an external connection;
  - no light client: the wallet needs a node's RPC.
- The Pi floor: the arm64 and arm/v7 images were built and inspected, not run on a Pi.
- Token rotation: the wallet UI Agents page writes a new token into `run/ui/mcp-http-token`; the MCP reads
  it on every request, so the old token gets 401 at once. The MCP has no rotation endpoint (docs/CONTAINER.md
  §10). StartOS also keeps the delete-and-restart action.
- The StartOS package's text is English only; other locales fall back to it. Translations, gallery images
  and icons are store-submission work.
- The images are referenced by tag (`:0.1.0`). umbrelOS pulls them on install, so a store needs them in a
  registry, pinned by digest (`dist/oci/IMAGES.md` has the index digests); the real-box run used a registry on
  the build host's loopback, tunnelled to the box's.
