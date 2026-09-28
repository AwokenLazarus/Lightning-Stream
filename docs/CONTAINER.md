# Containers: the data dir, secrets, health and images (AGP-038)

Umbrel and StartOS (Start9) run our services as containers. This page is the **shared standard** for
xbt-agentpay and xbt-compute (cmp CONTRACT §U). cmp has no layout yet, so it adopts this one. Its
components already have their places here. agentpay implements it in `xbt-signer`,
`xbt-anchor-witness`, `xbt-wallet-mcp` and `xbt402-hub`. The code is in the `xbt-svc` crate.
`scripts/container_test.sh` tests it on regtest.

Status: **proposal, pending cmp-lead's OK** (forwarded by agp-lead, 2026-09-28).

## 1. One data dir, one sub-dir per component

`XBT_DATA_DIR` (cmp: `CMP_DATA_DIR`) is mounted at **`/data`** in every image. On Umbrel it is
`${APP_DATA_DIR}/data`. On StartOS it is the package's `main` volume. Bare metal uses any directory.
Nothing is written outside `/data` and `/tmp`, so every container runs with `read_only: true` and a
tmpfs `/tmp`.

```
/data/
  signer/          agp  uid 10001  0700  policy.json, .run/ (B2 state: ledger, audit, sealed hot/channel keys,
                                         channels, routing, signatures.jsonl), secrets/
  witness/         agp  uid 10002  0700  anchors.jsonl, alerts.jsonl       (XBT_WITNESS_DIR: own mount, own owner)
  mcp/             agp  uid 10003  0700  secrets/, mcp-payer.jsonl (local payer mode)
  hub/             agp  uid 10004  0700  hub.json (optional), state/, secrets/
  cmp-node/        cmp  uid 10011  0700  operator key, operator service, merchant ledgers and meters, secrets/
  cmpd/            cmp  uid 10012  0700  device runtime state, secrets/
  cmpd-cache/      cmp  uid 10012  0700  the model span cache: LARGE, its own mount (CMP_CACHE_DIR), safe to prune
  cmp-client/      cmp  uid 10013  0700  client ledger, input logs, secrets/
  knots-xbt/       cmp  uid 10020  0700  the pruned XBT Knots node's datadir (cmp bundles the node image)
  run/<component>/ the server's uid and gid, 0750: its sockets (0660) and readiness file (0640)
     run/signer/   signer.sock, ready.json
     run/anchor/   anchor.sock
```

Rules:
- **A container mounts only its own sub-dir**, plus the `run/<peer>/` directories of the sockets it
  connects to. Read-only is enough to connect to a Unix socket.
  - The MCP mounts `mcp/` and `run/signer/` (ro).
  - The signer mounts `signer/`, `run/signer/` and `run/anchor/` (ro).
  - The witness mounts `witness/` and `run/anchor/`.
- **Separately mountable paths** have their own override variable, for another disk, another owner or
  pruning:
  - `XBT_WITNESS_DIR`: the witness store, which the signer's user must not be able to write.
  - `XBT_RUN_DIR`: the socket root.
  - `CMP_CACHE_DIR`: the span cache.
- **Owners:** each image's shared base layer carries the `/data` skeleton with the owners above. A
  Docker named volume mounted there takes its owner from the image on first use. Bind mounts (Umbrel's
  `${APP_DATA_DIR}`) need the installer, or an init container, to `chown` each sub-dir once.
  - If a box runs everything as one user (Umbrel's usual `user: 1000:1000`), the layout still works.
  - What is lost then is the separation between the witness and the signer. Umbrel packaging
    (CMP-098 / AGP-P-002) should keep the UIDs.
- **Socket groups:** a socket's group is its server's group, and each client is a member of it.
  `/etc/group` in the images:
  - `xbt-signer` group: `xbt-wallet-mcp` is a member;
  - `xbt-anchor-witness` group: `xbt-signer` is a member.

  So the MCP cannot reach the witness, and the witness cannot reach the signer.
- **State formats do not change.** `signer/` is exactly B2's signer root (`policy.json` + `.run/`), so
  B2's Python tools and an existing bare-metal wallet move in unchanged.

UID table (the images' `USER`; the cmp rows are reserved):

| uid/gid | user | image |
|---|---|---|
| 10001 | xbt-signer | xbt-signer |
| 10002 | xbt-anchor-witness | xbt-anchor-witness |
| 10003 | xbt-wallet-mcp | xbt-wallet-mcp |
| 10004 | xbt402-hub | xbt402-hub |
| 10011 | cmp-node | cmp-node (reserved) |
| 10012 | cmpd | cmpd-* (reserved) |
| 10013 | cmp-client | cmp-client (reserved) |
| 10020 | knots-xbt | knots-xbt (reserved) |

## 2. Secrets: one lookup, by name

A secret has a **name**, the same string everywhere: the file name in `$CREDENTIALS_DIRECTORY`, in
the data dir, and in the env variable (upper-cased, `-` → `_`). Lookup order (`xbt_svc::Secrets`):

1. `XBT_SECRET_<NAME>_FILE` (cmp: `CMP_SECRET_<NAME>_FILE`): an explicit path. StartOS config and
   secrets written to files use this, and so do compose and Docker secrets.
2. `$CREDENTIALS_DIRECTORY/<name>`: systemd `LoadCredential=`. cmp.keys already reads this.
3. `/data/<component>/secrets/<name>`: the file must be 0600 in a 0700 directory. Production refuses a
   secret readable by group or others. Wrapping keys, tokens and hub keys are **generated here on first
   run**: created exclusively, 0600, fsynced, never overwritten.
4. `XBT_SECRET_<NAME>`, a plain env value: **dev mode only**. Production refuses it at start, and so do
   the older env secrets `B2_HOT_PASSPHRASE`, `XBT_MCP_HTTP_TOKEN` and `B2_HOT_ALLOW_PLAINTEXT`.

`XBT_MODE=production|dev`. The images set `production`. If it is unset, the mode is production when
`XBT_DATA_DIR` is set, and dev otherwise, which keeps the pre-AGP-038 bare-metal behaviour.
`XBT_SECRETS_DIR` overrides step 3's directory.

| name | component | what | first run |
|---|---|---|---|
| `signer-wrap-key` | signer | 32-byte AES-256-GCM wrapping key for the sealed hot and channel keys (raw or 64 hex) | generated |
| `signer-passphrase` | signer | instead of the wrap key: scrypt passphrase (B2 format) | never generated |
| `node-rpc-auth` | signer, hub (cmp: any node client) | `user:password` in cookie format (a node's `.cookie` works as is) | provisioned by the installer |
| `mcp-http-token` | mcp | bearer token for MCP over HTTP (64 hex) | generated when listening off loopback |
| `hub-payto-key` | hub | payTo secret (hex scalar) | generated |
| `operator-passphrase` | cmp-node | cmp operator key passphrase (cmp.keys) | cmp's rule |
| `client-passphrase` | cmp-client | cmp client identity passphrase (cmp.keys) | cmp's rule |

cmp's existing `$CREDENTIALS_DIRECTORY/<name>` and passphrase-file handling is steps 2 and 1. Adding
step 3 and the `CMP_SECRET_*` names makes it this scheme. `--secrets-dir` (§U) is `XBT_SECRETS_DIR` /
`CMP_SECRETS_DIR`.

## 3. Health, readiness, status

Every HTTP service serves these without auth (probes cannot send tokens). The bodies hold no secrets:

- `GET /healthz`: the process is up. Returns `200 {"ok": true, "service": ...}`.
- `GET /readyz`: ready for work. Returns `200` or `503`, with JSON status in the body. The status always
  includes the node's `reachable`, `synced` and `sync_pct` (from `verificationprogress`), the same
  `xbt_svc::health::node_status` everywhere. The body *is* the service's status JSON, so a UI (the
  signer UI, AGP-039, linking to cmp's node/hub status page) reads `/readyz` and gets a 200 or 503
  plus the details. cmp may add `GET /status` returning the same document, always 200.
- Both are also served under the base path (`<base>/healthz`).

| service | /readyz is 200 when |
|---|---|
| `xbt-wallet-mcp` | the signer answers `health` on its socket, **and** the signer's readiness file is fresh and `ok` |
| `xbt402-hub` | the node is reachable and synced; the body also gives `pay_to` and the provider count |
| `xbt-signer` (socket only) | readiness **file** `run/signer/ready.json`, rewritten every `XBT_READY_INTERVAL` s (default 5), `ok` when all of these hold: node reachable and synced, keys unlocked, the witness answering `latest` (when anchoring is on), the signer's own socket answering `health` |
| `xbt-anchor-witness` (socket only) | `xbt-anchor-witness healthcheck`: the witness answers `latest` |

**Why the signer has a readiness file, not a health listener.** The signer holds every key. A file adds
no network surface at all, where a listener would add one, even on loopback. The file works in a
`FROM scratch` image (the binary's own `healthcheck` subcommand reads it). Other containers read it
through the shared `run/signer/` mount (group-readable, 0640). A stale file means the signer is gone or
wedged (the heartbeat stops), which a socket probe alone would not show before a timeout.

**Image HEALTHCHECK = liveness.** It runs the binary's own `healthcheck` subcommand: signer file fresh,
witness answering, MCP/hub `GET /healthz`. The binary is used because the images have no shell or curl.
`--ready` switches the subcommand to readiness, for StartOS health checks, or for compose
`depends_on: condition: service_healthy` when a stack should wait for sync. With readiness as the
default, a node doing hours of IBD would mark every service unhealthy.

## 4. Networking and reverse proxies

- **Bind addresses come from config.** In the images:
  - MCP: `XBT_MCP_HTTP=0.0.0.0:33510`;
  - hub: `XBT_HUB_BIND=0.0.0.0`, `XBT_HUB_PORT=9480`.

  Bare metal defaults to loopback.
- **Auth off loopback:** the MCP refuses a non-loopback listener without a bearer token. In data-dir mode
  it generates `mcp-http-token`. The signer has no HTTP API. The hub is a paid public service, so its
  auth is the payment.
- **Base path:** `XBT_BASE_PATH=/x`. Every endpoint answers both at `/x/...` (a proxy that keeps the
  prefix) and at `/...` (one that strips it).
- **Public URL:** used for the hub's 402 `resource.url`. Tor `.onion` and StartOS LAN/Tor interfaces work
  without configuration. In order:
  1. `XBT_PUBLIC_URL`;
  2. with `XBT_TRUST_FORWARDED=1`: `X-Forwarded-Proto` / `X-Forwarded-Host` / `X-Forwarded-Prefix`;
  3. otherwise the request's `Host`.

  **There is no hard-coded self-URL.** Umbrel's `app_proxy` and StartOS both set the forwarded headers.
  Trust them only behind such a proxy.

## 5. Configuration (env or file)

Every setting has an env variable. Files are optional.

| service | config |
|---|---|
| signer | B2's `B2_*` env (unchanged), plus `XBT_NODE_RPC_HOST`, `XBT_NODE_RPC_PORT`, `XBT_CHAIN`, `XBT_NODE_WALLET`. Policy: `XBT_SIGNER_POLICY` (JSON; authoritative, and rewrites `policy.json` when it changes), or `XBT_SIGNER_POLICY_FILE`, or the existing `policy.json`, or a default that pays nobody. `XBT_ANCHOR=off` runs without a witness. New knobs: `B2_RPCHOST`, `B2_RPCCOOKIE` (a credentials file), `B2_SIGNER_SOCK_MODE` (≤ 660). |
| witness | `XBT_WITNESS_DIR`, `XBT_ANCHOR_SOCK` (defaults under `/data`) |
| MCP | `XBT_MCP_HTTP`, `XBT_MCP_PATH`, `XBT_BASE_PATH`, `XBT_MCP_HTTP_ALLOW_REMOTE`, the existing `XBT_MCP_*` payer settings, and `B2_SIGNER_SOCK` (default `/data/run/signer/signer.sock`) |
| hub | `hub.json` (`--config`, `XBT_HUB_CONFIG`, or `/data/hub/hub.json`), each field overridable: `XBT_NODE_RPC_HOST`, `XBT_NODE_RPC_PORT`, `XBT_HUB_WALLET`, `XBT_HUB_NETWORK` (default: derived from the node's anchor block), `XBT_HUB_BIND`, `XBT_HUB_PORT`, `XBT_HUB_DATADIR`, `XBT_HUB_CONNECT`, `XBT_HUB_JSON`, `XBT_HUB_WATCH_INTERVAL`, `XBT_HUB_THREADS`, `XBT_PUBLIC_URL`, `XBT_TRUST_FORWARDED` |

None of these binaries depends on systemd. `$CREDENTIALS_DIRECTORY` is just one secret source.

## 6. Images

`scripts/oci_build.sh` builds one image per binary for **linux/amd64, linux/arm64 and linux/arm/v7**. Each
is `FROM scratch` with the static musl binary (built with zig). There is no `RUN`, so no emulator or
binfmt is needed. The images are saved as OCI archives in `dist/oci/*.tar` (never pushed), with digests
and sizes in `dist/oci/IMAGES.md`. `scripts/oci_inspect.py` checks every platform: architecture, static
ELF, non-root, HEALTHCHECK, two layers, and the shared base layer.

- **Layer 1** is shared and byte-identical in every image and platform, so it is stored once:
  `/etc/passwd`, `/etc/group`, `/tmp` (1777), and the `/data` skeleton with owners. It is generated
  deterministically by `container/mkbase.py`.
- **Layer 2** is the binary.
- **Config:**
  - `USER` is the component's user, never root;
  - `ENV XBT_DATA_DIR=/data XBT_MODE=production`;
  - `ENTRYPOINT` is the binary;
  - `HEALTHCHECK` runs the binary's own `healthcheck`.

  Run the containers with `read_only: true`, `tmpfs: /tmp` and `no-new-privileges`.
- **cmp's images follow the same pattern:**
  - `cmp-node` and `cmp-client` are one image each.
  - `cmpd` comes in **per-backend variants**: `cmpd-cpu` (static, the default on boxes, which are usually
    CPU-only), `cmpd-cuda`, `cmpd-vulkan` and `cmpd-rocm`. Every variant has the same data layout
    (`cmpd/`, `cmpd-cache/`), the same env, and the same health endpoints, so an app switches the backend
    only by changing the image name.
  - GPU variants cannot be `FROM scratch`: they need the vendor runtime libraries. The rule for them is
    the smallest base that carries those libraries, still non-root and with a read-only root filesystem.
  - `knots-xbt` is cmp's node image. agentpay's apps reference it, not an image of their own.

### Choices and comparisons

**Base image: scratch (chosen), distroless static, or alpine.**

| | scratch | distroless static-debian12 | alpine 3 |
|---|---|---|---|
| size | 0 (+ our 1 KB base layer) | ~2 MB | ~3.5 MB compressed, 8 MB unpacked |
| arm/v7 | yes | yes | yes |
| CA certs | not needed: rustls with webpki-roots compiled into the binaries | included | package |
| tzdata | not needed: everything is UTC/unix time | included | package |
| debug shell | none; `healthcheck` / `call` subcommands, or `docker run --volumes-from` a debug image | `:debug` variant | yes |
| attack surface | the binary only | minimal | a shell and busybox |
| pull from a registry | no (nothing to pull) | yes | yes |

scratch wins. The binaries are static and carry their own roots, and they need no zone data. The only
thing a base would add is a shell, and our own subcommands do that job without adding surface. It is
also the only option buildable here without pulling from a registry.

**Granularity: one image per binary (chosen), or one image with subcommands.**
- Per binary: the `USER`, `ENTRYPOINT` and `HEALTHCHECK` are each right for their service.
- Each container carries only its own binary (the witness image is about 0.36 MB compressed).
- Images can be pinned and upgraded independently.
- The duplication costs nothing, because the base layer is shared.
- A single image would need one generic HEALTHCHECK, one user for every service (breaking the
  witness/signer UID split), and would ship every binary in every container.
- cmp: the same choice, with `cmpd` per backend.

**Build tooling.** This host has no rootless Docker, podman or buildah. `docker buildx` runs through the
docker group (no sudo), and needs no binfmt because the Dockerfile has no `RUN`. The exports are
built for reproducibility: `SOURCE_DATE_EPOCH` is the commit time, `rewrite-timestamp` is set, and the base layer is
generated deterministically. The base layer digest was the same on every build. Byte-identical rebuilds of the
binary layers have not been verified yet.

## 7. Test

`scripts/container_test.sh` builds and inspects all the images, then runs the amd64 ones on a private
Docker network with a Knots regtest node. They are configured only by env and the data dir (named
volumes). The test:
1. pays an xbt402 call through the MCP over HTTP, behind a base path and with the bearer token;
2. kills and restarts the containers and checks that everything persists;
3. checks that `/readyz` follows the witness and the node;
4. checks the hub behind a proxy.

Ports 33700–33799. Evidence is written to `run/container-test/<stamp>/`.
