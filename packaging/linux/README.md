# Linux package

Lightning Stream for a plain Linux machine, beside the owner's own XBT node, Lightning node and DATUM
Gateway. The owner's guide is [docs/LINUX.md](../../docs/LINUX.md).

| file | what it is |
|---|---|
| `docker-compose.yml` | the app's services, pinned to the published images (`packaging/pin_images.py` writes the pins; `--check` checks them) |
| `.env.example` | the settings the compose file reads, with what each one is |
| `install.sh` | checks Docker, asks the owner's answers, writes `docker-compose.yml` and `.env` (0600) into the install folder, has the node bake the app's narrow macaroons from the admin macaroon on standard input, and starts the app |
| `uninstall.sh` | removes the containers, the images and (unless `--keep-data`) the data, and prints the root key ids to revoke |
| `test-linux.sh`, `test/` | the package on regtest: two installs, a hashmaker and a hashtaker, one paid rental, uninstall |

## Design: how to ship it

The criterion: an outside tester on Ubuntu runs the **same tested programs** as the Umbrel app, with the
fewest steps, on the widest range of hardware, with no service left reachable that need not be.

| option | for | against |
|---|---|---|
| **Docker Compose of the published images** (chosen) | the same images, digests and hardening (read-only, no capabilities, no new privileges) as Umbrel; amd64, arm64 and armv7 already published; one install script; update = new pins | needs Docker; the containers run on the host's network to reach nodes that listen on loopback |
| static binaries with systemd units | no Docker; the binaries already exist (the images hold them) | eight services, their users, directories, sockets and secrets to lay out by hand or in units; another layout to test and keep in step with the images |
| a .deb package | the native Ubuntu way | the same layout work as units, plus packaging per distribution and architecture; nothing to reuse |
| snap or flatpak | sandboxed, self-updating | confinement fights the unix sockets between services and the host's node files; a store account and review |

**Choice:** Compose, as the main route. The static binaries come as a second route for people without
Docker: the **Linux binaries** workflow (`.github/workflows/linux-binaries.yml`, started by hand) packs
the same binaries per architecture, with SHA-256 sums, as artifacts of the run. Service files for them
can follow if testers ask.

## Choices inside the package

- **The host's network.** An owner's lnd, Knots and DATUM Gateway listen on 127.0.0.1 by default. A
  container on a bridge network can't reach the host's loopback without the owner changing each node's
  listen address and its certificate. So every service uses `network_mode: host`, and every port the
  app opens is bound to 127.0.0.1, with two exceptions:
  - the hashmaker's miners port (23340) and link port (23341), only when the owner turns the hashmaker
    on (Compose profile `hashmaker`);
  - the gateway's selling port, once the owner saves a shop with an https address.

  The witness has no network at all, and the services talk to the signer over its unix socket, as on
  Umbrel.
- **No admin macaroon on disk.** `install.sh` pipes it to `xbt-wallet-ui node-keys` with
  `XBT_KEYS_ADMIN=-`, which reads it once into memory: the file's bytes, or the same as hex. Only the
  narrow macaroons are written. On Umbrel the same tool reads the Lightning app's file, mounted into
  that one-shot only.
- **A login password of the app's own**, set at install (random unless the owner gives one). There is
  no platform login on Linux, and no setting that trusts a header instead of the password.
- **Several installs on one machine** need a different `COMPOSE_PROJECT_NAME`, different ports in
  `.env`, and the hashmaker on in one of them only. The test does this; an owner normally has one.
