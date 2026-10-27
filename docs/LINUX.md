# Lightning Stream on Linux

Lightning Stream runs on a plain Linux machine (Ubuntu or any other distribution with Docker) beside
nodes you already run yourself. It is the same app as on Umbrel, from the same published images,
pinned by digest. The package is in [`packaging/linux`](../packaging/linux).

This guide covers p2p-hash first:
- **Hashtaker:** you rent other people's miners into your own DATUM Gateway, and pay for each piece of
  work from your own Lightning node.
- **Hashmaker:** you rent your miners out.

The rest of the app (buying and selling services) works the same as on Umbrel. Use real sats in small
amounts only: the software is tested on mainnet with small amounts.

## What you need

- **Linux with Docker:** Docker 24 or newer and its Compose plugin, 2.20 or newer. On Ubuntu that's
  `sudo apt install docker.io docker-compose-v2`, or Docker's own packages. The user who installs needs
  to be able to run `docker` (the `docker` group). Images exist for x86_64, arm64 and armv7.
- **Your XBT node (Knots BLAKE2b)** on the same machine, with `server=1` and an RPC user and password
  for the app. A cookie changes at every restart, so it can't be used. The wallet asks the node about
  the chain; it never holds your coins there.
  - **If your node uses only its cookie** (no `rpcuser` in its config): add an `rpcauth` line for the
    app. Unlike `rpcpassword`, it leaves the cookie in place for your other apps. Knots ships the
    script that makes the line:
    ```
    python3 share/rpcauth/rpcauth.py lightning-stream
    ```
    Run it in the Knots source folder, or the folder a Knots release download unpacks to (the script is
    in its `share/rpcauth/`). It prints an `rpcauth=lightning-stream:…` line and a password; keep the
    password. Add the line to the node's config file (`~/.bitcoin/bitcoin.conf` by default), restart the
    node, and check that the login works:
    ```
    bitcoin-cli -rpcuser=lightning-stream -rpcpassword='THE PASSWORD' getblockcount
    ```
    It prints the node's block height. Then give `install.sh` the user `lightning-stream` and that
    password when it asks. The app does not read the cookie file: the cookie is remade at every restart
    of the node, and the app would lose its login each time.
- **Your Lightning node (lnd-family, such as Lightning Fork)** on the same machine, unlocked, with its
  REST interface on (lnd's default is `https://127.0.0.1:8080`) and channels on the BLAKE2b Lightning
  network.
  - Its `tls.cert` must be readable by other users. It's a public certificate, so `chmod 644` is fine.
  - You need its `admin.macaroon` once, during installation (see below).
- **For a hashtaker, your DATUM Gateway:** its Stratum port, `127.0.0.1:23334` by default. The pool your
  rented work is paid through is set in your DATUM Gateway, not in this app.
- **For a hashmaker:** your miners on the same LAN, and a way for hashtakers to reach you from outside
  (see [Hashmaker](#hashmaker)).

Everything runs on the host's network, so the app reaches your nodes on 127.0.0.1 where they listen by
default, and the app's own ports are on 127.0.0.1 too. There are two exceptions: the hashmaker's two
ports, and the selling port once you set up a shop.

## Install

```bash
git clone https://github.com/AwokenLazarus/Lightning-Stream.git
cd Lightning-Stream
packaging/linux/install.sh
```

The script is short and readable, so read it first if you like. It:

1. checks Docker and the Compose plugin;
2. asks where your nodes are, guessing from `~/.lnd` and `~/.bitcoin/bitcoin.conf`;
3. asks whether to turn the hashmaker on;
4. writes `~/lightning-stream/docker-compose.yml` and `~/lightning-stream/.env` (mode 600: it holds the
   app's login password and your node's RPC password);
5. downloads the pinned images;
6. **makes the app's own Lightning keys.** It reads your `admin.macaroon` (with `sudo` if your user
   can't) and hands it, on standard input, to a one-shot container. That container asks your node to
   bake the app's narrow macaroons, each under a root key of its own, then exits. The admin macaroon is
   never written anywhere. These are the narrow macaroons:

   | for | permissions |
   |---|---|
   | the wallet, paying | `info:read offchain:read offchain:write onchain:read` |
   | the shop, invoices | `invoices:read invoices:write` |
   | the shop, the chain height | `info:read` |

   If you'd rather not hand over the admin macaroon, leave that answer empty. Then bake these yourself
   with `lncli bakemacaroon` and paste them in on the app's Lightning and Sell pages.
7. starts the app.

Use `install.sh --dir DIR` to install somewhere other than `~/lightning-stream`. To change an answer
later, run `install.sh` again: your current answers are the defaults.

## First run

The page is at **http://127.0.0.1:8482/**. From another machine, open an ssh tunnel first:
`ssh -L 8482:127.0.0.1:8482 you@your-node-machine`. The password is what follows `LS_UI_PASSWORD=` in
`~/lightning-stream/.env` (`grep LS_UI_PASSWORD ~/lightning-stream/.env` shows it). A password you chose
with spaces or other signs in it is written in single quotes there: type it without them. (Earlier installs
wrote every password in quotes.)

1. **Make your approval key.** The app asks for it first. It's the key that signs your spending rules,
   and it stays in your browser. Save its backup.
2. **Sign the safe starter rules:** Settings → Spending rules → *Start from the safe starter rules* →
   *Review the change*, then sign. **The app pays nothing over Lightning until these rules are signed in
   the app**, on mainnet as everywhere: the rules turn paying on and set its limits. On mainnet the
   limits are low. The rules include a `hashrate` task with a small budget, so rented hashrate is paid
   under its own limit.
3. **Confirm paying with real money.** On mainnet the app pays nothing until you confirm, once, that it
   may pay with real money, even with the rules signed. After you sign, the app takes you to the
   Lightning page (Settings → Your node): under *Pay with real money*, tick the box and press *Start
   paying*. Until then Home and Setup show a *Start paying* link instead of "ready", and a refused buy
   says the same.
4. **Check the Lightning page.** It should say the app connected to your node and is ready. If it says
   your node holds more than your rules allow, press *Raise the limit* and sign.

After you sign a change that waits for a restart, the app says so. On Linux, in the folder you
installed to (`~/lightning-stream` unless you chose another), run `docker compose restart`.

## Before you buy: get a channel

The app pays from your own Lightning node, so your node needs a funded channel on the BLAKE2b Lightning
network with a route to the shop you buy from. Without one, the first buy fails with "no route".

1. **Open one channel** from your Lightning node. lnd refuses channels under 20,000 sats by default, so
   20,000 to 50,000 sats is a good size for trying things out: a shop's ticket is about 1,000 sats.
2. **Open it to a well-connected public node**, such as ours, lazarus-xbt (it takes channels of 20,000
   sats or more). Payments to any shop find their way from there, because every invoice carries hints
   for the last hop. It's reachable over Tor only for now, so your node needs Tor (Lightning Fork on
   Umbrel has it on). Connect with `lncli connect <key>@<address>`, using:
   - key: `033665f1accdf08dd2d2f22f62f8dd70ccd238381402b10c12c0be3e7fd493b8d5`
   - address: `6y4rkcimjbzfhj2j4oidbg4br4xgdfvpbsx7x3ifedv6jgfxg55wtiqd.onion:9735`

   Some nodes take only larger channels: they refuse a smaller one before anything is paid, so a
   refusal costs nothing. A channel straight to a shop's own node pays it from 0.1.17 on; before
   0.1.17 such a channel cannot pay a shop that sells by BOLT 12 offer, ours included.
3. **Wait for the channel to be active.** That takes a few confirmations, then a few minutes for the
   network to learn about it.

If a payment can't find a route:

- Check that the channel is **active** and that your side holds more than about 1,000 sats.
- Wait ten minutes after the channel opens, then try again.
- Open a second channel to a different well-connected node, or straight to the shop's node.
- Still stuck? Open an issue at https://github.com/AwokenLazarus/Lightning-Stream/issues and include
  your node's public key.

## Hashtaker

You rent hashrate into your own DATUM Gateway and pay for each piece of work:

1. **Services → Hashrate.** Check that it says *Ready to rent*, meaning your DATUM Gateway answers. If
   not, set its address under *Your DATUM Gateway*.
2. **Miners for rent** lists the offers hashmakers publish on Nostr (relay.lazarus-xbt.xyz,
   relay.kilombino.com, relay.damus.io and nos.lol by default). For a hashmaker you haven't paid before, press **Allow this hashmaker to be paid**. The rules
   page shows that hashmaker's address added, tied to the Lightning node its signed listing names, and you
   sign the change.
3. Choose the machines, how long, and the most the rental may cost, then press **Rent**.

**What you pay:**
- Work is counted only from shares your own DATUM Gateway accepts, weighted by difficulty.
- Each piece of work is paid once it's finished, from a Lightning ticket.
- The rental ends at its time or its budget, whichever comes first, and **Cut** ends it at once.
- The hashmaker stops its miners within about one piece of work if payment stops.
- Your exposure at any moment is the unspent credit of your current ticket. A ticket is at least
  546 sats. The wallet asks for a smaller ticket when your limit is low, if the hashmaker allows it.
  Leftover credit stays with that hashmaker and isn't refunded.

## Hashmaker

You rent your miners out, and they hash for your own pool whenever nobody rents them:

1. Run `install.sh` again and answer **1** to the hashmaker question. It also asks for this machine's
   LAN address.
2. **Point your miners** at `stratum+tcp://<this machine's LAN address>:23340`. **Keep 23340 on your
   LAN:** don't forward it.
3. **Sell: your shop.** Hashtakers pay at an https address that leads to the app's selling port,
   `127.0.0.1:8402` on this machine. Put a reverse proxy with a certificate in front of it (nginx,
   Caddy, or a tunnel that gives an https address), and write that address on the Sell page. Once it's
   saved, the selling port listens beyond loopback, so let only your proxy reach it.
4. **Sell → Hashrate:**
   - set your own pool (your DATUM Gateway, or your pool, as your miners use it today);
   - set a price per piece of work and a name;
   - set **the address hashtakers use**: your public address with port **23341**, after you forward TCP
     23341 to this machine. The link is encrypted end to end, so it needs no certificate, and https
     tunnels for websites can't carry it.

   Then tick *Rent out my miners* and save. With a miner connected and the address set, your offer goes
   on the Nostr relays within a minute.

## Update, stop, remove

- **Update:** `git pull`, then `packaging/linux/install.sh` again. It keeps your answers, your keys and
  your rules, and pulls the newly pinned images.
- **Stop / start:** `docker compose -f ~/lightning-stream/docker-compose.yml down` and `... up -d`. To
  see why something isn't working: `docker compose -f ~/lightning-stream/docker-compose.yml logs ui`
  (or `signer`, `hashtaker`, `hashmaker`, `gateway`).
- **Remove:** `packaging/linux/uninstall.sh`. It stops and removes the containers and images, then,
  after you type `yes`, the data folder (keys, rules, tickets). Move anything left in the app out
  first. `--keep-data` keeps the folder. It also prints the root key ids of the macaroons the app made,
  which stay valid on your node until you revoke them with `lncli deletemacaroonid ID`.

## Without Docker

The same programs are static binaries for x86_64, arm64 and armv7. Two ways to get them:
- the **Linux binaries** workflow builds them as tarballs with SHA-256 sums;
- or build them yourself: `cargo build --release -p xbt-hashlink -p xbt-gateway -p xbt-signer`.

There are no service files for them yet. [P2P-HASH-TRY-IT.md](P2P-HASH-TRY-IT.md) runs each side by
hand.

## Tested

`packaging/linux/test-linux.sh` runs the whole package on regtest:
1. `install.sh`'s checks in a bare Ubuntu 24.04;
2. two installs on one machine, a hashmaker and a hashtaker, against a test Lightning network, from
   `install.sh --yes`;
3. each owner's first run on their page;
4. one rental, paid piece by piece;
5. `uninstall.sh`, which must leave nothing behind.
