# xbt-wallet-ui

The agent wallet's web UI, for a box with no terminal (Umbrel, StartOS), from AGP-039. It lets the owner:

- set and review the policy: budgets, per-counterparty caps, the allowlist, the human threshold and the hot-key cap;
- approve or deny payments above the threshold (replacing `agentwallet-approve`);
- see balances and the hot-key cap status;
- see, read-only, the on-chain channel records an earlier version of the wallet left, with their close reports and what to do about one that is not settled (this wallet has no on-chain channel: it was removed in October 2026);
- see the signature log and its anchor verification;
- sweep and rotate the hot key, signed by the human;
- see the xbt-compute node's status, when one is configured;
- rotate the agent MCP token from the Agents page (no terminal, no restart);
- run a first-time setup wizard (the approval key, the policy template, the wrapping key and backup).

The UI is a separate process that talks only to the signer socket, as the MCP server does. It never
holds a wallet key or the approving key. The UI binary does not link the signer's key-handling code.

## Run

```bash
cargo build --release -p xbt-wallet-ui
XBT_UI_BIND=0.0.0.0:8480 XBT_UI_SIGNER_SOCK=~/wallet/.run/signer.sock XBT_UI_DATA_DIR=~/wallet-ui \
  XBT_UI_PASSWORD_FILE=/run/secrets/ui-password target/release/xbt-wallet-ui
```

Without a password source, the first start prints a one-time setup code and writes it to
`$XBT_UI_DATA_DIR/setup-code` (0600). The first visit needs that code to set the password.

| variable | default | meaning |
|---|---|---|
| `XBT_UI_BIND` | `127.0.0.1:8480` | listen address |
| `XBT_UI_SIGNER_SOCK` | `B2_SIGNER_SOCK`, else `$B2_ROOT/.run/signer.sock` | the signer socket (a path, or `tcp://127.0.0.1:PORT`) |
| `XBT_UI_DATA_DIR` | `$XBT_DATA_DIR/ui`, else `./xbt-wallet-ui` | the login hash and the setup code |
| `XBT_UI_PASSWORD_FILE` / `$CREDENTIALS_DIRECTORY/xbt-ui-password` / `XBT_UI_PASSWORD` | | the platform's password: a file (StartOS config, Docker secret), systemd `LoadCredential`, or env (Umbrel `${APP_PASSWORD}`; removed from the environment once read) |
| `XBT_UI_BASE_PATH` | `/` | a proxy's path prefix (the cookie path; prefixed and stripped request paths both work) |
| `XBT_UI_SESSION_IDLE_S` / `XBT_UI_SESSION_MAX_S` | 900 / 28800 | session lifetimes |
| `XBT_UI_SECURE_COOKIE` | auto | `Secure` cookie: `1` always, `0` never, auto when `X-Forwarded-Proto: https` |
| `XBT_UI_ALLOW_IPS` | all | peers allowed to connect (IPs or prefixes such as `10.21.0.`), e.g. only the box's app proxy |
| `XBT_UI_ALLOWED_HOSTS` | | AGP-063 W4: extra host names the UI answers to, comma-separated (`wallet.example.com`; `*`: any). Always allowed: IP literals, single-label names (`localhost`, a container name), `*.local`, `*.localhost`, `*.onion`. Another Host is 421 (DNS rebinding); a POST whose `Origin` names another host is 403 (`Origin: null`, which Chrome sends under `no-referrer`, is accepted) |
| `XBT_UI_SETUP_OPEN` | 0 | `1`: the first-run password setup needs no code (the platform proxy already authenticated the owner) |
| `XBT_UI_CMP_URL` | | xbt-compute's node status page, linked from Wallet |
| `XBT_UI_CMP_STATUS_URL` | | xbt-compute's status JSON (e.g. its `/readyz`, CONTRACT §U), shown as a compact tile |
| `XBT_UI_MCP_URL` | | MCP endpoint(s) shown on the Agents page |
| `XBT_UI_MCP_TOKEN_FILE` | `$XBT_DATA_DIR/run/ui/mcp-http-token`, else `<data dir>/secrets/mcp-http-token` | the bearer token shown on Agents. The UI owns it and rotates it there (atomic replace, mode kept, never world-readable); the MCP only reads it (AGP-042) |
| `XBT_UI_SERVICES` | `<data dir>/services.json` | path of a JSON list of services for Browse and the player. Each service is `{name, kind, seller, price_text, items}`, with an optional `address` (where apps and agents use it), `kind` one of `video`, `files`, `api`, `ai`, and each item `{title, url}` with an optional `year` and `credit`. See `examples/services.example.json` (three Creative Commons films). The Services page writes it: paste a seller's address, and each service its signed listing names is added. |
| `XBT_UI_SUGGESTED_SELLERS` | | sellers' addresses (comma-separated) that Sellers and an empty Browse offer to add in one click. Nothing is fetched until the owner adds one. |
| `XBT_UI_SELL` | `0` | `1`: the wallet's UI also has the Sell page, which sets up the gateway beside it (the `XBT_UI_GW_*` settings) in plain words: connect the node once, say where buyers find you, and add each service with its address and a price in sats. It keeps the owner's list in `sell.json` in the data dir and writes the gateway's config from it. The one Lightning Stream app sets this. |
| `XBT_UI_CONNECTOR` | `http://127.0.0.1:8480` | the connector the player loads. A video's source is this URL plus `/s/` plus the item URL. The page's `media-src` allows only that origin. This is the connector's default listen address; the UI's own default bind is the same port, so on one machine set one of the two. |
| `XBT_UI_RELAY_LINK_S` | 21600 (6 hours) | how long a link for an external player lives. The Player page makes one per item on request (a logged-in POST): `<UI address>/r/<token>`, which VLC or mpv opens without the login and which plays that item only, seeking included. Links can be revoked there, and a restart of the UI revokes them all. |

`GET /healthz` is always 200. `GET /readyz` is 200 when the signer answers, else 503. Neither needs
a login, and neither reveals wallet state.

`xbt-wallet-ui sign --key FILE --message-hex HEX` and `xbt-wallet-ui pubkey --key FILE` let the owner
sign on another device, with the key's backup file (32 raw bytes or 64 hex, the format
`agentwallet-approve` uses).

The MCP server can wait for the approval: with `XBT_MCP_APPROVAL_WAIT_S=N`, an over-threshold
`xbt402_pay` waits up to N seconds. Once the owner approves in the UI, it returns the paid result.

## Stack: the options and the choice

| | server-rendered HTML from Rust (chosen) | a small SPA (Svelte/Preact) embedded as assets | a TUI in the browser (ttyd + xterm.js) |
|---|---|---|---|
| binary | 0.79 MB aarch64, 0.82 MB armv7, 0.88 MB x86_64 (static musl, `release-small`) | the same server plus a 40–150 kB JS bundle and a node toolchain at build time | a pty server plus about 300 kB of xterm.js, and a TUI to write |
| arm/v7 and small boxes | std HTTP server (`xbt_svc::http`), no async runtime; about 1 MB RSS idle | the same server; the phone does more work | a pty and a process per session |
| security surface | no JSON API for changes, only form POSTs with CSRF tokens; strict CSP (`script-src 'self'`, no inline script, no eval); one 20 kB script, used only for keys and signing (plus the decorative river, which reads and sends nothing) | a JSON API, so CORS and CSRF on every endpoint; larger third-party dependency trees | a shell-like surface; hard to put behind the proxy's auth |
| accessibility | semantic HTML, labels, keyboard focus, readable without JS (JS is needed only to sign) | depends on care; broken without JS | poor: screen readers and phones |
| offline, Tor, proxies | relative URLs, no external resources; works on an .onion and under any prefix | the same only with care (router base paths) | WebSocket through Tor and proxies is fragile |
| maintenance | one Rust crate in the workspace; the pages are functions | two toolchains, a lockfile of npm dependencies | little code, but no real UI |

Templates are plain Rust with one escaping helper (`html::esc`). askama and maud were also available,
but they add proc-macro dependencies for about 15 pages. Everything user-controlled goes through
`esc`, and the CSP blocks any inline script that slipped through.

## Security model

- **Who can do what.** The UI login (scrypt, N=2^15; throttled at 5 failures a minute) lets someone
  see the wallet. Denying a live request also needs the human
  signature (AGP-063).

  Anything that raises what the wallet may spend, or moves or exports keys, also needs the human's
  ed25519 signature: approve, the policy, a new human key, a sweep, a rotation, the backup. The
  signer verifies that signature. The signer socket is shared with the model-facing MCP process, so
  these are new *signed* signer methods (`policy_set`, `human_key_rotate`, `rotate_hot_key_signed`,
  `backup_export`), not trust in the UI. A compromised UI process or MCP process cannot raise the
  budget or approve a payment.
- **Where the approving key lives: in the owner's browser.** The key is generated there with
  `crypto.getRandomValues` and kept in `localStorage`, XORed with a PBKDF2-HMAC-SHA512 pad of a
  passphrase (210,000 iterations, OWASP 2023+) and a MAC. New passphrases must be at least 12
  characters and are refused if they are only digits or a repeated pattern; the page shows a
  strength hint. A wrap stored at the AGP-039 cost (60,000) unlocks once and is re-wrapped at
  210,000. The owner writes down its 64-hex backup once. Only the public key goes to the box
  (`human_key_enroll`; after that, `human_key_rotate` signed by the old key). AGP-063 W4: the first
  enrolment needs the one-time code the signer prints when no key is enrolled. On Umbrel it is in
  the app's log (app page, Troubleshoot), on StartOS in the service's Logs, elsewhere on the signer's
  stderr or in `.run/enroll-code`. Five wrong codes replace it with a new one. Denying a pending
  request is signed in the page too (`deny_message`), so the agent cannot refuse for the owner.

  The message is signed in the page. `ui.js` rebuilds it from the fields shown; for a policy, it
  signs the text shown, and refuses if the displayed text differs.

  The same page accepts a signature made on another device (`xbt-wallet-ui sign`, the message's hex
  is shown), so B2's `agentwallet-approve` keys keep working.

  Options compared:

  | option | against |
  |---|---|
  | WebAuthn/passkeys | Needs a secure context (https or localhost), and Umbrel is plain http on the LAN. Authenticators sign `authenticatorData ‖ clientDataHash` with P-256 bound to an origin, not our ed25519 message, so the signer would need a WebAuthn verifier and an origin that changes with .onion and LAN names. |
  | WebCrypto Ed25519 | Also secure-context only. Pure JS works everywhere: `tests/js/crypto_test.mjs` checks it against RFC 8032, RFC 4231 and hashlib vectors, and `tests/crypto_js.rs` checks it against the signer's bytes and ed25519-dalek. |
  | a separate phone app | The strongest isolation, but a second app to build and ship. The paste-a-signature path supports it today. |

  KDF options for the wrap (AGP-041; measured on Node, Ryzen 9 9950X3D):

  | option | unlock (this host) | phone / Pi-served page | reach | install | safety | choice |
  |---|---|---|---|---|---|---|
  | **PBKDF2-SHA512 210k, already in ui.js** | 2.7 s | ~4–7 s estimated (over the ~2 s goal) | every browser, including plain-http Umbrel | none; the script is already there | OWASP 2023+; hashlib-tested | **chosen** |
  | PBKDF2-SHA512 60k (AGP-039) | 1.0 s | ~2–3 s | same | same | a 6-digit PIN is offline-bruteforceable | kept only as the migration source |
  | scrypt / argon2id in new pure JS | unknown; OWASP scrypt is 128 MB | worse on a phone tab | same if we write it | thousands of unaudited lines, no CDN | memory-hard, but new primitives (SHA-256, Salsa20) | rejected: no in-tree implementation, large audit surface |
  | WebCrypto PBKDF2 only | tens of ms | tens of ms | **secure context only** (https / localhost); Umbrel LAN is http | none | same count, native speed | rejected as the only path; Umbrel has no SubtleCrypto |

  The wrap stays pure JS so a phone on a Pi-served Umbrel page still unlocks. 210k in that JS is slower than ~2 s on a mid-range phone; that is the cost of OWASP's count without a CDN or a new KDF.

  The trade-off: the key protects against the model and agents, against a stolen or compromised box
  disk, and against the signer and MCP processes. It does not protect against a fully compromised
  UI server that serves malicious JavaScript to an unlocked browser. That process holds no key, is
  separate from the MCP, and serves only its embedded assets under a strict CSP. For the highest
  assurance, sign on another device.
- **Sessions and CSRF.** A 32-byte session id in an `HttpOnly; SameSite=Strict` cookie (`Secure`
  behind https). Sessions end after 15 minutes idle and 8 hours in total, with at most 16 live. Each
  session has its own CSRF token, checked on every POST, and a POST marked `Sec-Fetch-Site:
  cross-site` is refused.

  Headers: `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self';
  img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri
  'none'`, plus `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer` and `Cache-Control:
  no-store`. Bodies are capped at 256 kB.
- **Models and agents never reach the UI.** None of the UI's methods is an MCP tool: they are in the
  MCP's `FORBIDDEN` list, which its tests check. The UI has its own port, login and cookie; the MCP
  has none of them.

  On a box, bind it to the app proxy's network and set `XBT_UI_ALLOW_IPS` to the proxy. An agent
  that can reach the port still needs the password, and nothing it can do there spends without the
  human's key.
- **The approval of a Lightning payment is a one-time grant.** The human signs (token, payee,
  amount, expiry). The signer marks the token approved. The agent's next `ln_pay` of the same
  invoice pays under it once. A deny or revoke drops it.

  The approval of an on-chain `pay` keeps B2's `approve`, which pays at once.

## Pages and words

The app is for someone with no technical knowledge, and for any kind of service, not one. The menu
has five places, each with its pages as tabs: **Services** (Browse, Sellers, Live connections),
**Sell** (with `XBT_UI_SELL=1`), **Wallet** (balance and activity, approvals), **Apps & agents**
and **Settings** (setup, your node, spending rules, keys and backup, records). Home says what the
owner can do: use a service, sell a service, and whether the wallet is ready.

Browse lists services by category: Media, AI, and Data & APIs. Each service has a page of its own.
A media service's page lists what it plays, and opens the player; any other service's page gives
the address apps and agents use it at. Live connections shows what is being paid for, what it has
cost and a Stop button.

Main screens use plain words. The exact terms (keys' permissions, node addresses, raw settings) are
in collapsed "Advanced" and "Details" parts. `tests/ui_http.rs` (`main_screens_speak_plain_words`)
fails if a word like "macaroon", "msat" or "upstream" reaches a main screen.

## The look

The app is drawn as an electric river at night, after its icon: a deep-night ground, currents in
electric blue and violet, and one warm colour (amber) for the main action on a page and for money.
Light and dark follow the system. `assets/ui.css` holds the tokens and the components: cards,
buttons (the warm one is the main action; `secondary`, `danger` and `link` for the rest), inputs,
status pills (`pill good|warn|bad`, a word and a colour), the navigation, empty states and the
numbered first-run steps. Everything is local: no web fonts, nothing from another host, and the CSP
stays `default-src 'none'; script-src 'self'; style-src 'self'`.

Behind every page, `assets/river.js` draws a few slow streams on a fixed canvas (`aria-hidden`, no
pointer events). Near the pointer the streams brighten a little and ease aside in one smooth bump,
and a soft glow trails the pointer; a click sends one pulse along the nearest stream from where it
was clicked; `lsRiver.pulse()` sends one down a whole stream, for payment and stream events. Every
effect is drawn along the streams' own curve (`tests/js/river_test.mjs` checks that each of its
points lies on a stream). It is decoration only: it reads nothing and sends nothing. To stay out of
the way:

- it draws in a worker on an `OffscreenCanvas` where the browser has one, so the page's thread only
  forwards pointer positions; elsewhere it draws in the page with the same code;
- 30 frames a second while the pointer moves, 6 at rest (sleeping between frames, not waking at
  every display refresh), none while the tab is hidden or a video plays;
- half resolution (at most 0.75 backing pixels per CSS pixel; the glow hides it), the stream count
  scaled to the window, one still frame when the system asks for reduced motion;
- no flash between pages: the streams' shape is a function of the clock, so every page shows the
  same frame at the same moment; the page draws that first frame itself before it shows (the worker's
  first frame then replaces it), and the browser cross-fades same-origin pages (`@view-transition`);
- 8.7 kB as served (the source without indentation and comment lines).

The bar at the top is sticky and above the page: the page scrolls under it, and it casts a shadow
once it has.

**Cost** (Chrome 152 headless, software rendering with no GPU, which is the dearest case; AMD Ryzen 9
9950X3D, load average about 6 from other work; 1920x1080, dark, the Browse page; CPU of all the
browser's processes as % of one core; two rounds of 30 s each, alternating with and without the
river, averaged; 2026-10-26):

| | pointer still | pointer moving |
|---|---|---|
| without the river | 1.57% | 2.95% |
| with the river (worker) | 3.25% (+1.68) | 7.23% (+4.28) |
| with the river (in the page, the fallback) | 4.03% (+2.46) | 16.97% (+14.02) |
| page thread busy, without / with (worker) | 0.04% / 0.04% | 0.45% / 0.66% |

A frame of the river takes 0.14 ms on average and at most 0.9 ms, in the worker, never on the
page's thread (the first frame of each page is drawn on the page's thread, once). A browser with a
GPU composites the canvas there, so the cost on a normal desktop or phone is lower than this.
**Contrast:** averaged over 8x8 px (a letter's size) at the brightest point the river and the glow
reach, body text is 10.4:1 (dark) and 11.5:1 (light), secondary text 5.9:1 and 5.4:1; on a card,
body text is 15.5:1 and 14.6:1. **Between pages:** 17 shots taken as fast as Chrome gives them while
moving from Browse to another page each show at least as much river as the steady page (ratio 1.0).

Repro (writes the screenshots, `look.json` and the numbers above; about 6 minutes):

```bash
XBT_UI_LOOK=1 XBT_UI_LOOK_DIR=run/look cargo test -p xbt-wallet-ui --test look -- --nocapture
```

The test fails if the river at rest costs 3% of one core or more over the page without it, if a
frame takes more than 4 ms, if body text falls under 7:1 or secondary text under 4.5:1 anywhere
over the river, if a shot taken while moving between pages shows less than half the river of a
steady page, or if, after scrolling (on a desktop, and on a phone with the menu open), the bar is
not the top-most thing at its own middle and corners.

## Tests

```bash
cargo test -p xbt-wallet-ui          # ui_http (auth, CSRF, headers, proxies, every action), crypto_js, browser (headless Chrome)
XBT_UI_LOOK=1 cargo test -p xbt-wallet-ui --test look   # screenshots, the river's cost and the contrast (see "The look")
node crates/xbt-wallet-ui/tests/js/crypto_test.mjs
scripts/ui/regtest_ui.sh             # real regtest: the agent asks, the UI approves, paid and confirmed on chain; a deny; a sweep
scripts/ui/verify_agp039.sh          # all of the above plus the signer and MCP suites
```
