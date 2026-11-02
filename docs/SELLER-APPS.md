# A seller's own app, inside Lightning Stream

A seller can let buyers use the service's own web page: Jellyfin's web client, the chat page of
an AI model's server, a game, any web service. The buyer presses **Open the app** and the page
runs inside Lightning Stream. Every request it makes is paid for as it goes, at the seller's
price (per MiB, per 1,000 tokens, per request), under a spending limit the buyer sets for the
visit. Nothing in Lightning Stream is specific to one kind of service.

A seller's page is someone else's code running next to a wallet. Most of this design is about
keeping it away from the wallet.

## The parts

```
browser                         the buyer's box                                  the seller
 wallet page  :8482  ── visit, limit, stop ──▶ UI ── /visits ──▶ connector
   └ iframe   :8486  ── every request ───────▶ UI app origin ── /v/<visit>/… ──▶ connector ──▶ signer ── pays, asks ──▶ gateway ──▶ service
```

- **The app origin.** The UI serves seller apps on ports of their own (`XBT_UI_APP_PORTS`, four
  by default: 8486–8489). Each port is an origin: one seller's app at a time has it, and a
  seller keeps its port while it is in use.
- **The visit.** The wallet page asks the connector for a visit: a seller's app address and a
  limit in sats. The connector pays for every request of the visit and refuses the next one once
  the limit is reached. The page shows the limit, what has been spent, and **Stop**.
- **The connector** carries any method, the request's body and the headers a web app needs
  (its cookies, its login, its formats) to the signer, and hands the answer back with its
  status and headers as it streams. Range requests seek as the player does.
- **The signer** pays exactly as it pays for a film: `xbt402_pay`, with the caller's headers
  (`headers`) and the seller's response headers in the head line (`head_headers`).
- **The seller's gateway** sells the app under a route of its own. That route lets through the
  methods and headers the app needs. The service may answer compressed (`accept_gzip`): the
  gateway unpacks it and meters and signs the plain body. It may also add the seller's guest
  login (`upstream_headers`), which never reaches the buyer.
- **Caching.** A browser keeps a free route's answers for an hour where the service says nothing of
  caching (Jellyfin sends its web client with a validator and no `Cache-Control`), so a buyer's next
  visit loads the scripts and styles from the browser instead of over the link. HTML pages are left
  as they are, so an upgraded app's page is never kept stale. A route's `cache` sets how long, in
  seconds (`"cache": 86400` keeps a day; `0` adds nothing). The gateway adds `Cache-Control` only to
  a GET or HEAD whose answer says nothing of caching and sets no cookie: `public, max-age=…` (with a
  `Vary` on the login headers) on a free route for a request with no login, cookie or key in its
  query, and `private, max-age=…` otherwise, always on a priced route or one with buyers' accounts,
  so that a shared cache in front of the shop never serves a paid answer unpaid or one buyer's to
  another. A compressed answer (a free route's text, to a buyer that takes gzip) carries a weak
  `ETag` and no `Accept-Ranges`; an event stream is never compressed.
- **Credit kept ahead.** A visit's requests each hold a small share of its limit, too small for a
  ticket. When a call says the session's credit is low, the visit's next request goes first with
  room for a ticket and asks the signer to top the credit up before it leaves (`top_up_sats`), so
  that no answer is cut where the credit ends. The top-up is best effort: where no ticket can be had at
  once it buys nothing, and the request goes on as it would; it never stops the session.
- **The limit.** A video app priced by the byte is offered a limit for about ten minutes of 1080p at
  its price (1,000 to 20,000 sats); other apps, 1,000. Once four fifths of the limit is used, the
  bar offers **Add**, which raises it by the first limit. At the limit the page waits for the owner,
  and goes on after Add; nothing is raised without a click.

## Why a hostile seller page cannot reach the wallet

- **Another origin.** The app runs on its own port, which the browser treats as another origin
  than the wallet's. It cannot read the wallet page, its storage (where the approval key is kept)
  or its answers. Every wallet answer says `X-Frame-Options: DENY` and
  `Cross-Origin-Resource-Policy: same-origin`, and the wallet page frames only the app ports.
- **Cookies are per host, not per port**, so the wallet's cookies would reach the app's port. The
  wallet's session cookie is `HttpOnly` (no page script reads it), and the app origin strips every
  cookie that is not the app's own before anything goes to the seller. The app's cookies are kept
  apart per port: the proxy gives each a prefix, and passes on only the ones of its own port.
- **No writes from another origin.** A page on the app's port can send a request to the wallet's
  port, and the browser sends the wallet's cookies with it (same site). Every POST to the wallet
  needs the session's CSRF token, which the app cannot read. On top of that, the wallet now
  refuses any request other than GET or HEAD whose `Sec-Fetch-Site` is not `same-origin` or `none`.
- **A visit is a capability.** The app port is reachable on the LAN, so it serves nothing
  without the visit's cookie. The wallet page hands the iframe a one-time code, and the app port
  trades it for an `HttpOnly` cookie of that port. No visit, no request, no payment.
- **Money has two bounds:** the visit's limit, enforced in the connector, and the owner's
  spending rules, enforced in the signer, which apply to every call as always.
- **Storage left behind.** When a port passes to another seller, its first answer clears the
  origin's storage (`Clear-Site-Data: "storage"`), so the next seller does not see the last
  one's.

## The visit's limit, exactly

Many requests of an app run at once. A visit lets one of them at a time buy a ticket: that call
may spend what is left of the limit. The others may only use the credit the seller already
holds for the session: they are sent `credit_only`, so the signer buys no ticket for them, with
what is left of the limit as the most their answer may charge (the seller is told that figure and
stops the answer there). One that needs a ticket before it starts waits for its turn and asks
again. So tickets are bought only within the limit, however many requests run at once. One limit
remains: an answer running on credit that runs out of it part-way ends there, since it may not
buy; the page asks for it again.

A call may also name `max_charge_sats` beside `max_sats`: then `max_sats` bounds what may leave the
wallet for it (a whole ticket included), and `max_charge_sats` what its answer may charge (the
seller is told that figure). A small use of a seller, such as a VPN exit's region check or a
hashrate trial slice, buys the seller's ticket and is charged only its own use; the rest stays as
the session's credit with that seller.

## The seller's side

On Sell, a service gets **Buyers can open its own web page**, with:

- **the app's base path**: what the app sees as `/`. For the AI model it is the model's route,
  `/ai/`. For Jellyfin it is `/`, because the client uses `/web/`, `/Users/`, `/Items/` and more;
- **where it opens** (Jellyfin: `/web/`);
- optionally **a guest login header** the gateway adds to every request, for a service that needs
  a login. For Jellyfin, a user the seller makes for buyers, limited to the libraries on sale.
  Never use an owner or admin account.

**Parts a buyer must not reach.** A web app sold whole also serves its admin pages, other
users' sessions and its settings. The gateway's route takes two lists of path prefixes, matched
on the decoded path and ignoring case (many servers ignore it, and Jellyfin's own client asks
`/users/public` in lower case and `/Users/...` elsewhere):

- `deny_paths` refuse, with 403 before payment and before the service sees the request;
- `allow_paths` serve; when the list is given, a path that starts with none of its entries is
  refused;
- where a path starts with entries of both, **the longest one decides**.

So one route says "all of the app, none of `/users` but the guest's own login and pages". For
Jellyfin, every buyer is the same guest user, and this is the route, checked with Jellyfin 10.10's
web client through a gateway (`crates/xbt-gateway/tests/app_hold.rs`):

```json
{"path": "/", "methods": ["GET", "HEAD", "POST", "DELETE"], "websocket": true,
 "forward_headers": ["authorization", "x-emby-authorization", "x-mediabrowser-token", "x-emby-token"],
 "allow_paths": ["/", "/users/public", "/users/authenticatebyname", "/users/me", "/users/<guest id>",
                 "/system/info/public", "/system/endpoint", "/sessions/capabilities",
                 "/quickconnect/enabled", "/branding/configuration"],
 "deny_paths": ["/users", "/sessions", "/system/", "/devices", "/quickconnect/", "/auth/", "/startup/",
                "/plugins/", "/packages/", "/scheduledtasks/", "/library/", "/environment/", "/branding/",
                "/userplayeditems", "/useritems/"]}
```

Refusing `/Sessions` (but for the client's capabilities) also keeps one buyer's playback progress
from becoming the next buyer's resume point: every buyer is the same Jellyfin user. The guest is a user made for
buyers, shown on the login screen with an empty password and limited to the films on sale, so a
buyer taps it once; it can download and delete nothing.

The web app's manifest (`<link rel=manifest>`) is fetched by the browser without the visit's
cookie, so it is refused: the app cannot be installed from a visit, and nothing else is affected.

**Price video and pages apart.** A route per kind of traffic: the films (`/Videos/`) per MiB, and
the rest of the app per request at a small price, so a page's images and scripts do not cost
what film does.

The listing names the app as a service of kind `app` at the base path, with one item: where it
opens. Apps older than this version skip a kind they do not know (the rule since 0.1.10), so
they still read the rest of the shop.

## Video at 4K

A 4K film streams at about 80 Mbit/s, 10 MiB a second. Three things decide whether it plays without
stalls, measured on the payment path (signer and seller's gateway, with a stand-in Lightning node):

| | Measured | How |
|---|---|---|
| What the path carries | 1.5 to 6 Gbit/s on one host, for 512 MiB to 1 GiB bodies | `cargo test --release -p xbt-signer --test ticket_pay throughput -- --ignored --nocapture` |
| A 4K-rate body (10 MiB/s) with prepaid tickets of 1,000 sat at 20 sat/MiB, each payment taking 1.5 s | 200 MiB at 84 Mbit/s, the source's rate; the longest wait between reads 17 to 91 ms, p99 under 10 ms | the same test, case `/rate10/` |
| The same, before the next ticket was paid ahead | the longest wait 1.6 to 1.9 s, at every ticket | the same test on the commit before |

A prepaid ticket is a Lightning payment, which takes a second or more on a real route. The wallet
used to pay for the next one when the paid bytes ran out, so a body stopped for the length of a
payment at every ticket: every 4.5 s of 4K at 20 sat/MiB. It now pays for it beside the reading,
early by twice the body that arrived while the last payment took (3 s before any was timed), at
most half a ticket's worth ahead, one payment at a time. A refusal of a ticket paid early is tried
again where the ticket is due; only a refusal there ends the answer.

Paying ahead keeps up while half a ticket's worth of body takes longer to arrive than a payment
does. At 20 sat/MiB a 1,000-sat ticket is 50 MiB, so with 1.5 s payments the body may run at up to
about 140 Mbit/s without a pause; above that it waits at each ticket, as before. At 1 sat/MiB the
same holds up to about 2.8 Gbit/s.

**What 4K costs.** At 20 sat/MiB, the films' price today, 4K is about 72,000 sat an hour. A price
for long viewing is about 1 sat/MiB: 4K for about 3,600 sat an hour, 1080p for about 1,800, and a
900-sat ticket lasts about 90 s of 4K. The starter rules' 20,000 sat a day with one seller allow
about five and a half hours of 4K at that price, and a seller that charges by the MiB should say so in its terms.

### 4K and HDR from a media server: what the seller's box has to do

Stream carries what the media server sends; it does not change the picture. Whether a 4K or HDR film
plays well is decided mostly by the media server and the buyer's player, measured in the lab with six
4K clips (HDR10, Dolby Vision, HDR10+ and SDR, 26 to 100 Mbit/s) against the same Jellyfin with no
Stream in the path (Research note "4K and HDR through Stream", 2026-10-30):

- **In a web browser, 4K HEVC is converted on the seller's box.** Browsers generally can't decode
  HEVC, HDR or Dolby Vision, so Jellyfin turns them into 4K H.264 as the buyer watches. On the lab's
  CPU that took 8 to 11 cores to stay ahead of the film (38 to 76 frames a second). **A 2 to 4 core box
  (a typical Umbrel or StartOS machine) cannot convert 4K as it plays.** Turn on hardware transcoding
  in Jellyfin (Dashboard, Playback: Intel Quick Sync, NVIDIA NVENC, AMD or VA-API, whichever the box
  has), or offer a 1080p version for browsers.
- **Turn on tone mapping with it.** Without it, HDR converted for a browser looks washed out.
- **For real HDR, buyers use a player that decodes it directly:** the Jellyfin apps for TVs and
  phones, or mpv or VLC, through a local link (docs/LOCAL-LINKS.md). Then the film passes through
  untouched, at its own bitrate, and the seller's box only sends bytes.
- **Bitrate decides the link.** A streaming-quality 4K film needs about 15 to 25 Mbit/s, a full-disc
  copy 40 to 100. Direct links carry that easily. Through a relay, the seller's upload and the relay
  path are the limit: a shop serves on four link keys, so relayed buyers don't share one relay
  connection (docs/RUN-A-RELAY.md).
- **A seek costs what it costs without Stream:** a seek restarts Jellyfin's conversion, a few
  seconds on the lab's CPU. Over a direct link or https, Stream added under 1.5 s at start and under
  0.5 s at a seek in those runs.

## WebSockets

A web app's live connection (Jellyfin's sync and remote control, a game, a chat) is a WebSocket:
an HTTP request that becomes a two-way byte stream. A route carries them with `"websocket": true`
(priced by the request and the byte, or free). Carrying one through a visit:

- **Every hop carries the upgraded connection as a byte stream**: the app port to the connector,
  the connector to the signer (its stream socket, used both ways), the signer to the seller's
  gateway, and the gateway to the service. Nothing in it reads WebSocket frames, so the leg between
  the signer and the seller can be any two-way byte stream (TCP and TLS today; a QUIC stream).
- **It is paid as it flows.** The route prices it per MiB (both directions counted) or per second.
  The gateway charges each chunk before passing it on, as it charges a body; the signer counts the
  same bytes and seconds at the same price, and releases or buys the next ticket ahead, as for a
  film. Neither side reads money from the other's word: the gateway's receipts close the stream.
- **The visit's limit holds**: an open WebSocket holds a share of what is left of the visit's limit
  (at most 1,000 sat), counted as spent while it is open and then only what it cost. It does not
  hold the turn to buy, which the page's other requests need. Stop closes it.
- **Where it is built**: the shared HTTP server's upgraded answer (`Reply::Upgrade`), the gateway's
  `gateway/websocket.rs`, the signer's `TicketWire::upgrade` (plain TCP, or TLS with the seller's
  certificate checked as for any request; a QUIC stream can implement the same method) and the
  `upgrade` call, the connector's `visit_socket`, and the app port's `socket`. Tests:
  `crates/xbt-gateway/tests/websocket.rs`, `a_websocket_is_carried_both_ways_and_every_byte_paid`
  in the signer's, and the app port's in `crates/xbt-wallet-ui/tests/seller_app.rs`.

## Limits of this version

- A page's absolute links to the seller's base are rewritten to the app port in text answers
  (HTML, scripts, styles, JSON, SVG), as written, without their scheme, or JSON-escaped. A link a
  script builds from pieces at run time still leaves the visit.
- The app ports are plain `http` on the LAN, as the wallet page is. A wallet page opened over
  `https` cannot frame them.
- A long answer that runs out of the session's credit while another request of the visit holds
  the turn to buy is cut short. A player asks again, but a page may not.

## Status (work in progress, paused)

Built and tested on the branch `app/seller-app` (rebased on main at 00d9c40, not merged):

- signer `headers`, `head_headers` and `body_b64`;
- gateway `accept_gzip` and `upstream_headers`;
- the listing kind `app`, the connector's visits, and the UI's app ports, pages and same-site guard;
- Sell's web-page option, the owner's free preview, the package ports and the docs.

Test results: the workspace tests pass (118 suites), and so does clippy on 1.98.0. The seller-app browser test passes 20/20, with the hostile page shown to make the wallet pay when the guard is off.

Left to do:

1. Run the ticket_e2e and ln_rail labs. They were stopped before finishing.
2. Rebase onto main, bump the Umbrel version, then merge and push.
3. Publish and pin the images, and update the public store.
4. Deploy to the box, and turn on the AI model's page there (its offer's `app`, base `/ai/`).
5. StartOS: the app ports in the merged `lightning-stream` package.
6. Jellyfin on the box needs a guest user and the owner's decision first.
