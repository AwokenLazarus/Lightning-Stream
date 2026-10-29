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
holds for the session (`max_sats` 1: a ticket is never 1 sat, so none can be bought). One that
needs a ticket waits for its turn and asks again. So the sats a visit spends never exceed its
limit, however many requests run at once.

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
on the decoded path and ignoring case (many servers ignore it):

- `deny_paths`: refused with 403, before payment and before the service sees the request;
- `allow_paths`: when given, the only paths served; everything else is refused the same way.

For Jellyfin, every buyer is the same guest user, so the guest must not see the server's
sessions, its users or its settings: deny `/Sessions`, `/System/`, `/Devices`, `/QuickConnect/`,
`/Auth/`, `/Startup/`, `/Plugins/`, `/Packages/`, `/ScheduledTasks/`, `/Library/` and
`/Environment/`, `/Branding/Configuration`, `/UserPlayedItems` and `/UserItems/`, and let
through of `/Users/` only `/Users/Public`, `/Users/AuthenticateByName`, `/Users/Me` and the guest's
own `/Users/<guest id>/`. Denying `/Sessions` also keeps one buyer's playback progress from becoming
the next buyer's resume point: every buyer is the same Jellyfin user. The guest is a user made for
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
900-sat ticket lasts about 90 s of 4K. The starter rules' 10,000 sat a day allow a little under
three hours of 4K at that price, and a seller that charges by the MiB should say so in its terms.

## WebSockets: the design

A web app's live connection (Jellyfin's sync and remote control, a game, a chat) is a WebSocket:
an HTTP request that becomes a two-way byte stream. Carrying one through a visit:

- **Every hop carries the upgraded connection as a byte stream**: the app port to the connector,
  the connector to the signer (its stream socket, used both ways), the signer to the seller's
  gateway, and the gateway to the service. Nothing in it reads WebSocket frames, so the leg between
  the signer and the seller can be any two-way byte stream (TCP and TLS today; a QUIC stream).
- **It is paid as it flows.** The route prices it per MiB (both directions counted) or per second.
  The gateway charges each chunk before passing it on, as it charges a body; the signer counts the
  same bytes and seconds at the same price, and releases or buys the next ticket ahead, as for a
  film. Neither side reads money from the other's word: the gateway's receipts close the stream.
- **The visit's limit holds**: the upgraded connection is one call of the visit, with the turn to
  buy while it needs a ticket. Stop closes it.
- **What it needs built**: an upgraded answer in the shared HTTP server (the head written, then the
  connection handed to the handler); a two-way call in the signer's connection to the seller; the
  gateway's upgraded route and its upstream; and the connector and app port passing the upgrade on.

## Limits of this version

- **WebSockets are not carried yet** (the design is above). A request to upgrade is answered
  `501`. Jellyfin's web client works without its socket, but it does not get live updates. A game
  that needs a socket will not work yet.
- The app sees the box's address and an app port. A page that builds absolute links to the
  seller's own host name leaves the visit. Relative links and links to its own `/` work.
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
