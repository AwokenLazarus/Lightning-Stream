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

The listing names the app as a service of kind `app` at the base path, with one item: where it
opens. Apps older than this version skip a kind they do not know (the rule since 0.1.10), so
they still read the rest of the shop.

## Limits of this version

- **WebSockets are not carried.** A request to upgrade is answered `501`. Jellyfin's web client
  works without its socket, but it does not get live updates. A game that needs a socket will not
  work yet. Carrying one needs a metered two-way stream through the gateway and the signer.
- The app sees the box's address and an app port. A page that builds absolute links to the
  seller's own host name leaves the visit. Relative links and links to its own `/` work.
- The app ports are plain `http` on the LAN, as the wallet page is. A wallet page opened over
  `https` cannot frame them.
- A long answer that runs out of the session's credit while another request of the visit holds
  the turn to buy is cut short. A player asks again, but a page may not.
