# Local links: a bought service as an address on your own network

A seller's web app (Jellyfin, a model's chat page, any web service) is the main way people use
Lightning Stream. The app inside the page (docs/SELLER-APPS.md) needs the Lightning Stream page open.
A **local link** does not: it is an address on the buyer's own network, such as
`http://192.168.1.20:33530/l/Xr7…/`, that any browser or app on that network can use as the
service itself. Paste it into the Jellyfin app on a TV or a phone as the server, and the app talks
to the seller's Jellyfin through it, paid as it goes, within the limit the owner set for the link.

This is the design. It is built on the visit and the app-port machinery that exist now.

## What the owner does

On a bought service in Browse: **Make a local link**, with

- **a spending limit** for the link, in sats (and optionally per day);
- **a name** ("Living room TV").

The app shows the link, as text with a **Copy** button and as a QR code, under the service's and
the seller's names as Browse shows them (with the shop's key for a shop reached by a direct link),
with one line on what to do with it: "Use this in the Jellyfin app on your TV: add a server with
this address". The port and the token are under Advanced. The list of links shows, for each:

- what it has spent, and its limit, live;
- **Paused** when the limit is reached: nothing more is paid until the owner raises the limit;
- **Revoke**: one click, the link stops at once, and its address answers nothing again.

## The address

```
http://<the box's LAN address>:<links port>/l/<token>/
```

- **One port for all links** (33530 by default, `XBT_UI_LINKS_PORT`), so a package opens one port
  and a firewall rule covers every link. The token in the path tells the links apart.
- **The token is the credential**: 128 random bits, base64url (22 characters). It is shown only to
  the owner, and kept hashed on disk, so a copy of the files does not give the links away. It is
  **never written to a log**: every log line that has a link's path writes it as `/l/…/`. Nothing
  past the links port sees it: the request that goes on to the seller has the path without it.
- **The page says it plainly**: anyone who has the address can spend up to the link's limit, so
  share it only with your own devices, and revoke it if it leaks.
- **Why in the path:** native apps take a server address and add their own paths to it, keeping any
  path in it (Jellyfin's apps keep a base path, as for a reverse proxy at `/jellyfin`). They cannot
  do a cookie exchange or open a page first. A path is the one place every client keeps.
- Everything under the link is the seller's app at its base: `/l/<token>/web/` is Jellyfin's
  `/web/`, `/l/<token>/Users/AuthenticateByName` its login, and so on. Absolute links to the seller
  in its pages are rewritten to the link, as in the app port.

## Bound to the LAN by default

- The links port listens on the box's LAN addresses only, never on a public interface.
  - **Umbrel**: the compose file publishes `33530:33530` on the service that listens, as the MCP
    port (33511) and the hashrate ports are published; it is on the LAN at `http://<box>.local:33530`,
    with no Umbrel login in front of it, so the token is its only gate.
  - **StartOS**: an interface `locallinks` bound to the port, of type `api` (not a web page), with
    no public domain suggested.
  - **Linux**: the host's port, documented in `docs/LINUX.md`; bound to the LAN, never `0.0.0.0` on
    a public host without a warning.
  - Ports beside it: 33511 (MCP), 33512/udp (the gateway's direct links), 33521–33524 (app ports),
    33540 (the local AI endpoint).
- **Host check:** a request whose `Host` is not one of the box's own addresses or names is
  refused (the same `allowed_hosts` rule the UI uses), against a DNS-rebinding page on the LAN.
- **Peer check**, optional: only private addresses (RFC 1918, link-local, loopback, ULA) are
  served, unless the owner turns on "reachable from outside my network" for a link, with a warning.

## The same-site rule, extended

The links port is its own origin: it shares no cookie with the wallet's page, and the wallet's
page never frames it. What reaches the wallet from a link is only payments, inside the link's
limit, for the one seller the link is for:

- a link pays only its own seller, at its base: the token selects the seller, not the request;
- `Origin` or `Sec-Fetch-Site` from another site on a request that changes state (not a GET or
  HEAD) is refused, except for the seller's own app pages served on the link itself;
- the response carries `Referrer-Policy: no-referrer`, so the token is not sent to other sites;
- a seller's `Set-Cookie` is kept under the link's own path (`Path=/l/<token>/`).

## How it is paid

A link is a long-lived visit (docs/SELLER-APPS.md, "The visit's limit, exactly"): every request
goes through the connector, one request at a time may buy a ticket, and the sum the signer charges
the link's requests never exceeds its limit. What changes:

- **It persists**: kept in a file (the token's hash, the seller's base, the limit, what was spent,
  paused or revoked), and survives a restart of the app.
- **It pauses at the limit** instead of ending: requests get `402` with a short text ("This link's
  spending limit is reached: raise it in Lightning Stream"), and resume when the owner raises it.
- **Spend is counted from the signer's answers**, the same numbers the Activity page shows.

## Jellyfin's apps

What they need, and what the link gives them (checked against Jellyfin 10.10 with `~/jellyfin-test`):

- **The server address** is the link. They ask `/System/Info/Public`, show the server, then log in
  with `/Users/AuthenticateByName` and send the token they get in `Authorization` (or
  `X-Emby-Authorization`) on every request: these headers pass through the link and the gateway.
- **The guest**: the seller's buyer user, shown on the login screen with an empty password. The
  seller's `allow_paths`/`deny_paths` keep admin, sessions and other users out (docs/SELLER-APPS.md).
- **The WebSocket** (`/socket`) for sync and remote control: carried and paid as bytes, both ways.
- **Video**: the apps ask for direct play when the codec fits the device, and for HLS transcodes
  otherwise; both are ordinary HTTP with ranges, priced on the seller's `/Videos/` route.

## One store for links and keys

Local links and the local AI endpoint's keys (port 33540, `Authorization: Bearer sk-stream-…`) are
the same thing: a secret a device on the LAN holds, with a limit, its spending and a revoke. They
share one store (`crates/lightning-stream/src/credentials.rs`) and one page, "Your links and keys":
each entry has a kind (link or AI key), a name, its secret's SHA-256, its limit (and optionally a
daily one), what it spent in msat, whether it is paused or revoked, when it was made, and for a
link the seller's base. Each server checks only its own kind.

## What is built and what is not

Built: the gateway's path lists, WebSockets on every hop (gateway, signer, connector, app port),
the app port's link rewriting, and the visit with its limit. To build for links: the links port
and its token routing on the shared store, pause and resume, the Browse and links pages, and the
package ports.
