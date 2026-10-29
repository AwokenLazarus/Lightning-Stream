# How many buyers a service takes at once

A seller's box has so much processor and bandwidth. A media server converting films for five
buyers at once can be too slow for all five. A route's `capacity` lets the seller say how much the
service carries at once, so that the next buyer is asked to come back shortly instead of slowing
everyone down.

## What the seller sets

On the Sell page, under a service, "How many buyers at once". In the gateway's config, a route's
`capacity` object. Every limit is off when not set.

| Setting | On the Sell page | What it counts |
|---|---|---|
| `max_buyers` | Most buyers at once | Buyers (sessions) that used the route in the last 5 minutes, or have one of its answers open. Priced routes only: a free route has no buyers to count. |
| `max_streams` | Most streams at once | Long answers open at once, over all buyers: a film, a WebSocket, an event stream, any body longer than 8 MiB or of no stated length that is not a page's ordinary part (not text, JSON, script or an image). |
| `max_streams_per_buyer` | Advanced: most streams for one buyer | Long answers open at once for one buyer. |
| `max_mbit` | Advanced: most Mbit/s together | The route's answers' rate over the last 10 seconds; above it, no new long answer starts. |

A service's web page (docs/SELLER-APPS.md) counts with its service: both routes get the same
`capacity`. For a media server such as Jellyfin on a small box, 5 buyers and 3 streams is a good
start; each 4K film the server converts can use several processor cores.

```json
{"path": "/", "price": {"byte_msat": 1000, "per_bytes": 1048576}, "capacity": {"max_buyers": 5, "max_streams": 3}}
```

## What a buyer turned away sees

A `503` with `Retry-After: 30` and this body:

```json
{"error": "busy", "detail": "This shop is busy (3 of 3 streams in use). Try again in a moment.",
 "busy": {"scope": "streams", "inUse": 3, "limit": 3, "retryAfter": 30}}
```

`scope` is `buyers`, `streams`, `buyer_streams` or `bandwidth`.

- **A new buyer is turned away before buying or paying anything.** A new visit asking the price gets
  the 503 instead of the 402, so it gets no terms to buy a ticket with. A paid request from a buyer
  the route does not serve yet is authenticated (its sequence number used, so the buyer's count
  stays in step) and turned away before a ticket's secret it carries is taken: the ticket stays
  held, then is cancelled or expires as any unused one, and nothing of it is the seller's. A buyer
  who already has credit with the shop keeps it for later.
- **A long answer over a stream limit is not started.** The service's answer is closed unread, and
  what the request had reserved from the buyer's credit is given back: nothing is charged.
- **No buyer already served is cut off to make room.** A buyer the route serves goes on, its page's
  ordinary parts included; only a new long answer can be refused for a stream limit.

The wallet tells it in its own words, with the counts read as bounded numbers and never the seller's
text: the rule `seller_busy`, `charged_sats` 0, and `busy` with the scope and counts, for an agent
(MCP) to read. In a seller's web page opened in the app, the page says the shop is busy and that
nothing was charged; loading it again tries again.

## Where it shows

- The gateway's `/services` document gives each route with a `capacity` its counts now:
  `buyers`, `maxBuyers`, `streams`, `maxStreams`, `maxStreamsPerBuyer`, `mbit`, `maxMbit` and `busy`.
  It is not signed and is read fresh, so it can change from one minute to the next.
- The Sell page shows each service's buyers and streams now, and "Full" when it turns new buyers away.
- The signed listing (`listing/1`, on the shop's address and on Nostr) is unchanged. Its readers
  refuse keys they do not know, so a capacity there would make every older app reject the listing.

## Limits of this version

- The counts are in the gateway's memory. A restarted gateway counts no one until its buyers come
  back.
- Transcode caps, a queue, and an app that retries by itself come later (0.1.21).
- A buyer that bought tickets with the shop's terms from `/services` (not from a 402) and is then
  turned away keeps those tickets as credit with the shop or as held tickets that expire unused.
