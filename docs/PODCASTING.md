# Podcasts, per-minute pricing and boosts (design, not built)

Status: a plan for after 0.2.14. Nothing here is in the app yet. Tracking issues are linked at the end.

## Why

Lightning Stream already sells media paid as it plays: a seller's own web app (Jellyfin) or a folder of
files, by the megabyte, each answer metered and receipted, paid from the buyer's own node to the seller's.
Two things people expect from Lightning media are missing:

- **A price by the minute.** Audio and video are easier to price per minute than per megabyte.
- **Boosts.** A one-off payment, with a short message, on top of what the meter charges.

The open **Podcasting 2.0** standard has both, and lets any podcast feed say who gets paid while it plays.
Adopting it for Bitcoin (XBT) gives creators a reason to run Lightning Stream, and gives listeners a
non-custodial way to pay them.

## 1. Per-minute pricing (small)

The meters already count seconds. A seller of audio or video picks the unit: per MiB (as today) or per minute.

- The listing carries the per-minute price, and Browse shows it as "2 sat a minute".
- The connector charges per second of playback, at the per-minute rate divided by 60, through the same
  tickets and lottery as today, with the same receipts.
- A seek or pause stops the clock. The charge follows what was played, not what was downloaded.
- What isn't changed: the spending rules, caps and receipts are the same as for per-MiB.

## 2. Boosts (small)

A boost is a one-off payment from a buyer to a shop or creator, with an optional message of up to 280
characters.

- From any service page or player: "Boost 1,000 sat" plus a message.
- It's paid like any other payment, within the owner's spending rules. A new task, `boosts`, has its own
  daily budget, 0 by default until the owner sets one.
- The seller sees boosts with their messages on the Wallet page. The seller can mute a sender, and messages
  are shown as plain text only.
- On the wire, a boost to a shop is a normal paid request to a `/boost` route on the shop's gateway, so it
  needs no new payment type. A boost to a podcast's value block uses keysend (section 3).

## 3. Podcasting 2.0

### What it is

- **Value block.** An open extension to podcast RSS feeds (the `podcast:` namespace, maintained by the
  Podcast Index project). Its `<podcast:value>` block names who gets paid while an episode plays:
  `<podcast:valueRecipient>` entries, each a Lightning node (paid by keysend) or a Lightning address, each with
  a split, plus a suggested rate.
- **Streaming.** While the episode plays, the listener's app sends a payment about once a minute to each
  recipient by its split. Each payment carries a record of the show, episode, timestamp and app (bLIP-10,
  TLV record 7629169).
- **Boosts and time splits.** A *boost* (a "boostagram") is a one-off payment with a message.
  `<podcast:valueTimeSplit>` pays a guest only during their segment.
- **Podcast Index.** An open directory with an API for finding feeds and their value blocks.

### The network question

Today's value blocks pay recipients on the **SHA-256 fork's** Lightning network. Lightning Stream pays on
**XBT Lightning**: same software family, different chain. A node on one can't pay a node on the other.

The value tag has no field saying which network, so XBT recipients must be marked:

- `<podcast:value type="lightning" method="keysend" network="xbt">`.
  - Existing apps ignore the unknown attribute, so they would still try those recipients and fail harmlessly.
  - Or use a new `type`, e.g. `type="lightning-xbt"`, which existing apps skip outright.
  - Prefer the new `type`, and propose it to the namespace maintainers.
- Lightning Stream pays only XBT recipients, and shows SHA-256-only feeds as "pays on another network".

So there is no existing audience to plug into. XBT creators and XBT value blocks start from zero.

### Phase A: creators publish (build first)

- A **Podcast** service on the Sell page. Point it at a folder of episodes, give the show a title and image,
  and set the splits (yourself, guests, an app share). It publishes a standard RSS feed with an XBT value block
  naming the box's node.
- The feed and episodes are served free over plain https, so any podcast app can play them. The value block
  is how listeners pay.
  - Optionally, listeners using Lightning Stream pay per minute (section 1), and others listen free.
- The box's node accepts keysend. On Umbrel this is one Lightning Fork setting; the app checks it and says
  if it's off.
- The Wallet lists streams and boosts received: show, episode, amount and message.

### Phase B: listeners pay (the player)

- A **Podcasts** page in the wallet: paste a feed URL or search the Podcast Index, then play an episode in the
  browser.
- While it plays, the app streams sats per minute to the XBT recipients by their splits. Boosts carry
  messages. Guests are paid per time split.
- Everything stays within the owner's signed spending rules, under a `podcasts` task with its own budget,
  as hashrate rentals have. Each recipient counts as a counterparty.
- **New payment path: keysend.** The wallet pays only invoices today. Keysend sends to a node ID with no
  invoice, carrying the payer's own preimage and the bLIP-10 record. This is money-path work and needs its own
  review and tests:
  - limits per payment and per minute;
  - no double send on retry;
  - a lost answer is never resent.

### Phase C: discovery

- Submit Lightning Stream feeds to the Podcast Index.
- Show shows that pay on XBT in Browse, next to shops.

### Risks and limits

- **No audience yet.** It only pays off if a few XBT shows exist. Lazarus and Lightning Stream's own show
  could be the first.
- **Keysend is a new payment path.** It needs review and caps (above).
- **Boost spam.** Messages are capped in length and rate, and can be muted. They're never rendered as HTML.
- **Privacy.** Keysend reveals no sender unless the bLIP-10 record names one. The app leaves the sender name
  empty by default.

## Order

1. Per-minute pricing (section 1).
2. Boosts (section 2).
3. Phase A.
4. Phase B.
5. Phase C.
