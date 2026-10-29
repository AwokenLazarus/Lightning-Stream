# Changelog

Lightning Stream versions, newest first. One version number covers the Umbrel app, the StartOS
package (from 0.1.14) and the Linux package (from 0.1.12). Dates are UTC.

Lightning Stream is early software. It runs on mainnet; use small amounts.

## 0.1.19 (2026-10-29)

**Paying**
- A session that is busy spending its credit stays open. The wallet closed a session ten minutes
  after its last ticket purchase even while it was still being paid from that ticket's credit, so a
  long film or rental bought a new ticket every ten minutes and left the old credit at the seller.
  Every paid request now counts as use, and credit left by a session that did close is spent first
  by the next one with that seller.

**A local AI address**
- New: Services, AI. The app gives this box an OpenAI-compatible address (`/v1`) on your network, so
  any AI app or agent that speaks that API can use the AI models of sellers you allow, paid per
  token within your spending rules. Each program gets its own key with a total and a daily limit,
  and can be revoked. The app picks the cheapest seller that answers, moves to the next one if a
  seller fails before it answers (never paying twice for one answer), and you can prefer or block
  sellers. On Linux the address is local to the machine unless you open it to your network.
- Known limit: a very long answer can pause briefly while the next ticket is bought.

**Hashrate**
- A rental survives a short break in the link between hashtaker and hashmaker: the miner goes back to
  its own pool for the moment, and the rental carries on when the link returns, with no slice paid
  twice.
- A hashtaker whose wallet is restarting waits for it before a slice goes unpaid.
- Offers show the price per TH/s per day beside the hourly figure.
- The hashmaker measures each miner's speed over five minutes instead of one, which steadies it.

**The look**
- A new, calmer theme: new fonts (Inter and JetBrains Mono, carried in the app), a new mark and app
  icon, a quieter background, and a click that runs along the streams like a spark. Light and dark,
  and no motion for those who ask for less.

## 0.1.18 (2026-10-29)

**Playing films**
- Closing or pausing the player stops the paying. A browser's video reads ahead of the picture, and
  a paused one went on filling its buffer, so closing the player half a minute in could cost a whole
  ticket. The wallet now asks a seller for a film at most 4 MiB at a time, and the player lets go of
  the film when it is paused for a few seconds, has ended, or its page is left; pressing play takes
  it up where it was. However a player goes away, it is charged at most one 4 MiB part beyond what
  it received.

**Spending rules**
- With the starter rules, a buyer can play a film and then ask the AI of the same shop straight
  away. The rule that stops one large payment from being cut into small ones also counted the
  wallet's own ticket refills, so a second 900-sat ticket to one shop within ten minutes was
  refused. Tickets are now bounded by the ticket budgets, the cap on one seller and the daily,
  weekly and counterparty limits, and a payment cut in two is still caught.

**The app**
- Live connections show what a stream has used and the credit left with the seller as it plays,
  and whether anything is playing.
- The pages no longer say that money paid ahead comes back: credit on a prepaid ticket stays with
  that seller and is spent first next time.
- For agents: `ticket_stop` takes a seller's address as well as a session.

**StartOS**
- The guide says how to add our registry: Marketplace, then the registry menu, then Add,
  `https://registry.lazarus-xbt.xyz/`.

## 0.1.17 (2026-10-27)

**Paying**
- A wallet whose channel goes straight to a shop's node can pay it. A shop that sells by BOLT 12 offer
  hands out invoices whose hidden route can enter through another node; when the wallet's node finds
  no way there, the failed try (nothing was sent) is written off and the shop's ordinary invoice for
  the same ticket or win is paid instead, once. A payment the shop itself refused is not retried.

**If you are on an earlier version**
- Until 0.1.17 is installed, open your channel to a well-connected public node, such as lazarus-xbt
  (it takes channels of 20,000 sats or more), not straight to the shop.
- If you added our shop before 0.1.16, press **Check for updates** on it under Services, Sellers,
  before **Allow this seller to be paid**: the list saved before then names the shop's old address.

## 0.1.16 (2026-10-27)

**Selling**
- A shop that moved to a new address is listed there whole: items saved at its old address move with
  it, each time the shop is saved or the app starts.
- A wallet can allow a moved shop to be paid. It reads the seller's Lightning node from each service's
  address and an item of each, at the seller's address, and asks the front page last (a shop need not
  price it). Before, it said "the seller asked for no payment at its address".

**Paying**
- A seller that charges a call more than its limit is stopped. The wallet sends the call's limit with
  each paid request; a seller that ignores it (one of before 0.1.15) and charges past it gets nothing
  more in that session, the wallet page says what happened with the numbers, and the seller's signed
  receipt is kept in the wallet's records. Such a seller can take at most the credit it already held.

**Linux package**
- The signer starts while your XBT node is stopped or not set up yet, instead of restarting in a loop.
  `LS_CHAIN` in `.env` says the chain (`main` unless set), and the wallet page says when the node does
  not answer.
- The signer waits a moment for the anchor witness at start, so a first start is clean.
- `install.sh`: an empty answer to the admin macaroon question skips that step, as it says; a path with
  no file is said to be missing, not blamed on the Lightning node.
- `.env` holds a plain value as it is, so the random password is what you see; the install's last lines
  say exactly what to type.
- The guide: how a node that uses only its cookie gives the app a login (`rpcauth`, with a check), and
  that some nodes take only channels of 100,000 sats or more.

**Wording**
- The Your node page says the app is tested on mainnet with small amounts only.
- Start paying while the wallet restarts says it is starting, not "Nothing to confirm on a test
  network".
- A signed rules change that waits for a restart says how to restart on your platform (Umbrel,
  StartOS or Linux), and names no test-chain setting on mainnet.
- The signer's log sends you to the setup page for the enrolment code, not to a file inside its
  container.

## 0.1.15 (2026-10-27)

**Paying on a new wallet**
- A new wallet on mainnet can pay right after setup. It asks a seller for a ticket small enough not to
  need your approval, and refuses only when even the seller's smallest ticket is too large, giving the
  numbers.
- Setup asks you to confirm paying with real money straight after the spending rules. Home no longer
  says the app is ready before you do.
- If your node holds more than your rules allow, the Lightning page says how much, and raises the
  limit in one click for you to sign.
- Credit left with a seller is used first, after a restart and under any of the shop's addresses,
  instead of buying a new ticket.
- A stream you stop early costs no more than the limit you set for it.
- Agents can buy part of a file or film (a byte range).
- A program using the wallet can give up a session's leftover credit, to start clean.

**Security**
- **Another page could make the wallet pay a seller you had allowed.** A page served by another app on
  the same box (for example another Umbrel app), or on Linux any web page open in a browser on the same
  machine, could start a stream through the wallet. It stayed within your signed spending rules and
  only reached sellers you had allowed, but you hadn't asked for it. The wallet now answers such
  requests only by opening its home page, the player's stream links carry a token no other page can
  read, and the Linux connector refuses requests that come from a web page.

**Fixes from reviews of the payment code**
- Two parts of the wallet could wait on each other forever when a refill overlapped a status check.
- A shop that changed its ticket size could resize tickets still open after a restart, and drop
  prepaid ones with no credit.
- A buyer coming back to a shop after a few quiet minutes could have their new tickets cancelled. No
  money was lost (the payment went back), but the buy failed.
- A payment note chosen by a program using the wallet could escape the per-session speed limit.
- An error in cleaning up the wallet's records after a payment had gone through could be reported as
  a failed payment. For an on-chain send, a retry could then pay twice.
- Tidying the wallet's ticket book could forget finished payments that weekly limits still count.
- After a restart, a stuck payment or a restore, the wallet could undercount what it had spent, or
  send a ticket it had already marked failed.
- A seller that never revealed its lottery draws could keep a buy open forever.
- If the wallet's Lightning payment record could not be read, it was treated as empty and later
  overwritten. The wallet now stops paying instead.
- The plain-words summary of a spending-rules change could hide a change inside a section, such as a
  seller's Lightning node being swapped. Every changed setting is now listed, and nothing is cut short.
- Hot wallet: a coin already spent could be counted, a sweep the node had sent could be reported as
  failed, and a slow scan could hold up the wallet's status.

**Other**
- The real-money confirmation no longer says the software has only run on test chains.
- After a change that waits for a restart, the app says how to restart it on your platform (on Linux,
  `docker compose restart` in the install folder).
- **Linux guide:** the first run includes the "Pay with real money" step, and a node that has only
  its cookie file gets an `rpcauth` line for the app.
- StartOS: 0.1.15 alongside the Umbrel app.

## 0.1.14 (2026-10-27)

- Your shop is published on Nostr as soon as it has an https address, with nothing to set by hand.
- Four default relays: relay.lazarus-xbt.xyz, which takes only Lightning Stream listings, then
  relay.kilombino.com, relay.damus.io and nos.lol.
- The suggested seller is at its new address, https://stream.lazarus-xbt.xyz. When you change your
  shop's address, the old one keeps working for buyers who saved it, hashrate included.
- A new shop sells 900-sat tickets, so a buyer on the safe starter rules can pay it right away.
- **StartOS:** the first public package, one `lightning-stream` package with everything in it, in our
  registry at https://registry.lazarus-xbt.xyz. It asks Lightning Fork for its own narrow node key
  through Lightning Fork's app-access grant (thanks to Paul for building the grant), so there is no key
  to copy by hand. Lightning Fork comes from Paul's StartOS registry; see docs/STARTOS.md.
- **Linux guide:** a "Before you buy: get a channel" section.

## 0.1.13 (2026-10-27)

- Signing the safe starter rules on mainnet now lets the app pay. They set how much your Lightning node
  may hold (twice what it holds now, at least 100,000 sats), which the wallet needs before it pays
  through a mainnet node. If paying is on but that limit is missing, Spending rules fills it in for
  you to sign.
- With paying off, Spending rules opens on the starter rules. On mainnet the form never offers the
  large built-in limits meant for test chains.
- Your node page says why it can't pay yet, in plain words.
- The key backup file says it is not your passphrase. A wrong passphrase leads to restoring the key
  from that file with a new one.
- Hashrate offers are read and published on a third relay, relay.kilombino.com (thanks to Kilombino).

## 0.1.12 (2026-10-27)

- The two sides of hashrate renting have names: the **hashmaker** brings the miners and lists them,
  the **hashtaker** rents them into its own DATUM Gateway (names from Kilombino). Your settings and
  rentals carry over.
- **Linux package:** Lightning Stream beside your own nodes, with Docker Compose, from the published
  images. See docs/LINUX.md.

## 0.1.11 (2026-10-26)

- Signing the safe starter rules now turns paying on. Before, a new install could not pay.
- The first run speaks plainly: the rules review lists each change in a sentence with its unit, Home
  and Your node agree on whether the node is connected, the approval key's backup step says up front
  what it needs, and an app with nothing to sell yet shows as healthy.
- Your node lists the keys to revoke on the node before an uninstall.
- The app's images are published, so a fresh install can pull them.

## 0.1.10 (2026-10-26)

- A spending limit is now a hard cap, routing fees included: when the next ticket would go over it,
  nothing more is paid.
- Buyers can ask for smaller tickets (down to 546 sats) to fit their limit, and your shop sells them.
- Listings keep working when sellers add new kinds of service: an app shows the services it knows and
  leaves out the rest.

## 0.1.9 (2026-10-26)

- Changes an update makes to what your shop lists take effect when the app starts, without pressing
  Save on Sell.

## 0.1.8 (2026-10-26)

- Hashrate is listed beside your other services when you rent out your miners. Browse has a Hashrate
  category that leads to Rent hashrate.
- Sell, Hashrate explains how to give renters an address (forward TCP port 23341 to the box). A new
  address is published within a minute.

## 0.1.7 (2026-10-26)

- Your hashrate offer goes on public listings only once you give the address renters use to reach
  your miners, and is published again only when what you offer changes, not with every wobble of the
  measured hashrate.

## 0.1.6 (2026-10-26)

- Rent out this box's miners and rent other people's (Sell and Services, Hashrate). Idle miners hash
  for your own pool; each rental takes whole miners and pays per piece of work, after the work is
  delivered.

## 0.1.5 (2026-10-26)

- **Security:** the app skipped its password for a peer named like the box's login proxy. umbrelOS
  2.0 runs no such container, so another app on the box could have taken the name and opened the app
  without the password. Log in with the app password Umbrel shows for this app.

## 0.1.4 (2026-10-26)

- No setup to connect your Lightning node: the app makes its own narrow keys through the node.
- The app password is shown on the app's page in the Umbrel dashboard, with no codes to read from
  logs.
- An approval key backup you can download.
- "Allow this seller" in one signature.
- Services on this box are offered on the Sell page, with help getting an https address.
- A player that says why something doesn't play.
- A free preview of your own shop (a box can't buy from itself).

## 0.1.3 (2026-10-26)

- A calmer background, no flash between pages, and a top bar the page scrolls under.
- Adding a seller that prices each item separately works.

## 0.1.2 (2026-10-26)

- The Services page can read sellers' signed listings from two public Nostr relays (opt-in).

## 0.1.1 (2026-10-26)

- Laid out for any service (media, AI models, other web services), in plain words, with five places:
  Services, Sell, Wallet, Apps & agents and Settings. Selling is part of the main page.

## 0.1.0 (2026-10-26)

- The wallet, the connector and the gateway in one Umbrel app.

## Thanks

To the people who reviewed the design (see the README), to Paul for Lightning Fork, Knots-BLAKE2b
and the StartOS app-access grant, and to Kilombino for the hashmaker and hashtaker names and a relay.
