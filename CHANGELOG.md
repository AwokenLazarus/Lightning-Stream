# Changelog

Lightning Stream versions, newest first. One version number covers the Umbrel app, the StartOS
package (from 0.1.14) and the Linux package (from 0.1.12). Dates are UTC.

Lightning Stream is early software. It runs on mainnet; use small amounts.

## 0.1.20 (2026-10-31)

**Shops without a web address**
- A shop can be reached by its key alone, over an encrypted direct link, with no hostname,
  Cloudflare or port forward. The shop's node vouches for the link, and buyers check that before
  sending anything. Where the two ends can't connect directly, a relay carries the traffic, and it
  never sees what is sent. In private mode a shop uses relays only, so buyers never learn its
  address.
- The relay is built into Stream, off by default. Shops announce the relays they use, and buyers
  choose among them.
- A shop reached only by its key can list web apps and Files from the Sell page.
- The AI address and agents can pay shops reached by key.
- The AI page shows prices for shops reached by key.
- A seller added, updated or removed on the Services page reaches the AI address at once.
- Two AI sellers with the same name are told apart by their shop key or address, so preferring or
  blocking one no longer hits the other.
- After a restart, the AI address finds sellers' models within seconds, instead of answering
  "model not found" for about five minutes.
- A shop saved before its first service is now published on Nostr, so buyers can find it.
- A web app such as Jellyfin works through a relay over a slow path (a VPN, a far-away buyer); the
  wallet keeps a buyer signed in and re-asks a price only when needed.
- A shop reached through relays serves on four keys, each with its own relay connection, so its
  relayed buyers share several connections instead of one.

**Sellers' own web apps**
- A web app that keeps buyer accounts opens when the buyer's session began on another of the shop's
  routes, or the shop has restarted: the wallet says who it is and asks again, instead of showing a
  raw 403. A buyer who stays anonymous at a shop stays so on all its routes and is told why such a
  page is refused, with nothing charged for that request.
- A seller's whole web app, for example Jellyfin with its full interface, can be sold through
  Stream, paid as it is used, with an account made for each buyer.
- The built-in player is gone. A media server is shared as a web app, and a new **Files** service
  shares a folder: buyers pay per GB to download a file or open it in their own player.
- On Umbrel, Files shares a folder from the box's Downloads, which the Files app shows; read-only.
- On StartOS, Files can share a folder from File Browser, read-only; File Browser stays optional.
- On StartOS, a shop reached directly through the app can be bought from: Sell asks for a third key,
  link signing (`message:write` only), so the node vouches for the shop's link. Before, no buyer could
  allow such a shop. A link signing key pasted on a running shop is used within a minute, with no restart.
- Saving the shop with nothing changed no longer restarts it (it cut buyers' sessions), even on a later day.
- A shop switched from being reached directly to a web address no longer keeps serving its direct link.
- Files from File Browser shares only File Browser's own folder, including the files you upload to
  it (File Browser keeps those readable by its own group only; Stream reads them through that group).

**Paying**
- A paid download or film no longer ends when a loaded node or a slow route is late with its next
  ticket, or when the wallet's chain or Lightning node stops answering for a moment. The wallet waits
  up to 12 s, all told, while the seller keeps the answer open, and releases nothing for an answer the
  seller has closed. A whole paid call now has one deadline of 50 s, so its caller gets a plain answer
  in time, and a stop ends the answer at once.
- An answer priced by the second is charged for that wait, by the clock: at 400 sat a second, an answer
  of about 3,600 sat came to 4,800 sat with its ticket 11 s late.
- A seller that keeps not showing the wallet's tickets, and a ticket stuck on its way for over 90 s,
  now end the session, and the reply says which.
- A small payment works from no credit at a shop: the wallet buys a ticket sized to what the call may
  be charged, while the call itself stays capped at that charge.
- Stopping a call ends it at once: nothing more is booked or paid for that session once the stop
  begins, and a prepaid ticket or win paid without its proof now counts in what the call charged.
- A file is never read past the size its listing shows. From a 0.1.20 shop, a file that grew after
  it was listed is refused before any of it is sent, costing nothing on a route priced by size, such
  as Files, and only the request's price on a route with one; one whose server states no size is
  stopped at the listed size. From an older shop, the wallet stops at the listed size and
  pays only for what was already on its way.
- A download, film or AI answer streamed to you is no longer cut after 50 seconds while it is still
  arriving: it runs as long as it delivers, within its limit. A seller that goes quiet is stopped
  after 30 seconds, and any answer the wallet stops early now reaches your program as cut short,
  never as a smaller file that looks whole.
- A new zero-conf channel carries payments once its funding confirms.
- The price a shop shows in its listing is now the most your wallet will pay it: one that asks more
  than it advertised is refused before anything is paid. This covers web apps, Files, AI, hashrate
  and VPN exits.
- A shop caught over-charging is blocked until you lift the block (with your signature); a shop that
  loses requests is held to what they could have cost; each shop has a daily cap. Existing wallets
  get a daily cap of 20,000 sats per shop until changed.
- Several requests to one seller run side by side in one session, each exactly accounted, so a busy
  page no longer waits on itself. Whatever way an answer ends (whole, cut short, or reported late),
  the wallet believes the seller's charge by one rule, and a charge above it is a seller fault.
- Several answers to one seller, cut or reported late, and AI replies cut short, are believed no
  more than they could have delivered; an AI reply never past its quoted price.
- A busy service refuses new buyers before they pay; buyers it is already serving stay served, and
  a refused buyer is sold nothing.
- WebSockets (for example a web app's live updates) stay open for up to six hours, paid as their
  bytes pass, instead of ending with an ordinary answer's limit.
- A paid WebSocket is charged no more than the limit the buyer set for it: the shop's gateway ends
  it there.
- Higher default limits for a shop: 100 sessions and 512 connections. A shop behind a tunnel is
  limited as a whole, not as if all its buyers were one address.

**VPN exits**
- A priced exit's region check now runs for a buyer with no credit at that exit. Each check is
  charged at most 20 sats, and the day's checks share a budget that survives a restart.
- Stopping a session waits for its open answers' last receipts, so a VPN tunnel's spend is reported
  in full; the VPN seller page shows what was charged.
- Sell or buy a VPN exit, paid as you use it: a buyer's devices go out through another box's internet
  connection over Stream, by the GB, with no account; exits are checked for the country they claim,
  an exit only its own shop's gateway can open, and exits that waste a buyer's money held off.
- The bundled country table is readable again, so exits' regions are checked as intended.
- The VPN page says why a device is blocked.
- The VPN page shows which exit each device goes out through and what it has spent.
- Paid VPN tunnels open: before, each one closed as it opened, after its ticket was bought.
- Restarting the app no longer stops the VPN service opening paid tunnels.
- A shop that sells only its VPN exit is listed, so buyers can find it by its key.

**Hashrate**
- A trial slice and a rental smaller than the shop's ticket are paid from no credit, instead of
  being refused; credit left with a seller lasts about 20 hours, and the rental card says what left
  the wallet.
- A rental shows "Connecting…" until its link opens; one that never opens says why, and that
  nothing was paid.
- Rentals run over the encrypted link.
- A hashtaker can buy a short paid test slice before renting, and a hashmaker publishes a signed
  history of what it delivered.
- Miners behind one address (a home router, or Docker on Umbrel and StartOS) move between rentals
  once each way, instead of bouncing between connections under load. In a test of 25 rentals of 3
  miners each at once, every rental received 98–99% of the work its miners could do in that time.
  Buyers are charged only for work that reaches their pool.
- A hashmaker rents out only miners that have connected and named themselves, so a rental never
  gets a silent connection that does no work.

**The app**
- A visit to a shop reached by its key is headed by the shop's name, and pages show such a shop by
  its shortened key rather than a long internal address.
- Sell: services added in any order each get a path of their own. Only a media server takes the shop's
  root, and a clash names the service that holds the path.
- A shop's settings no longer show the values of headers it sends (they can hold secrets).
- On Umbrel and StartOS the Sell page shows whether your shop is selling, instead of always
  "Starting, or stopped".
- Clicking the background sends lightning down two streams only when you click between them; near
  one stream, only that one.

**Umbrel**
- Lightning Stream installs before your Lightning wallet exists. Create your Lightning wallet in
  Lightning Fork; Lightning Stream picks it up automatically, with no restart. Before, the install
  failed until the wallet was made.

**Linux**
- A shop's gateway on a port of your own (LS_GW_PORT) no longer shows as unhealthy.
- An update keeps every setting in .env (including ones added by hand), LS_* settings given to
  install.sh win over .env, also with --yes, and the Files folder has its own port setting,
  LS_FILES_PORT. install.sh and the Sell page say plainly when another program holds it.
- The installer refuses a chain name the node doesn't use (for example mainnet instead of main) and
  says which to use.

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
- A seller's list of AI models is free to read, so the AI address finds sellers' models by itself.
  Sellers need this release for their models to be listed. Preferring or blocking a seller applies
  at once, and a key at its limit says what the request may cost and what the key has left.
- Known limit: a very long answer can pause briefly while the next ticket is bought.

**Hashrate**
- A rental survives a short break in the link between hashtaker and hashmaker: the miner goes back to
  its own pool for the moment, and the rental carries on when the link returns, with no slice paid
  twice.
- A hashtaker whose wallet is restarting waits for it before a slice goes unpaid.
- Offers show the price per TH/s per day beside the hourly figure.
- The hashmaker measures each miner's speed over five minutes instead of one, which steadies it.

**StartOS**
- Package 0.1.19:1: the AI page and the Agents page showed their addresses with the path twice
  (`…/v1/v1`, `…/mcp/mcp`), so a copied address did not answer. They now show it once. The agents'
  address had shown it twice since 0.1.14.

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
