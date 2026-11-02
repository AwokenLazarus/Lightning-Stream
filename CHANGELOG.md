# Changelog

Lightning Stream versions, newest first. One version number covers the Umbrel app, the StartOS
package (from 0.1.14) and the Linux package (from 0.1.12). Dates are UTC.

Lightning Stream is early software. It runs on mainnet; use small amounts.

## 0.2.5 (2026-11-02)

Web apps in visits, faster and whole, from a hands-on run of 0.2.4 with the demo shop's Jellyfin over a
relayed link. The connector, the wallet UI, the signer and the seller's gateway change.

- **Answers are no longer cut where the credit ends.** Each request of a visit runs within a small share of
  the visit's limit, too small for a ticket. An answer that ran past the credit with the shop was cut where
  the credit ended: a bitrate test or a part of a film came short of its length, and Jellyfin fell back to a
  720p transcode. Now, when a call says the credit is low, the visit's next request goes first with room
  for a ticket and tops the credit up before it leaves (the signer's new `top_up_sats`). The visit still
  never spends more than its limit, and each share is settled once.
- **Requests no longer wait two minutes at the edge of the credit.** With no credit left, a page's requests
  (Jellyfin's sign-in and playback reports among them) were refused and asked again one at a time, and the
  page gave up on them. The credit is now topped up before it runs out.
- **"Used" is what the connection's credit fell by.** For an answer cut short or left by the page, the
  visit now counts the seller's signed charge, which includes the bytes that were on their way. Before, the
  bar could say 85 sat used where the credit had fallen by about 164.
- **Stop closes the shop's connection.** The visit's Stop now also closes the connection with the shop
  when no other open visit uses it, as Stop on Live connections does. Before, an earlier visit to the same
  shop, closed without Stop, kept it open.
- **A limit sized for film, and more on request.** A video app priced by the byte is offered a limit for
  about ten minutes of 1080p at its price (1,000 to 20,000 sats); other apps keep 1,000. Once four fifths
  of the limit is used, the bar offers **Add**, which raises it. At the limit the page waits for you
  instead of closing. Nothing is raised without a click.
- **Shops: web clients load faster and are kept.** On a free route, the gateway sends text (scripts,
  styles, JSON) gzip-compressed to a buyer that takes it, about a third of the bytes over a slow link.
  Nothing on a free route is metered or signed, so this changes no price. It also adds
  `Cache-Control: public, max-age=3600` to a free route's answers that say nothing of caching (HTML pages
  excepted), so a buyer's next visit loads the web client from the browser. A route's new `cache` option
  sets how long, on any route, or turns it off (`0`).
- **Shops: fixed UDP ports for the link.** A new `link.port` in the gateway's config fixes the link's UDP
  ports (key *i* on `port + i`, IPv4 and IPv6). A shop that allows inbound UDP on them is reached directly
  by buyers behind a NAT that gives each destination another port (commercial VPNs, carrier-grade NAT).
  Unset, the ports stay random. The gateway logs the ports it bound.
- **A cut answer is logged.** The connector logs why a page's answer was cut short (its status and the
  wallet's words, no address).

## 0.2.4 (2026-11-02)

Web apps in visits, from a hands-on run of 0.2.3 with the demo shop's Jellyfin. The connector and the
wallet UI change; payments and the signer are unchanged.

- **Web apps load at once.** A web app such as Jellyfin asks for about a hundred things as it opens. Each
  request of a visit now holds an eighth of the visit's limit (10 to 1,000 sats) instead of room for a whole
  ticket, so a 1,000 sat visit runs eight requests at once. Before, the first request held the whole limit
  and the others waited for it one at a time: the page stayed white for 20 to 100 seconds. A request that
  needs to buy a ticket asks again with room for one, and then alone, as before. The visit still never
  spends more than its limit.
- **Sign-in no longer hangs.** A web app's live connection (a WebSocket, which Jellyfin opens after sign-in)
  holds at most 50 sats while it is open, and a visit's live connections together at most half of its limit.
  Before, it held the whole limit for as long as the page was open, and every request after it was refused
  after two minutes: the sign-in spun forever.
- **Free parts of a shop are not paid for.** A visit reads which of the shop's routes are free and asks for
  those directly, with nothing to spend, in one round trip. Before, it sent them as paid, the shop refused
  them, and the wallet asked again.
- **Rent on Hashrate says why it is off.** A disabled Rent button says why, beside it and as its tooltip, and
  an offer paid where this box's hashmaker is paid is shown as your own.
- **Get started counts a shop allowed through its node.** Home's Get started now counts a shop allowed through
  its Lightning node's line in your rules, as the wallet pays it. Before, it kept saying "Allow a shop" and
  left "Buy something" unticked.
- **An AI seller's page points to your AI address.** It sends programs to the AI page, for this box's AI
  address and a key of their own, instead of showing the seller's own address (for a shop reached by its key,
  a made-up one only this wallet's agents can reach). That address is still under Technical details.

## 0.2.3 (2026-11-02)

Usability, from a hands-on run of 0.2.2 on Umbrel. The wallet UI, the VPN service and the signer
change (one read added; payments are unchanged).

- **Buy and Sell.** The main menu's Services is now Buy, beside Sell. Settings keeps Setup, Your node,
  Spending rules and Keys and backup as tabs; Records, Stream relays and Old channels are under Advanced.
- **Get started on Home.** A list of what is left (approval key, node, starter rules, a shop, a first
  purchase), with the next step's button. The demo shop is added and allowed in one press, a service's page
  says when its shop isn't allowed yet, with the button, and a shop is named by its listing everywhere.
- **Real money in the same signature as the rules.** On mainnet, signing the starter rules carries one box,
  "I understand the app pays with real money, within these rules", which writes the same confirmation Your
  node writes; no separate page. Your node can still turn paying with real money off and on.
- **One figure for what a payment cost.** Paid is what left your node: the shop's amount plus the routing fee,
  from the wallet's settled record, with its two parts ("903 sats (900 + 2.009 fee)"). Wallet, Live
  connections and the visit bar name the same three figures: paid, used and credit left. A booking before a
  payment settles is shown as reserved, never as paid.
- **Credit you have with a shop.** After a connection closes, what it left with the shop shows on Sellers, on
  the shop's service page and on the Wallet's row. A visit that runs on earlier credit says how much is left.
- **One Stop.** Stopping a visit also closes its connection with the shop, unless another visit to that shop
  is still using it.
- **Allowed means paid.** A shop allowed through its Lightning node's line in your rules is shown as allowed.
  Before, Sellers, AI and Spending rules said it couldn't be paid while the wallet paid it. A node line is
  shown as the shop's Lightning node, not as a coin address. A shop with no node on file gets a one-press fix.
- **VPN exits.** Every exit the VPN service finds is listed, also a paid exit whose country isn't checked yet.
  Before, a paid exit such as the Pi Demo's (SV, 1,000 sat/GB) was found but never shown. Found on Nostr on
  the VPN page lists the exits your relays carry, with **Add this exit**; your devices then prefer it whenever
  it meets their rules.
- **Hashrate.** A shop that goes Private is paid at its key address. Before, the hashmaker went on publishing
  the old web address and every rental failed at its first piece of work.
- **Plain words and fewer keys.** Refused payments in Wallet activity are explained as the refusal pages
  explain them. A shop is named by its name on the service and visit pages and in Wallet activity. Your
  node's raw status is under Technical details. The AI address is also given by the box's IP address.
- **Faster first pages.** Found on Nostr, Stream relays, VPN and Hashrate are asked once at start, in the
  background. The signer's slow-changing reads now serve pages for 20 s (they were kept 3 s, too short to
  help).
- **Also:** the agent access key is shown only after Show the access key; starter rules' least node limit is
  1,000,000 sats; Setup counts each seller and step once; Live connections shows a rate only while streaming.
- **The look of lightning-stream.com.** The app is dark by default, with the website's near-black ground,
  lightning-yellow main buttons and amounts, white-blue accents, its Inter type and its mark. A light theme
  in the same colors is one button away in the bar, and the browser remembers it. The background's electric
  river is slower and finer, in yellow and electric blue, still reacts to the pointer and to clicks, and
  stays still with reduced motion and on low-power devices. Every page works at phone width.

## 0.2.2 (2026-11-02)

A fix release for a first purchase, from a tester's hands-on run of 0.2.1.

- **Sellers by name.** Sellers, Spending rules, Wallet activity, Live connections, Found on Nostr and the visit
  pages name a shop by its listing ("Lightning Stream Genesis"), never by its key or its made-up
  `….shop.invalid` address. Found on Nostr marks shops already on your list.
- **Who may be paid is a list.** Spending rules show one row per seller: name, key or address, its Lightning
  node, and Remove. An edit can no longer cut a seller's node off; before, a long line wrapped in a text box
  and editing it could drop the node, after which every payment to that seller was refused. A seller with no
  node, or with a node other than the one the shop vouches for, is warned about before you sign. Removing a
  seller from Sellers points you to the rules where it is still allowed.
- **No blank pages.** When the wallet won't pay (a seller not allowed, no route, a limit or cap, your node over
  "The most your Lightning node may hold"), the app shows why in plain words, what fixes it, and links, with
  the wallet's own words under Details.
- **Your node can't send.** Before opening a shop's app or downloading, and on Browse, the app warns when your
  node's channels hold too little you can spend (after the channel reserve), with how much and what to do.
- **A visit's numbers.** The visit bar shows what was used, what was prepaid and what is left as credit with
  the shop; Stop says what the visit used. The limit field says the least a shop needs (559 sat for a 546-sat
  ticket) and starts at 1,000.
- **Version.** The app's version is in the footer and on Setup.
- **Faster pages.** Found on Nostr, Stream relays and Hashrate show what they last knew at once and ask the
  relays and the hashrate service in the background; repeated reads from the signer within a few seconds are
  answered once. Each response carries a `Server-Timing` header.

## 0.2.1 (2026-11-02)

A fix to 0.2.0.

- On Browse, **Found on Nostr**, a shop reached by its key (such as the demo shop, Lightning Stream
  Genesis) now offers **Add this shop**. Its list is signed by the key that is its address, so it is the
  shop's own. Before, it offered only *Check with the seller*, which asks the seller's web address; a
  shop reached by its key has none, so the check failed with a name-lookup error. Adding the shop by its
  key under Sellers worked all along.
- **A file that costs less than a shop's smallest ticket can be bought.** A Download, or a file opened
  in your player, now lets its first call buy one whole ticket (546 sat, 559 with routing fees, at the
  least) even when the file costs less, such as Big Buck Bunny at Lightning Stream Genesis (about 284
  sat). What the file doesn't use stays as credit with the shop. Before, the call's limit was the
  file's own price, so a buyer with no credit got a raw JSON refusal and nothing was paid. Where the
  wallet names a larger smallest ticket (up to 2,000 sat), the call is made once more with it, and any
  other refusal is now a page in words. Your spending rules still apply to every payment.
- **A web-app visit needs a limit of at least 559 sat.** A smaller limit opened a visit whose first
  request said the limit was reached with nothing spent. The form now refuses it, says why, and sets
  the limit to 559 sat for you to confirm; what a visit doesn't use stays as credit with the shop.

## 0.2.0 (2026-11-01)

A public test release. What is new since 0.1.19, in short; the sections below give the details.

**In 0.2.0**
- **Hashrate rental with masked jobs.** The Stream Gateway (DATUM-compatible) now comes with the app
  on Umbrel, StartOS and Linux, and a renter's rented hashrate goes through it. Every job is masked
  with a key the gateway holds, so a rented miner can't tell which share is a block and can't
  withhold one. The renter checks each job before its miners get it: a rental whose job can't be
  shown masked ends, and nothing is paid before the first job has been checked. It mines solo, paid
  to your own address, or on Lazarus Pool, which takes jobs masked with your gateway's own key; a pool
  that doesn't is refused.
- **Hashrate payments.** Both sides prove every share, and a renter pays as the work arrives: you
  never have more paid for and not yet received than a minute of the miner's hashing, or one share,
  one slice and one ticket (546 sat at least), whichever is more, plus any start fee shown on the
  offer. Shares sent again after a link drop still get their verdict, and a hashmaker's difficulty
  requests go no further than the renter.
- **Rentals.** A start fee asks for 30 pieces of work at most, so a rental with a small piece starts
  before its first payment is due. A seller's listing never offers 0 miners just after a start or a new
  price. A Rent sent twice starts one rental and pays one start fee. Delivery records are shown
  as claims anyone can publish, and a flood of them no longer hides a hashmaker's own. A hashmaker's
  public summary names no renter.
- **Wallet limits.** The hashrate rental's own limits apply only to the app's renter paying a rented
  miner's work; any other call that names the task "hashrate" is refused (`ticket_rental_payer`) and
  pays nothing. One task's credit is never spent by another: ticket sessions are per task, so a shop
  may see two sessions from one wallet.
- **Paying.** Slow routes, channel drops of up to 8 s, a seller's 408, resumes from a byte (with
  `If-Range`), and stream tickets under load no longer end paid calls or pay twice. An agent's long
  paid call waits for the wallet instead of failing at the MCP. A seller behind a private channel is
  paid through its route hints. A file resumes after a channel outage. Wins are paid in the order
  their sellers' grace ends.
- **VPN exits.** A tunnel pays about one and a half tickets ahead at most, asks again for a ticket
  refused for a moment, and shows what it has used as it runs.
- The lab checks now require usage times the listed price, to the msat, on both sides for files,
  web apps and VPN tunnels.

**Licences**
- The Stream Gateway image (`xbt-datum-gateway`) is CONVOY's datum_gateway (MIT) with Lightning
  Stream's changes. It is linked statically with libsodium (ISC), jansson (MIT), libcurl (curl
  licence), musl (MIT), and two LGPL libraries: libmicrohttpd 1.0.1 (GNU LGPL 2.1 or later) and
  argp-standalone 1.5.0 (GNU Library GPL 2 or later). The image carries each licence and a NOTICE in
  `/usr/share/xbt-datum-gateway/`. You may rebuild the gateway, or relink it against modified
  versions of those two libraries: this repository holds its complete source, the pinned library
  versions with their sha256 sums, and the script that builds and links it
  (`scripts/datum_gateway_build.sh`), at the commit the image's tag names. The GitHub release `v0.2.0`
  carries the exact source tarballs of both libraries that the image was built from, with their
  checksums (`SHA256SUMS-datum-gateway-lgpl`).

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
- A download cut short by a channel outage now picks up from the byte it stopped at. If the seller
  has forgotten the session or has no room for more tickets, the wallet opens a fresh session once
  and carries on. It never retries a session the seller faulted or one you stopped, and never pays
  twice for the same bytes. If a seller ignores a byte range and sends the whole file, the wallet
  closes at once; the unread part costs at most what was already on its way.
- A channel outage is no longer taken for a full route. Before, the payments that failed while your
  channels were down halved the tickets your wallet holds with that seller, for this session and the
  next, for up to ten minutes. Now the wallet waits 30 s and pays from prepaid tickets meanwhile, then
  holds as many as before. A route that really is full is still counted as before.
- On a busy wallet, lottery wins are now paid nearest-deadline first. A seller's unpaid wins are
  hurried as soon as it reaches its limit. Every invoice is checked again just before it is sent, so
  none goes out about to expire. A 0.2.0 wallet tells a 0.2.0 seller it can cancel, and gets win
  invoices of up to 180 s, so a busy wallet no longer misses wins. Older wallets and sellers keep
  today's behaviour.
- A seller can now say how long it waits for the next ticket, and the wallet ends its own pause a
  little before that (a tenth of the wait, between 1 s and 3 s), so no ticket is ever paid into an
  answer the seller has already closed. A seller that doesn't say keeps today's behaviour.
- A slow wallet no longer blames a seller whose web server timed out waiting for the wallet's request
  (HTTP 408). Nothing was served or charged: the wallet sends the same request once more, and if it
  times out again, that call alone is refused and the session goes on.
- A file no longer gets cut because the wallet's disk is slow while it pays many sellers. With 50 or
  100 ms added to each of the wallet's disk writes and 20 other sellers' wins queued, the win a seller
  was waiting for was paid after 19 to 30 others, and its file was cut in 9 of 12 runs. It is now paid
  after 1 to 8 others, and the file arrives whole in 12 of 12.
- After the wallet's Lightning node restarts in the middle of a download, a win it could not pay at
  that moment is paid on the next call. The seller used to refuse that call and every later one for
  as long as the session lasted.
- A channel that drops for a moment no longer ends a paid file or answer: the wallet waits up to
  8 s for it to come back, and as long for a route to the seller (after a link further along the way
  was replaced, a node may find none for some seconds), rather than sending a payment that fails. A seller
  the node has no route to for good ends the call with `ln_no_route` within 8 s counted from after the
  node's checks, and holds up no
  other seller's payments. The route is asked for with the invoice's route hints, so a seller reached through a
  private channel (an LSP's, say) is found as its payment finds it, and waited for the same way; an invoice with
  blinded paths, which the route query does not take, is paid at once, as before. A channel that stays down still ends what is paid by tickets, with that
  reason; a file paid by draws may still finish, with the wins it could not pay listed unpaid.
- A win whose invoice ran out while it waited its turn is paid on the seller's next invoice, rather
  than ending the file; a win that would arrive after its invoice ends is not sent.
- Going on with a file from where it stopped (`range`) no longer buys the start of it again from a seller
  whose server ignores ranges. Until now the wallet read and paid for a whole body sent in answer to a range,
  "like any other"; now it reads none of it and says `ticket_range_ignored` (a range from the first byte,
  which is what a player asks first, is a whole answer: read whole, up to the call's `max_sats`, not cut at the
  range's last byte, so a caller of `bytes=0-1023` with a large `max_sats` can pay for the whole body), with what the call cost (on a route
  priced by the byte, what the seller's socket took before the wallet closed it). A call that goes on from an
  earlier answer can name that answer's `etag` (`if_range`): a seller whose file has changed since sends the whole
  new file, which is not read either, rather than the rest of another file spliced onto the old start. The app's
  player link and the wallet's own player pass the player's `If-Range` on and the seller's `ETag` and
  `Last-Modified` back; a seek on a changed file is answered 412, with that reason.
- A win whose payment failed no longer costs a file: the wallet asks the seller to cancel that invoice,
  and pays the seller's next one at once rather than waiting for the first to lapse. It asks the same
  for an invoice it held back because the win would have arrived after it ended. A seller on an
  earlier version behaves as before.
- A paid download or film no longer ends when a loaded node or a slow route is late with its next
  ticket, or when the wallet's chain or Lightning node stops answering for a moment. The wallet waits
  up to 12 s for each ticket while the seller keeps the answer open, and releases nothing for an answer
  the seller has closed, or after the call's deadline. Where only the Lightning node's router was away,
  tickets it never got hold their places for up to two minutes, and the file ends with `ticket_none`.
- A whole paid call now has one deadline of 50 s, and answers plainly within about 55 s, before its
  caller's 60 s, even if a node or the seller hangs: asking again then does not pay twice. Three things
  can still run past that: paying a prepaid ticket, which waits as long as the Lightning node's own
  timeout (60 s); the checks of the nodes that begin a call, each up to its own 30 s; and the wallet's
  background check of its tickets while the Lightning node hangs, which holds the ticket book up.
- An answer priced by the second is charged for that wait, by the clock, and each ticket can wait: at
  400 sat a second, an answer of 3,600 sat came to 4,800 sat with the seller's word held back to 11 s,
  and to 7,600 sat with its ticket 11 s past due.
- A seller that keeps not showing the wallet's tickets, and a ticket stuck on its way for over 90 s,
  now end the session, and the reply says which. A stop ends the answer at once.
- A small payment works from no credit at a shop: the wallet buys a ticket sized to what the call may
  be charged, while the call itself stays capped at that charge.
- Stopping a call ends it at once: nothing more is booked or paid for that session once the stop
  begins, and a prepaid ticket or win paid without its proof now counts in what the call charged.
- A file is never read past the size its listing shows. From a 0.2.0 shop, a file that grew after
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
- On a slow route the AI address no longer gives up on a seller while the wallet is still paying it,
  and pays a second seller for the same answer: a seller's time to answer is counted from when its
  call is paid for (up to 90 s for the payment, `LS_AI_PAY_WAIT_S`). A seller that has the request
  and is then silent is no longer followed by another; whatever a failed call cost is booked to its
  AI key.
- A lottery win paid over a slow route reaches the seller before its invoice lapses: the seller's
  grace, and with it a win's invoice, is 60 s by default instead of 30 s.
- WebSockets (for example a web app's live updates) stay open for up to six hours, paid as their
  bytes pass, instead of ending with an ordinary answer's limit.
- A paid WebSocket is charged no more than the limit the buyer set for it: the shop's gateway ends
  it there.
- Higher default limits for a shop: 100 sessions and 512 connections. A shop behind a tunnel is
  limited as a whole, not as if all its buyers were one address.
- A buyer whose first payment takes more than 20 s to reach a shop (a slow route) can now open a
  session: a session's first ticket invoice stays payable for 60 s, as every other does, instead of
  20 s. A payment that still arrives after its invoice lapsed is refused, with nothing paid, and the
  buyer is told so instead of seeing a timeout.
- A call's prepaid ticket (or lottery win) gives your node at most 60 s to pay it, whatever your
  Lightning timeout, so that web apps and Files show the wallet's answer rather than a timeout. A
  payment with no final answer by then no longer blames the seller: nothing more is bought from
  that seller for up to about 85 s, and your next call takes up the ticket's credit once your node
  shows it paid and the seller has credited it. A seller that keeps the money without crediting it
  is named in your wallet's history.
- After a restart, a session that picks up the credit left with a shop holds tickets with it again
  at once, instead of holding none until that credit ran out and buying another prepaid ticket.
- A prepaid ticket that settles after its call ended, or just as the wallet stopped, is shown to its
  shop, so its credit is there for the next call. A shop is told only after it has signed an answer
  for that session, so another on the same node, or one merely naming that shop's key, is not.
- A cancel names the session's own tickets, and also a ticket whose secret never reached the shop, so
  a session that took over a shop's credit keeps its tickets and nothing stays held.
- A shop that will not say what an earlier session left with it no longer has a new ticket bought
  beside that credit: the call is refused with a time to retry. After two minutes a new session starts,
  your wallet's history names what may be left, and the next session uses that credit first, oldest first.
- Credit one task leaves with a shop is no longer spent by another task's calls, which could take
  that task past its own budget. The credit now waits for a call of its own task, for up to about
  20 hours, and another task's call to that shop buys its own ticket.
- A call of one task is no longer paid from a session another task has open with the same shop, which
  spent that task's credit and booked the tickets it bought to that task, past the calling task's
  own budget. Each task now has its own session with a shop: a second task's call opens one beside
  it and buys its own ticket. A call at another address of the same shop no longer stops another
  task's session, and is no longer held back by another task's prepaid ticket still on its way.
- A kill or a lost answer no longer buys a second ticket when the first was paid: the next call waits
  for the shop to take it, for two minutes at most. Long answers open for over ten minutes are no longer
  cut by a second call to the same shop.
- An agent's paid download or payment that takes longer than a minute no longer fails at the MCP with
  "Resource temporarily unavailable" while the wallet goes on paying for it. The MCP waits for a paying
  call's answer as long as the wallet works on it; any other call still gives up after `B2_SIGNER_TIMEOUT`.
  If a paying call's answer is lost (the wallet's signer stopped), the agent is told the call may have paid
  (`signer_no_answer`, `request_sent: true`) rather than given an error that reads as if nothing happened.
  A paying call still has a ceiling, 24 h 5 min as shipped (`XBT_MCP_PAY_CEILING_S`, past the longest the wallet keeps any answer open), and at most 14 are in
  progress at once, so a stuck signer cannot take every worker of the MCP: a `ticket_stop` is always served.

**VPN exits**
- A priced exit's region check now runs for a buyer with no credit at that exit. Each check is
  charged at most 20 sats, and the day's checks share a budget that survives a restart.
- Stopping a session waits for its open answers' last receipts, so a VPN tunnel's spend is reported
  in full; the VPN seller page shows what was charged.
- A VPN tunnel at a high price pays about one ticket ahead, as other answers do, not three seconds
  of traffic: at 40 Mbit and 500,000 sat a GiB, a stopped tunnel left over six tickets with the seller.
  At a very high price a tunnel goes no faster than its tickets can be paid, as a file already does.
- A VPN tunnel whose next ticket is refused for a moment (a seller slow to show it locked) asks again
  when it is due, rather than ending with credit left. A refusal that will not pass (a stopped
  session, a blocked seller, the owner's limits) ends it at once.
- What a VPN tunnel has used shows as it runs, from the seller's signed counts, not only after it
  stops: at a low price "Used" stayed at nothing for a whole tunnel.
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
- The hashrate task's own limits (its 200,000 sat budget, tickets up to 10,000 sat, 600 an hour, outside
  the wallet's day, week and per-shop limits) now apply only to the app's renter paying a rented
  miner's work. Before, any agent or MCP tool that named the task "hashrate" could pay any shop on
  them, past your wallet's limits and with no approval. Such a call is now refused and nothing is
  paid. The renter pays through its own connection to the wallet, which nothing else in the app can
  reach.
- If you run the renter by hand (`xbt-hashlink renter --signer …`), or your app's parts are of different
  versions after an update, point `--signer` at the wallet's renter socket (`run/rental/signer.sock`), and
  update every part of the app together: a renter on the wallet's ordinary socket now has every rental
  payment refused, and the Hashrate page says so.
- Renting needs masked jobs, solo or through a pool, so a hashmaker can't keep back the shares that would be blocks.
  The app comes with its own gateway, the Stream Gateway (DATUM-compatible), which masks its jobs, and rents into it.
  The Rent page checks the gateway's jobs when it opens and before each rental; if they aren't masked (the gateway
  isn't set up or running, or the app is set to another gateway), it says so and rents nothing.
- *Your gateway* on the Hashrate page sets the Stream Gateway up: solo to your own XBT address (the default), or
  through Lazarus Pool. The address is checked for your node's network first (bc1q, bc1p or a legacy address on
  mainnet). The page shows the gateway running, connected to your node, and masking its jobs.
- Lazarus Pool mode masks its jobs too: Lazarus Pool takes gateway-held keys. A pool whose jobs aren't masked
  (`pool-null`) is refused for renting, and solo works. In that mode your gateway holds the key, so it could hide a block it finds from the pool,
  the same as any DATUM miner can today. Pools that hold the key themselves (CONVOY-style) come later.
- The gateway's config holds no secret: the node's RPC credentials go to a cookie file only the gateway reads, its
  API has no admin password (every admin page is off), and it listens on 127.0.0.1 only. A block it finds is kept
  on disk even if the node's submitblock fails.
- An app set to another gateway before this version is moved to the Stream Gateway once, and the Hashrate page
  offers the old one back. On armv7 the app has no Stream Gateway: the Rent page says the gateway isn't masking,
  and selling hashrate works as before.
- Both apps check every share's hash themselves, from the Stratum lines alone. A share counts only
  if it proves its work; neither side takes the other's word, and a renter's verdicts set nothing.
- Renters: paid as you use it, seconds at a time. You never have more paid for and not yet received
  than a minute of the miner's hashing, or one share, one slice and one ticket (546 sat at least),
  whichever is more, plus any start fee shown on the offer. That counts the credit left with the seller
  as well as the slices paid ahead: each ticket is sized to stay inside it. The app stops paying a seller
  after two first payments that delivered little.
- No payment, not the start fee or the first ticket, until the gateway's own first job is shown masked.
  Before, a renter pointed at a gateway that doesn't mask could pay 5 times before the first job's check
  refused it.
- Hashmakers: a renter gets no work it hasn't paid for. If it stops paying, your miners go back to
  your own pool within seconds. Measured on the real-money regtest: stopped with no work past what
  was paid. Hashmakers set no price by hand by default: it is the mining value at live difficulty.
- Known limits in this release: a new price waits until the hashmaker's running rentals end, so while any
  rental runs no new rental starts at the new price; a rental's last ticket can pass its budget by less than a
  slice, which stays with the seller as credit (a ticket is never smaller than a slice); a renter that reads its link slowly can hold up a
  hashmaker's sends to it for up to 5 s each; each side keeps the hashes of up to about 4 million shares a
  rental, about 100 MB at the most.
- Your gateway hides which shares win (`xor_key`), so a hashmaker can't drop the ones that would be
  blocks. The renter's page says, for your upstream, whether its jobs are blinded, checked job by
  job; one that isn't, or can't be checked, is refused. Measured: real masked blocks through a full
  rental, solo and through Lazarus's pool, each block's share one both sides proved; and over 10,240
  shares a hashmaker's best guess at which win was at chance (balanced accuracy 0.498).
- The app also ends a rental on shares held back, shares on an out-of-date job, or a pool turning
  most shares down.
- Checking a share costs about 1.7 µs on a lab core, about 7 µs estimated on a Raspberry Pi 4.
- Old and new versions refuse each other, with nothing paid: update both sides.
- On mainnet the starter rules let the hashrate task pay a rental at market price: a budget of 200,000
  sat, tickets of at most 10,000 sat, 600 payments an hour, paid by prepaid tickets only. These count
  against that budget alone, not the wallet's other limits. A wallet whose owner signed earlier rules
  keeps them until it signs new ones.
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
  Buyers pay a step ahead of the work and no more (see Renters, above).
- A hashmaker rents out only miners that have connected and named themselves, so a rental never
  gets a silent connection that does no work.
- After a break in the link, a rental keeps going even if a share's result was lost in the break.
  Before, the hashmaker stayed one share behind for the rest of the rental. With shares more than
  3 seconds apart it refused the next slice and ended the rental as unpaid: the wallet was charged
  nothing, and the hashmaker went unpaid for that work.
- A hashtaker that reconnects before the hashmaker has noticed the break carries on. Before, it was
  refused and the rental ended.
- A hashtaker reconnecting over a link that has gone silent now gives up when its time to come back
  runs out, and its unused tickets go back. Before, it could wait for good with them still held.
- A slice paid as the link breaks is taken while the rental waits for its renter to come back, within the
  rental's time to come back, and is paid and charged once. Before, a break of 2 seconds could refuse it and
  end the rental as unpaid.
- A renter can no longer hang a hashmaker's whole app by asking for an impossibly high difficulty. A
  difficulty of more than four slices a share now ends that rental at once, whichever of its miners it was said
  to, with all of that rental's miners; other rentals carry on. That is above 131,072 at the default slice: above
  about 113 TH/s on a miner at 0.2 shares a second, or any miner if the renter's gateway starts there. Larger
  slices are the hashmaker's setting.
- A renter's verdicts on shares no longer set what it owes: both sides count each share by its proof, so a renter
  that turns every share down still owes for each one proven, and the hashmaker forwards none past what's paid.
  Before, a renter that accepted a few shares could underpay without limit. See docs/P2P-HASH.md.
- A hashmaker can no longer turn shares it held back into paid work by dropping the link and sending them again:
  a share sent again goes on to the renter's gateway for its verdict, aged as of the drop; as many as its miners'
  rate says could have been on their way count at once, and the rest only once the gateway takes them. A link
  that drops more than 8 times in an hour ends the rental.
- After a dropped link both sides say their count once the shares sent again are settled, and the hashmaker's comes
  down to the renter's by no more than what it forwarded in the 2 s before the renter was last heard from, never
  more than 4 s before the drop. Before, a share sent again that the renter couldn't send on left the hashmaker's count ahead, and the rental could end unpaid.
- A price saved with no rental going on holds no miner back: the hashmaker takes no new rental only until its shop
  charges that price, and the Sell page says so. While rentals go on, a new price waits for them, and the hashmaker
  takes it for new rentals the moment the last one ends. The shop starts charging a new price only once the
  hashmaker shows it has the new terms with no rental going on, so a renter taken at the old terms in that moment
  pays them to its end. A market price moving with the chain changes at most once every ten minutes. Before, a price saved on a
  fresh install held every miner back, under "a new price waits for the rentals going on to end", until the app's
  next minute check found the shop charging it.
- Every share carries the renter's own id to its gateway, so its verdict is always read; a share with no id, or
  one still waiting for its verdict, is refused. A share whose time rolls back from its job's, or more than two
  hours forward, is refused. Before, shares with no id escaped the check of how many the gateway turned down.
- A hashmaker with no fallback pool keeps its miners connected through a renter's wait for a payment on its way,
  and they go on with the rental when it lands. Before, it let them go, and a miner that doesn't reconnect was lost
  to the rental. A renter says a payment is on its way only when its ticket buys are measured too slow for the
  hashmaker's 2 s clock.
- A slice's payment waits for the wallet as long as the wallet works on it. Before, the renter gave up after 200 s
  and took the slice as failed while the wallet might have paid it; a lost answer is now treated as possibly paid
  and never paid again.
- A hashmaker can't change what a share is worth at the renter's gateway: `mining.suggest_difficulty` and other
  lines that aren't a miner's session go no further than the renter, and `mining.configure` goes on without
  `minimum-difficulty`. After a new difficulty, shares wait for a job checked as masked at it.
- Sell, Hashrate says this beside "Rent out my miners", and the box starts unticked for an owner who has never
  saved the form; one who has keeps their choice. A rental card says in plain words why the hashmaker ended it for
  these two reasons.
- Rent sent twice (a double click, or the browser sending the form again) starts one rental and pays one start
  fee. Before, each send started a rental of its own, with its own start fee.
- An offer's delivery records say what they are: how many, from how many keys, and that anyone can publish
  them. No score is made of them and none is called confirmed. Before, the offer led with "TH-hours confirmed by
  both sides", which one person with two keys could fill at no cost.
- Records about other hashmakers no longer hide a hashmaker's own. Before, 500 records about anyone, free to
  publish, pushed every other record out of view.
- A hashmaker's published summary carries counts and totals only: rentals, slices and sats paid, and work. Before,
  it listed each renter's app key and the hour each rental ended, without the renter's say. It now goes out at
  most every six hours, dated to the hour; the rental-by-rental list stays on the hashmaker's box.
- A rental's time runs from the first share your gateway accepts, so the seconds spent connecting and moving the
  miners, or a gateway slow to answer, no longer come out of it.
- Mining solo, each offer says one machine's chance of finding a block in an hour, from your own node's
  difficulty, and how often a block comes at that speed on average. Through a pool it says nothing.
- A hashmaker's listing more than two days old is no longer offered: it is from a hashmaker that has stopped
  publishing. Listings now carry an expiry other Nostr clients read too.

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
