# A buyer's own account in a seller's web app

A seller's web app with accounts (Jellyfin: watch history, resume points, favourites) is far better
used with an account of one's own than with a guest every buyer shares. This is how each buyer gets
one, made by the seller's gateway the first time it sees them, without the buyer making an account,
giving a name, or being known to the seller as anything but a handle.

## Who the buyer is, to one seller

- **A key per seller.** The wallet derives a secp256k1 key for each seller from its ticket seed and
  the seller's receipt key: `HMAC-SHA256(seed, "xbt402 buyer v1" || receipt key)`. The same wallet
  (or another with the same seed: a restore, a second device) is the same buyer at that shop, in
  every session. Two shops have different receipt keys, so they see unrelated keys, and cannot tell
  that the two buyers are one.
- **Not the session key.** A session's key is the seller's to give, and a new session has a new one:
  it cannot be a stable identity. The buyer key sits beside it.
- **Never the Lightning node's key**, nor anything derived from it, nor the wallet's on-chain keys.
- **Proven for one session.** After a session opens, the wallet sends `identify` (a session call,
  authenticated like `status`): its key and its signature over `"xbt402 buyer v1"`, the seller's
  receipt key and the session id. The gateway checks it and ties the key to that session. A copy of
  one session's proof is no good for another session, or at another shop.
- **Only where it is asked for.** A seller whose routes give accounts says so in its terms
  (`identify: true`). A wallet identifies to that seller only, so a seller without accounts never
  sees a stable handle.

## The account

A route that carries accounts names an adapter (`accounts`). On a request from a session whose buyer
the gateway has not seen, it has the adapter make the buyer's account, once, and keeps what it gets
(in its state directory, mode 600). Every request of that buyer then goes to the service as that
account; the client's own login is replaced by the gateway's, so no buyer can act as another.

- **Jellyfin** (`"accounts": {"kind": "jellyfin", "admin_key_file": "…", "libraries": ["…"]}`), with
  the seller's API key (kept on the seller's box, mode 600, sent nowhere but to Jellyfin):
  - a user with a random password, hidden, not an administrator, seeing only the libraries for
    sale, allowed to download, delete and manage nothing;
  - a token for that user, kept for the buyer, and made again if Jellyfin refuses it (expired or
    revoked);
  - the login page shows the buyer one user, their own, with no password: one tap logs them in, as
    themselves;
  - every request's token (headers, and the `api_key` of a stream's or a socket's URL) is replaced
    by the buyer's own; a path naming another user's id is refused.
- **Any other app**: a hook the seller provides (`"kind": "hook", "command": "…"`), given the
  buyer's handle and returning the headers or the cookie to send as that buyer.
- **An app without accounts** keeps the shared guest (`upstream_headers`).

The path lists stay as a second layer: the admin and the server's own pages stay refused, whatever
the account may do.

## What the seller sees

A handle per buyer (a short hash of the key), with its account's name in the app (`buyer-` and the
handle), and what that buyer used and paid. Nothing else: not the buyer's node, not their other
shops. A buyer may give a display name, which the gateway sets as the account's name.

## What the buyer sees, and chooses

Before an app of such a shop opens, Lightning Stream says, in plain words: "This shop keeps your
watch history. It sees a private handle, not who you are, and it is the same each time you come
back", with **Stay anonymous here**. A buyer who chooses it is never identified to that shop (the
wallet keeps the choice per shop, `identity_set`), and uses the shop's shared guest where it has
one; a shop with no guest then refuses them. The app learns that a shop keeps accounts from the
shop's `/services` (`"accounts": true` on the route), asked when the page is shown.

## Backups, and a reinstall

The buyer key comes from the wallet's ticket seed (`.run/ticket_seed.json`, sealed). The wallet's
own backup file carries it, as it carries every file of `.run/`; a StartOS backup and an Umbrel
backup carry the app's whole data. A wallet restored from any of them is the same buyer at every
shop, with its history. A reinstall **without** a backup makes a new seed: the buyer is then new at
every shop, and the old accounts stay at the shops, unused.

Jellyfin makes a user's id from its name, so a `buyer-<handle>` made again (after the seller lost
its `accounts.json`) finds the same user's history.

## The seller's key, rotated or revoked

It is read for each account made, never kept in memory or sent anywhere but to Jellyfin. A key
that is rotated is the one used from then on; one that is revoked, removed or wrong makes no account:
the buyer's request is refused (`503 accounts_unavailable`), never sent with the seller's key or as
the guest. Accounts already made go on with their own logins.

## Where it is built

- the key and its proof: `Seed::buyer_key` (signer), `xbt402::ticket::buyer_message`, the wallet's
  `identify` after a session's first lock, and once more on `403 identify_first`;
- the gateway: route `accounts`, the session call `identify`, `gateway/accounts.rs`;
- tests: `a_buyer_key_is_the_same_at_one_seller_and_unrelated_at_another` (signer),
  `a_wallet_tells_a_seller_with_accounts_who_it_is_and_stays_anonymous_when_told` (signer, through
  a real gateway), `tests/accounts_jellyfin.rs` (gateway, a real Jellyfin, not run by default), and
  the note and choice in `two_apps_of_one_seller_are_two_visits_on_two_origins` (wallet UI).

Not built yet: setting accounts up from the Sell page (the gateway config's route takes them today),
and a buyer's display name.
