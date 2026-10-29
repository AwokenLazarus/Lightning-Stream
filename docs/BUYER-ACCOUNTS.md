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
