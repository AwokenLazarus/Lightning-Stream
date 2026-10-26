# Nostr Wallet Connect: the app as a wallet service

`xbt-nwc` (`crates/xbt-nwc`) lets other apps pay through the owner's own node. The owner makes a
connection on the wallet UI's **Connected apps** page and gives its connection string
(`nostr+walletconnect://...`) to an app: a phone wallet, a browser extension, an agent. The app
sends [NIP-47](https://github.com/nostr-protocol/nips/blob/master/47.md) requests over Nostr
relays, encrypted with [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md)
version 2. The service answers them by calling the wallet's signer over its socket, as the MCP
server and the connector do.

**No custody.** The service spends only the owner's own wallet, under the owner's signed policy.
It holds nobody else's money and keeps no balance for anyone. It holds no wallet key either: the
signer holds them all, and the service is one more front end without keys.

What has been run: the unit and integration tests in the crate (the NIP-44 test vectors, the
request handling against a stand-in signer, the whole path over an in-process stand-in relay) and
the wallet UI's test against the service's admin socket. The service has not yet been run against
a public relay, a real NWC app or a Lightning node.

## What it does

| method | what the app gets |
|---|---|
| `pay_invoice` | a BOLT 11 XBT Lightning invoice paid by the signer's `ln_pay`; the answer carries the preimage and the fee paid |
| `get_balance` | what this connection may still spend: what is left of its budget for the last 24 hours, and never more than the node's channels hold on our side as the signer reports them (`ln_status`) |
| `get_info` | the network (`mainnet`, `regtest`, ...), the node's block height, and the methods this connection may use. The node's public key and alias are not given out |
| `lookup_invoice` | one of this connection's own payments, by payment hash or invoice, brought up to date from the signer's book (`ln_lookup`) |
| `list_transactions` | this connection's own payments, newest first (`from`, `until`, `limit`, `offset`; `unpaid` adds pending and failed ones). An answer is kept under 60,000 bytes; `offset` gives the next page |

An app sees only its own payments: never the owner's other payments, nor another app's.

## What it refuses

- **`make_invoice`**, and so receiving: `NOT_IMPLEMENTED`. The signer has no safe receive path yet.
  The Lightning rail's macaroon is checked to allow paying only (on mainnet a macaroon with more is
  refused), and the signer has no method that makes an invoice. Receiving needs a separate
  invoice-only macaroon and a signer method that makes and books invoices.
- **An invoice without feature bit 512** (`option_blake2b`): it is not an XBT Lightning invoice.
  The service checks this before the signer sees the invoice, and `ln_pay` checks it again.
- **An invoice without an amount**: the amount must be in the payee's signature. A `params.amount`
  that differs from the invoice's is refused.
- **BOLT 12 offers through `pay_invoice`**: `NOT_IMPLEMENTED`. NIP-47 `pay_invoice` is for BOLT 11.
  The signer's `ln_pay` pays offers, so offers could come later through an NWC extension.
- **NIP-04** (a request with no `encryption` tag, or with `nip04`): answered `UNSUPPORTED_ENCRYPTION`.
  NIP-04 is deprecated and its encryption is unauthenticated. The info event says `nip44_v2` only.
- `pay_keysend`, `multi_pay_invoice`, `multi_pay_keysend` and anything else: `NOT_IMPLEMENTED`.
- Hold invoices: NIP-47 has none. The stream tickets that are held stay on the signer's own rail.

## Limits on a payment

A payment has to pass two sets of checks:

1. **The connection's limits** (the service): it is not expired, it is allowed `pay_invoice`, it is
   within its request rate (60 a minute by default), and the invoice is not more than what is left
   of its budget for the last 24 hours. The payment is booked against the connection before the
   signer sees it.
2. **The owner's policy** (the signer, as for any agent): the service calls `ln_pay` with
   `max_sats` set to what is left of the connection's budget. The signer refuses a payment whose
   amount plus its fee limit is above that. Then every rule of the owner's policy applies as it
   does to an agent's payment: the daily and weekly budgets, the per-transaction and
   per-counterparty caps, the allowlist, velocity, and the human threshold with the owner's
   ed25519 approval. So do the rail's checks: the chain identity of the node, bit 512, the channels
   the payment may leave by, the exposure cap, and the booking ahead of the send.

The service cannot raise or widen either set of checks. A payment above the owner's human
threshold waits on the wallet UI's Approvals page. By default the app is answered at once
(`QUOTA_EXCEEDED`, with a message saying so), and the same invoice sent again after the approval is
paid under it. With `NWC_APPROVAL_WAIT_S` set, the service waits that long for the approval.

When the payment settles, its booking becomes what it cost. When it fails, or the policy refuses
it, the booking goes. A payment whose outcome the service does not know (the signer did not answer)
stays booked at its ceiling until the signer's book says how it ended. An app that sends the same
invoice again gets the same answer, and the invoice is never paid twice.

## Security model

- **Keys.** Each connection has its own wallet-service key, so relays cannot link one app's
  traffic to another's. The service keeps that key in its state file. The app's secret is made when
  the connection is made, and it is put in the connection string. It is shown once, on the page
  that made it, and kept nowhere: the service keeps only the app's public key. The state file is
  mode 0600 in a 0700 directory. No key, secret or connection string is written to the log.
- **Who is answered.** A request is answered only if its id and signature are valid, it is
  addressed to one of our connections, and it is signed by that connection's app key. It must also
  be at most an hour old, not past its `expiration` tag, and not seen before. Anything else gets no
  answer at all. A key we do not know learns nothing, not even that the service exists.
- **Revocation.** It takes effect at once. The connection is removed from the state, its requests
  are no longer answered, and the relays are subscribed to again without its key.
- **Relays.** They see the event kinds, the keys, the times and the sizes of requests and answers,
  but not their content. A relay can drop or delay a request; it cannot forge one, change one or
  read one. Only `wss://` relays are used, checked against the Mozilla root list; `ws://` is allowed
  only to this machine. Relays that ask for NIP-42 authentication are not served yet.
- **The admin socket.** The wallet UI makes and revokes connections on a Unix socket, mode 0600
  (at most 0660 with `NWC_ADMIN_SOCK_MODE`). Whoever can reach it can make a connection, and so
  spend what the owner's policy lets the signer spend. That is no more than the reach of the
  signer's own socket. The UI's page needs the owner's login and its CSRF token, like every other
  change.

## Running it

```
B2_SIGNER_SOCK=/path/to/signer.sock \
NWC_STATE_DIR=/path/to/nwc \
NWC_ADMIN_SOCK=/path/to/nwc-admin.sock \
NWC_RELAYS=wss://relay.example.com \
xbt-nwc
```

Set `XBT_UI_NWC_SOCK` on the wallet UI to the same admin socket. The variables are listed in
`crates/xbt-nwc/src/main.rs`. `xbt-nwc healthcheck` asks the admin socket for its status.
