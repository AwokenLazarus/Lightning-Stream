# Lightning Stream Gateway

Sell an HTTP service you run, per request, per MiB or per second. Buyers' agents pay with stream tickets: a few
small hold invoices on your Lightning Fork node, one secret released per paid piece.

## First start

1. Install Lightning Fork first, and open a channel your buyers can reach you through (they pay you over it).
2. In Lightning Fork's dashboard, **Macaroons**: make two, each with a root key of its own:
   - one with exactly `invoices:read invoices:write`;
   - one with exactly `info:read`.
   Never use the admin macaroon: the setup page refuses one.
3. Start this service. **Setup page code** (Actions): open the *Setup page*, enter the code, choose a password.
4. On the setup page: the service you sell (`http://host:port`, as this server reaches it), the price and its
   unit, the https address buyers use, and the two macaroons. Save: the gateway starts with it.
5. To sell beyond your LAN: on the *Gateway for buyers* interface add a public domain. StartOS gets its
   certificate; type that `https://` address on the setup page. Buyers' wallets pay over https only.

## Mainnet

The setup page writes a test chain unless you choose mainnet and type the acknowledgement it shows. This
software has run on regtest only; on mainnet it starts you with low caps (4 buyers, 4 held tickets of
1,000 sat). Read the warning on the page first.

## Backups

StartOS backups include the gateway's receipt key, its sessions and journal (what buyers have paid and not
used), its config and macaroons.
