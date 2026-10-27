# Lightning Stream

Buy and sell any service over Lightning from this server, paid as you use it. One app for both sides:
the wallet pays sellers under spending rules you sign, your shop sells what you run, and hashrate works
both ways. Tested on mainnet with small amounts only: start with low limits.

## First start

1. Install **Lightning Fork** first (from its own StartOS registry), with a channel.
2. **Node connection** (Actions): your Knots BLAKE2b node's RPC host, port, user and password, and its
   chain. The service does not start without it.
3. Start the service. *Wallet ready to pay* turns green once the node is synced and the keys are unlocked.
4. **Web UI setup code** (Actions): open the *Web interface*, enter the code, and choose your password.
5. In the web interface:
   - **Your node**: the app asks Lightning Fork for its own narrow keys by itself. If the page says it
     could not, make the keys in Lightning Fork's dashboard and paste them there;
   - make your **approval key**. It stays in your browser. Download its backup file: the file is the key
     itself, not your passphrase;
   - sign the **safe starter rules** (Settings → Spending rules → Start from the safe starter rules).
     Nothing is paid over Lightning until you do.

## Buying

Add a seller on **Services** with the address they gave you, then allow it to be paid with one signature.
Agents connect to the *MCP server for agents* interface with the token from the **Agent connection** action
(or the Agents page).

## Selling

Open **Sell**: name your shop, add a public domain to the *Gateway for buyers* interface and type that
https address as the shop's address, then add each service you sell with its price.

## Hashrate

- **Rent your miners out** (you are the hashmaker): Sell → Hashrate. Point your miners at the *Miners*
  interface's address. Renters outside your network reach the *Hashrate link* (TCP 23341): forward that
  port on your router, or use a tunnel, and enter the public address on the page.
- **Rent others' miners** (you are the hashtaker): Services → Hashrate. The work goes to your own DATUM
  Gateway (the BLAKE2b one, or the official one).

## Password

*Reset the web UI password* forgets the password; the service restarts and *Web UI setup code* gives a new
code. Your approval key and your funds are not affected.

## Backups

StartOS backups include the signer's sealed keys and their wrapping key, the ledgers, the signature anchors,
your shop and hashrate settings. Keep the StartOS backup as safe as the wallet.

## Uninstalling

The keys the app made stay valid in Lightning Fork until you delete them there: note their root key ids on
the app's Your node page (under Details) before you uninstall.
