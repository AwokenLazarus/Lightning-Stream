// English only for now; the other locales fall back to it (translations are a store-submission step).
export const short = {
  en_US: 'Buy and sell any service over Lightning from this server, paid as you use it',
}

export const long = {
  en_US:
    "One app for both sides. The wallet pays sellers with stream tickets under spending rules you sign, and your AI agents connect to its MCP server. The connector, on this server only, asks the signer to pay for what a service sends (a stream, a file, a reply) as it arrives. The sell side is the gateway: it stays idle until you add a service on the Sell page, and it holds only narrow keys that can ask for payments. Hashrate works both ways: rent your miners out (you are the hashmaker), or rent others' into your own DATUM Gateway (you are the hashtaker), paid piece by piece. The signer is the only service that can spend.\n\nSet the Node connection action (your Knots BLAKE2b node), start the service, and open the web interface with the Web UI setup code. The app asks your Lightning Fork node for its own narrow keys by itself; if it cannot, paste keys you make in Lightning Fork. Then make your approval key in the browser (download its backup: it is the key, not your passphrase) and sign the safe starter spending rules.\n\nThe keys stay in the signer, sealed on this server. A separate anchor witness keeps a tamper record of every signature. On mainnet this software moves real funds and has been tested there with small amounts only: the app asks you to acknowledge that before it pays with real money. Needs Lightning Fork and an XBT (BLAKE2b) node.",
}
