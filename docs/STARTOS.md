# Lightning Stream on StartOS

Lightning Stream installs on StartOS 0.4 from its own registry. You add the registry to your
server once; after that, installs and updates work like any other service.

It is tested on mainnet with small amounts only. Start with low limits.

## What you need first

- **StartOS 0.4** on your server.
- **Knots BLAKE2b**, the node for the Bitcoin BLAKE2b chain.
- **Lightning Fork**, Paul Lamb's Lightning node for that chain, from his StartOS registry
  (see step 1), version 0.21.4-beta.21.1:1 or later. Lightning
  Stream depends on it by its package id (`lightning-fork`), so install it first. A Lightning
  channel to the sellers' side of the network lets you pay.

## 1. Add the Lightning Stream registry

1. In StartOS, open **Marketplace**.
2. Open the registry menu: the current registry's name at the top left (**Start9 Registry** at first).
   In the list of saved registries, choose the gear icon, then add a registry.
3. Paste `https://registry.lazarus-xbt.xyz` and save.
4. Choose it in the registry menu. You should see **Lightning Stream**.

Add the registry Lightning Fork is published in the same way (its address is on the setup page,
https://lightning-stream.com/download/), and install Knots BLAKE2b and Lightning Fork from it first. A registry is for StartOS, not a web page:
opening one in a browser shows nothing.

## 2. Install

From the Lightning Stream registry, install **Lightning Stream**. It is one service for everything:
buying, selling, hashrate, and the wallet your agents pay with.

StartOS then says *This service package isn't signed by anyone you trust* and asks *Install untrusted
software?*. It says so for every package from a registry other than Start9's: choose **Install anyway**.

## 3. First start

1. **Node connection** (Actions): your Knots node's RPC host, port, user and password. First run
   Knots BLAKE2b's **Generate RPC User Credentials** action and use the user and password it shows.
   With Knots BLAKE2b on the same server, the host is `knots-blake2b.startos` and the port `18443`
   (the form offers both).
2. Start the service.
3. **Web UI setup code** (Actions): open the web interface, enter the code, choose a password.
4. In the web interface:
   - **Connect Lightning Fork** on the **Your node** page. Lightning Fork's current releases have
     no way to grant an app its key, so the page walks you through pasting its connection address:
     in StartOS, open Lightning Fork, then **Interfaces**, then **REST LND Connect**, and copy its
     address (it starts with `lndconnect://`); paste it on Your node and press **Connect**. The app
     uses it once to make its own key, which can only pay (`info:read offchain:read offchain:write
     onchain:read`) within your spending rules, and the shop's keys, which can only ask for
     payments. It keeps neither the address nor the full-access key in it. Lightning Fork's wallet
     must exist and be running.
     A Lightning Fork with the **Grant app access** action (Paul's test releases) is asked
     instead: run that task in Lightning Fork, and Your node says *Connected* a few seconds later.
     Either key can be revoked in Lightning Fork;
   - make your **approval key**. It stays in your browser. Download its backup file and keep it
     safe: the file is the key itself, not your passphrase;
   - sign the **safe starter rules** (Settings → Spending rules → Start from the safe starter
     rules). Nothing is paid over Lightning until you do.

## Selling and hashrate

- **Sell**: add a public domain to the service's *Gateway for buyers* interface, type that https
  address as your shop's address, and add what you sell. The shop needs keys of its own that can
  only ask for payments: connecting Your node with Lightning Fork's address made them. With the
  grant instead, paste them on the Sell page (it lists the permissions).
- **Rent your miners out** (Sell → Hashrate): point your miners at the *Miners* interface. Renters
  reach your miners through the app's direct link, encrypted end to end: no port forward or address
  is needed. Only hashtakers on apps from before the direct link need a forwarded TCP port 23341 (the *Hashrate
  link*), which you can enter under Advanced on the page.
- **Rent others' miners** (Buy → Hashrate): the work goes to your own DATUM Gateway.
- **AI for your programs** (Buy → AI): programs on your LAN that work with OpenAI's API use the
  AI sellers you allowed through the *AI address for programs* interface, each with a key you make
  on that page. See docs/INFERENCE.md.

## Updates

When a new version is published, StartOS shows an update badge on the service.

## Removing it

Uninstall from StartOS, then revoke Lightning Stream's access in Lightning Fork, and delete the
shop's keys there if you made them.

## Contact

The registry is run by the Lightning Stream project. Questions and problems: open an issue at
https://github.com/AwokenLazarus/Lightning-Stream/issues.
