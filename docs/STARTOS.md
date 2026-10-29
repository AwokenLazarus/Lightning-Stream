# Lightning Stream on StartOS

Lightning Stream installs on StartOS 0.4 from its own registry. You add the registry to your
server once; after that, installs and updates work like any other service.

It is tested on mainnet with small amounts only. Start with low limits.

## What you need first

- **StartOS 0.4** on your server.
- **Knots BLAKE2b**, the node for the Bitcoin BLAKE2b chain.
- **Lightning Fork**, Paul Lamb's Lightning node for that chain, from his StartOS registry
  (see step 1), version 0.21.4-beta.21.1:2 or later. Lightning
  Stream depends on it by its package id (`lightning-fork`), so install it first. A Lightning
  channel to the sellers' side of the network lets you pay.

## 1. Add the Lightning Stream registry

1. In StartOS, open **Marketplace**.
2. Open the registry menu at the top (**Switch**), then choose **Add**.
3. Paste `https://registry.lazarus-xbt.xyz` and save.
4. Switch to it. You should see **Lightning Stream**.

Add the registry Lightning Fork is published in the same way (its address is on the setup page,
https://lazarus-xbt.xyz/stream/start/), and install Knots BLAKE2b and Lightning Fork from it first. A registry is for StartOS, not a web page:
opening one in a browser shows nothing.

## 2. Install

From the Lightning Stream registry, install **Lightning Stream**. It is one service for everything:
buying, selling, hashrate, and the wallet your agents pay with.

## 3. First start

1. **Node connection** (Actions): your Knots node's RPC host, port, user and password.
2. Start the service.
3. **Web UI setup code** (Actions): open the web interface, enter the code, choose a password.
4. In the web interface:
   - **Approve the app in Lightning Fork.** Lightning Stream asks Lightning Fork for its own key:
     open Lightning Fork, run its **Grant app access** task for Lightning Stream, and the app's
     **Your node** page says *Connected* a few seconds later. The key can only pay, within your
     spending rules; you can revoke it in Lightning Fork at any time;
   - make your **approval key**. It stays in your browser. Download its backup file and keep it
     safe: the file is the key itself, not your passphrase;
   - sign the **safe starter rules** (Settings → Spending rules → Start from the safe starter
     rules). Nothing is paid over Lightning until you do.

## Selling and hashrate

- **Sell**: add a public domain to the service's *Gateway for buyers* interface, type that https
  address as your shop's address, and add what you sell. The shop needs two keys of its own that can
  only ask for payments: make them in Lightning Fork's dashboard (the Sell page lists the
  permissions) and paste them there.
- **Rent your miners out** (Sell → Hashrate): point your miners at the *Miners* interface. Renters
  outside your network reach TCP port 23341 (the *Hashrate link*): forward it on your router, or use
  a tunnel, and enter the public address on the page.
- **Rent others' miners** (Services → Hashrate): the work goes to your own DATUM Gateway.

## Updates

When a new version is published, StartOS shows an update badge on the service.

## Removing it

Uninstall from StartOS, then revoke Lightning Stream's access in Lightning Fork, and delete the
shop's keys there if you made them.

## Contact

The registry is run by the Lightning Stream project. Questions and problems: open an issue at
https://github.com/AwokenLazarus/Lightning-Stream/issues.
