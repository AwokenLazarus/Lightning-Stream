import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const v0_2_3 = VersionInfo.of({
  version: '0.2.3:0',
  releaseNotes: {
    en_US:
      'A usability release. The menu says Buy and Sell; rarely used settings sit under Advanced. Signing the starter rules on mainnet includes the yes to paying with real money, and Your node can stop paying. The demo shop can be added and allowed in one click. Each payment shows one cost: what left your node, with the routing fee beside it. Credit with a shop is shown and used first. The VPN page lists exits found on Nostr with Add this exit. Pages open faster. The app has a new look, dark by default, with a light/dark toggle.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
