import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const v0_2_14 = VersionInfo.of({
  version: '0.2.14:0',
  releaseNotes: {
    en_US:
      'No hashrate rental is paid to a hashmaker with no miner online or to a seller the wallet cannot reach: before anything is paid, the app checks the offer has a free miner, the price is no dearer than the page showed, and the wallet\'s node finds a route to the seller\'s node. A rental going on can be topped up with sats and minutes, a rental refused on a seller\'s new price opens again on it when it costs no more, shops that stopped are said to be offline and folded away, listings lapse after a week unless sent again, no secret shows in a page as it opens, and Browse has an icon for each kind of service.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
