import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const v0_2_7 = VersionInfo.of({
  version: '0.2.7:0',
  releaseNotes: {
    en_US:
      'Fixes from a hands-on run of 0.2.6. Stop ends a visit completely, closing only what that visit used. A visit buys a ticket only when it needs one, and its report says exactly what it used and what was newly paid. Long AI answers no longer fail. Player links have their own address, so VLC and other players can open them on Umbrel. The Sell page warns when a media server has no way in for buyers. Plain names for the stream tickets budget and the wallet\'s records. The Stream Gateway that powers mining rental is now built on FlyTheElephant\'s datum_gateway.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
