import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const v0_1_14 = VersionInfo.of({
  version: '0.1.14:0',
  releaseNotes: {
    en_US:
      'Lightning Stream as one package, as on Umbrel: buy and sell services over Lightning, rent hashrate out or in, and let your agents pay within the rules you sign. Tested on mainnet with small amounts only.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
