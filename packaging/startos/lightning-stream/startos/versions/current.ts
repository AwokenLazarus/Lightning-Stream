import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.1.16:0',
  releaseNotes: {
    en_US:
      'A shop that moved to a new address is listed there whole, items included, and a wallet can allow it to be paid. Tested on mainnet with small amounts only.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
