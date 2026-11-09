import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.2.19:0',
  releaseNotes: {
    en_US:
      'Fixes a paid win left unpaid at the end of a call: when a win waited behind another payment to the same seller and its invoice ran out meanwhile, the wallet now asks the seller for a new invoice at once instead of leaving the win owed for a later call.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
