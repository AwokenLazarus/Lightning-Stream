import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.1.15:0',
  releaseNotes: {
    en_US:
      'A new wallet on mainnet pays right after setup: tickets are sized under your approval threshold, setup asks you to confirm paying with real money, and credit left with a seller is used first, after a restart and under any of its addresses. Another app of the server can no longer make the wallet pay. Tested on mainnet with small amounts only.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
