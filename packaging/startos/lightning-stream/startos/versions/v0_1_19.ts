import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const v0_1_19 = VersionInfo.of({
  version: '0.1.19:0',
  releaseNotes: {
    en_US:
      'A session busy spending its credit stays open, so long films and rentals no longer strand credit. New: a local AI address any AI app on your network can use, paid per token, with a key and limit per program. Hashrate rentals survive a short break in the link. A new, calmer look. Tested on mainnet with small amounts only.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
