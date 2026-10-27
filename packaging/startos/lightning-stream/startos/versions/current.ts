import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.1.17:0',
  releaseNotes: {
    en_US:
      'A wallet whose channel goes straight to a shop can pay it: when the shop\'s BOLT 12 offer cannot be reached, the shop\'s ordinary invoice is paid instead, once. Tested on mainnet with small amounts only.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
