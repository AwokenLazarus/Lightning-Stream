import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const v0_1_18 = VersionInfo.of({
  version: '0.1.18:0',
  releaseNotes: {
    en_US:
      'Closing or pausing the player stops the paying, and a film is bought at most 4 MiB at a time. With the starter rules a buyer can play a film and then ask the AI of the same shop straight away. Live connections show what a stream has used as it plays. Tested on mainnet with small amounts only.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
