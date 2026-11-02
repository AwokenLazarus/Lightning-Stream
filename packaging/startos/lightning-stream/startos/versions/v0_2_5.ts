import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const v0_2_5 = VersionInfo.of({
  version: '0.2.5:0',
  releaseNotes: {
    en_US:
      'Web apps such as Jellyfin load faster and whole: answers are no longer cut where the credit with a shop ends, the credit is topped up before it runs out, and free parts of a shop are sent compressed and kept by the browser. Stop closes the connection with the shop. A video visit gets a limit for about ten minutes of 1080p, and Add raises it. Shops can fix the UDP ports of their link so more buyers reach them directly.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
