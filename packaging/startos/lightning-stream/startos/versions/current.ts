import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.2.11:0',
  releaseNotes: {
    en_US:
      'Hashrate fixes sent by a hashmaker who runs the app. A payment the wallet\'s socket could not take for a moment is made again, never twice, so a long rental keeps paying. Ended rentals fold under History, and each rental says when it started, ended and why. Your gateway on the Hashrate page under Buy links to the Stream Gateway\'s own status pages, read-only.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
