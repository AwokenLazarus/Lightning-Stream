import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.21.3:0',
  releaseNotes: { en_US: 'Regtest stand-in.' },
  migrations: { up: async () => {}, down: IMPOSSIBLE },
})
