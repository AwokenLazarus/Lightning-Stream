import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.1.0:0',
  releaseNotes: {
    en_US: 'The stream-ticket gateway and its setup page. Side-load only; regtest-tested only.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
