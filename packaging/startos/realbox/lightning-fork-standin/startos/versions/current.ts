import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.21.4-beta.21.1:1',
  releaseNotes: { en_US: 'Regtest stand-in at the release that keeps tls.cert alone in public/.' },
  migrations: { up: async () => {}, down: IMPOSSIBLE },
})
