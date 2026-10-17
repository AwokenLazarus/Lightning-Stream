import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.1.0:0',
  releaseNotes: {
    en_US: 'The signer, the anchor witness, the MCP server and the web UI, paying over Lightning Fork with stream tickets. Side-load only; regtest-tested only.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
