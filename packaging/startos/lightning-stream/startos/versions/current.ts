import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.1.19:1',
  releaseNotes: {
    en_US:
      'The AI page and the Agents page show their addresses with the path once (they repeated /v1 and /mcp, so a copied address did not work). Also in 0.1.19: a session busy spending its credit stays open; a local AI address any AI app on your network can use, paid per token; hashrate rentals survive a short break in the link; a new, calmer look. Tested on mainnet with small amounts only.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
