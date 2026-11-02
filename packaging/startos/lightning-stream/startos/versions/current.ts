import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.2.1:0',
  releaseNotes: {
    en_US:
      'A fix to 0.2.0: on Browse, Found on Nostr, a shop reached by its key (such as the demo shop, Lightning Stream Genesis) now offers Add this shop. Before, it offered only a check with the seller, which failed with a name-lookup error.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
