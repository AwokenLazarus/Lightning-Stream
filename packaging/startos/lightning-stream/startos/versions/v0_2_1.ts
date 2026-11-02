import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const v0_2_1 = VersionInfo.of({
  version: '0.2.1:0',
  releaseNotes: {
    en_US:
      'A fix to 0.2.0: on Browse, Found on Nostr, a shop reached by its key (such as the demo shop, Lightning Stream Genesis) now offers Add this shop. Before, it offered only a check with the seller, which failed with a name-lookup error. A file cheaper than the smallest ticket a shop sells (546 sat) can now be downloaded: its first call buys one ticket and the rest stays as credit, and a refusal is a page in words, not raw JSON. A web-app visit needs a limit of at least 559 sat; a smaller one is refused with the reason and set to 559.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
