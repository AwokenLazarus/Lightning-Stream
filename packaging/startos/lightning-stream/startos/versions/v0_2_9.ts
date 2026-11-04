import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const v0_2_9 = VersionInfo.of({
  version: '0.2.9:0',
  releaseNotes: {
    en_US:
      'A fix release: renting hashrate works with the published images. The rental component was built without a library feature it needs, which made a rental fail to start; it now declares it, and a release check builds every component the way publishing does.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
