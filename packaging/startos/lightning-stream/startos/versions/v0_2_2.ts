import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const v0_2_2 = VersionInfo.of({
  version: '0.2.2:0',
  releaseNotes: {
    en_US:
      'A fix release for first purchases. Sellers show by name everywhere; who may be paid is a list you can only remove whole sellers from, and the app warns before signing if a seller has no Lightning node. When a payment cannot happen, the app says why in plain words instead of a blank page, and warns before paying when your node cannot send. A visit shows what it used and what is left as credit. The version shows in the footer and Setup. Pages that waited on relays or the hashrate service open at once.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
