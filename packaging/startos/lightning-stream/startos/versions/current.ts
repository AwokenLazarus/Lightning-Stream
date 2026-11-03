import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.2.8:0',
  releaseNotes: {
    en_US:
      'Small fixes from a hands-on run of 0.2.7. A visit\'s Stop says the credit with the shop is shared with your other uses of it. A spending limit that stops a payment says the payment would pass it. A player link answers a player\'s size check once the file is known. The Sell page shows its publish-anyway box only where it applies.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
