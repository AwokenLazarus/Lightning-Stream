import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.2.12:0',
  releaseNotes: {
    en_US:
      'Renting hashrate on spending rules signed before the app could rent hashrate. The Hashrate page under Buy says when your rules do not allow renting hashrate yet, with a button that adds only that to your rules for you to sign, and Rent stays off until then. A rental refused for it says so, and that nothing was paid. The rules page shows the budget for renting hashrate.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
