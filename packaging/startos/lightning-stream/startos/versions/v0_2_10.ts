import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const v0_2_10 = VersionInfo.of({
  version: '0.2.10:0',
  releaseNotes: {
    en_US:
      'Hashrate fixes, most sent by a hashmaker who runs the app. The market price works with Knots 29.4.3. The Hashrate page under Buy answers at once and says when it is still looking for offers on Nostr. A test slice can be paid. The Rent form suggests budgets in whole tickets and says what a budget buys. Renting turned back on brings the shop back without a Save. Add a service under Sell has a Hashrate choice. Rentals update by themselves, a refused payment says why, prices are said per TH/s for an hour, and your gateway takes your own coinbase tag.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
