import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.2.13:0',
  releaseNotes: {
    en_US:
      'Long hashrate rentals keep paying on a slow wallet. A ticket that takes 11 to 15 seconds to buy over several Lightning hops is now bought ahead, while what is paid still lasts, so the next piece of work is paid from credit, and a hashmaker waits up to 30 seconds for a payment on its way instead of 10. Browse shows a hashrate offer\'s live price, the Hashrate page\'s offers fill the row, the wallet shows one row a payment, and Settings has a Your gateway tab.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
