import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const v0_2_6 = VersionInfo.of({
  version: '0.2.6:0',
  releaseNotes: {
    en_US:
      'The public testing release. Your spending rules are checked before a shop is asked for a ticket, and a limit that stops a payment says so in plain words, naming the shop, the limit and where to raise it, also at the AI address. The starter rules fit a film and some AI at one shop. Selling Jellyfin 10.11 and newer works, and a web app\'s page files can be free. Paid amounts are exact. AI agents can list what they may buy. A shop that changes its address withdraws its old listing. Plain words throughout.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
