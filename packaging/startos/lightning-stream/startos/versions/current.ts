import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.2.17:0',
  releaseNotes: {
    en_US:
      'Fixes the web UI restarting every 30 seconds while the XBT node syncs: the signer now writes its readiness on time even when the node is slow to answer, so StartOS no longer takes it for dead. Hashrate offers now say each machine\'s speed and what all the free machines cost for an hour, 12 and 24 hours, and the Rent form says what the machines and minutes you type come to.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
