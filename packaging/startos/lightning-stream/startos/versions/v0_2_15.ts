import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const v0_2_15 = VersionInfo.of({
  version: '0.2.15:0',
  releaseNotes: {
    en_US:
      'Works with Lightning Fork\'s current releases, which have no Grant app access action: Your node walks you through pasting Lightning Fork\'s REST LND Connect address, from which the app makes its own narrow keys once and keeps neither the address nor its key. No task for a missing action, and no service restarting every 15 seconds. The Node connection form offers Knots BLAKE2b\'s address and port 18443, the setup code page names StartOS\'s own place for it, Home and Setup count the same steps done, and a hashrate rental whose budget is spent ends as that, not as unpaid.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
