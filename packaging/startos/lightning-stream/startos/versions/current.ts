import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.2.0:0',
  releaseNotes: {
    en_US:
      'Rented hashrate is masked: the app now carries its own Stream Gateway (DATUM-compatible), which gives every job a key of its own, so a hashmaker cannot tell which shares win and cannot drop them. Every job is checked before a miner gets it, and a rental never runs on jobs that are not masked. Mining is solo by default, paid to your XBT address; Lazarus Pool is a choice on Services → Hashrate. The Stream Gateway reads your node through the Node connection action and needs nothing else installed.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
