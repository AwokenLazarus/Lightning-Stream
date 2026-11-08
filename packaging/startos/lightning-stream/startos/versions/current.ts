import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.2.18:0',
  releaseNotes: {
    en_US:
      'The signer starts at once: it checks its on-chain coins after starting, and lets that scan finish, instead of waiting 30 seconds at every start and leaving the node scanning. Hashrate: an ended rental keeps its delivered figure, its card no longer says "on 0 machines", and the Rent estimate counts the machines you type when an offer doesn\'t say how many are free.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
