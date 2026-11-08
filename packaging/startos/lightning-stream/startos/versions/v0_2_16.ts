import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const v0_2_16 = VersionInfo.of({
  version: '0.2.16:0',
  releaseNotes: {
    en_US:
      'The log now explains the "Not Found" StartOS records when Lightning Fork has no Grant app access action: Lightning Stream connects by its address instead. The Node connection banner says when the form shows the connection you saved, Your node shows "No key connected yet" instead of a missing-file error before a key is connected, and Home\'s First steps and Setup\'s own count are named as the two lists they are.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
