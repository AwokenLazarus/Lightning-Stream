import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const v0_2_4 = VersionInfo.of({
  version: '0.2.4:0',
  releaseNotes: {
    en_US:
      'A fix release for web apps. A web app such as Jellyfin now loads many requests at once, so it opens in seconds instead of after a long white page, and its sign-in no longer hangs. Free parts of a shop are asked for directly. On Hashrate, a disabled Rent says why, and your own offer is marked as yours. Home counts a shop allowed through its node. An AI seller\'s page points to your AI address.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
