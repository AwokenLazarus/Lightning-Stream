import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const current = VersionInfo.of({
  version: '0.2.0:0',
  releaseNotes: {
    en_US:
      'A public test release. Hashrate rentals with masked jobs, through the Stream Gateway (DATUM-compatible) that now runs inside the package, so rented miners cannot see a winning block and cannot withhold it; solo, or on Lazarus Pool. Every rental is checked masked job by job or refused. Sell your own web apps (for example Jellyfin, with an account per buyer), a shared folder (Files, from File Browser if you choose), AI, hashrate and VPN exits, paid as they are used. A shop needs no web address: buyers reach it by its key over an encrypted link, directly or through a relay, and in private mode only through relays. The built-in player is gone: share a media server as a web app. Several requests to one shop run side by side; a shop is paid no more than its listing says, one caught over-charging is blocked until you lift the block, and each shop has a daily cap. Relays in this release are free.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
