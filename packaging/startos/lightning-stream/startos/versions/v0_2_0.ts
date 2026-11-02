import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const v0_2_0 = VersionInfo.of({
  version: '0.2.0:0',
  releaseNotes: {
    en_US:
      'A public test release. Rented hashrate is masked: the app now carries its own Stream Gateway (DATUM-compatible), which gives every job a key of its own, so a hashmaker cannot tell which shares win and cannot drop them. Every job is checked before a miner gets it, and a rental never runs on jobs that are not masked. Mining is solo by default, paid to your XBT address; Lazarus Pool is a choice on Services → Hashrate. The Stream Gateway reads your node through the Node connection action and needs nothing else installed. Sell your own web apps (for example Jellyfin, with an account per buyer), a shared folder (Files, from File Browser if you choose), AI, hashrate and VPN exits, paid as they are used. A shop needs no web address: buyers reach it by its key over an encrypted link, directly or through a relay, and in private mode only through relays. The built-in player is gone: share a media server as a web app. Several requests to one shop run side by side; a shop is paid no more than its listing says, one caught over-charging is blocked until you lift the block, and each shop has a daily cap. Relays in this release are free.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
