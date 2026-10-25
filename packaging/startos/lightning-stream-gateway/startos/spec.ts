/**
 * The gateway package's containers as plain data: which image, which user, which parts of the `main` volume
 * each one mounts, its environment and what it waits for. `main.ts` turns this into daemons, and
 * packaging/startos/test runs exactly these on Docker, so the test and the package cannot drift. No SDK import
 * here: `node --experimental-strip-types` loads it on its own.
 *
 * The `main` volume is laid out as docs/CONTAINER.md §1: `gateway/` is the gateway's state, `ui/` the setup
 * page's login, and `run/gateway/` the config and the two macaroons the setup page writes (owned by the UI,
 * group xbt-gateway: the gateway reads them, nothing else does). StartOS mounts the volume root-owned on every
 * start, so the `init` oneshot (xbt-init, as root) gives each sub-dir to its uid first. Of Lightning Fork's data
 * only its `tls.cert` is mounted, read-only. No admin macaroon is ever mounted or kept.
 */
export const PORTS = { ui: 8481, gateway: 8402 } as const

export type ImageKey = 'init' | 'gateway' | 'ui'
export type DaemonId = 'init' | 'gateway' | 'ui'

/** A part of the `main` volume, or (with `dependency`) one file of another package's volume. */
export type MountSpec = {
  subpath: string | null
  mountpoint: string
  readonly: boolean
  dependency?: { packageId: string; volumeId: string; type: 'file' | 'directory' }
}

export type ServiceSpec = {
  id: DaemonId
  image: ImageKey
  /** the image's own user unless set (only `init` runs as root) */
  user?: string
  command: [string, ...string[]]
  env: Record<string, string>
  mounts: MountSpec[]
  requires: DaemonId[]
  port?: number
  readyCommand?: [string, ...string[]]
}

export type Config = {
  /** Lightning Fork's REST address (`https://<its container address>:8080`), empty while it is not installed */
  lightningRest: string
  /** the addresses StartOS's proxy connects from, offered on the page as the X-Forwarded-For source to believe */
  proxies: string[]
}

/**
 * How the Lightning node's certificate reaches the gateway, as in the wallet package: 'pin' (now)
 * mounts nothing of Lightning Fork (its tls.cert sits beside its macaroons, and StartOS 0.4 mounts a
 * folder or nothing); the owner pins the certificate on the setup page, which writes it into the
 * gateway's own run/gateway. 'folder', once Lightning Fork keeps tls.cert in a folder of its own,
 * mounts that folder read-only (LF_CERT_FOLDER, to be confirmed against its release).
 */
export const CERT_SOURCE = 'pin' as 'pin' | 'folder'
const LF_CERT_FOLDER = 'tls'

export const LIGHTNING = {
  packageId: 'lightning-fork',
  restPort: 8080,
  cert: CERT_SOURCE === 'pin' ? '/data/run/gateway/tls.cert' : '/data/lightning/tls.cert',
} as const

/**
 * The published images, pinned by digest (packaging/images.lock; packaging/pin_images.py writes them);
 * the image set Umbrel and the wallet package use.
 */
export const IMAGES: Record<ImageKey, string> = {
  init: 'ghcr.io/awokenlazarus/xbt-init:0.1.0-cc28002e474e@sha256:dd00b3194dd4c32e955aeae8b729b1e7460ce3f57214eda878f24e2b3c0c276b',
  gateway: 'ghcr.io/awokenlazarus/xbt-gateway:0.1.0-cc28002e474e@sha256:2890c98a4aefd545c08b78b882111d9435fbb43058fe2098d13b80f28d3c214f',
  ui: 'ghcr.io/awokenlazarus/xbt-wallet-ui:0.1.0-cc28002e474e@sha256:c71d62e384b01b3910d50c21c4f4ff3bc59b847806c0a9b04cc30b130ff6ea53',
}

const vol = (subpath: string | null, mountpoint: string, readonly = false): MountSpec => ({ subpath, mountpoint, readonly })
const lightningCert: MountSpec = {
  subpath: LF_CERT_FOLDER,
  mountpoint: '/data/lightning',
  readonly: true,
  dependency: { packageId: LIGHTNING.packageId, volumeId: 'main', type: 'directory' },
}

export function services(cfg: Config): ServiceSpec[] {
  const cert = cfg.lightningRest && CERT_SOURCE === 'folder' ? [lightningCert] : []
  return [
    {
      id: 'init',
      image: 'init',
      user: 'root',
      command: ['/usr/bin/xbt-init', 'init'],
      env: { XBT_INIT_COMPONENTS: 'gateway,ui' },
      mounts: [vol(null, '/data')],
      requires: [],
    },
    {
      id: 'gateway',
      image: 'gateway',
      // the image's entrypoint: xbt-supervise starts the gateway once the page has written its config, and
      // again when the config, a macaroon or the certificate changes
      command: [
        '/usr/bin/xbt-supervise',
        '--wait',
        '/data/run/gateway/config.json',
        '--watch',
        '/data/run/gateway/invoices.macaroon',
        '--watch',
        '/data/run/gateway/info.macaroon',
        '--watch',
        LIGHTNING.cert,
        '--',
        '/usr/bin/xbt-gateway',
        '/data/run/gateway/config.json',
      ],
      env: {},
      mounts: [vol('gateway', '/data/gateway'), vol('run/gateway', '/data/run/gateway', true), ...cert],
      requires: ['init'],
      port: PORTS.gateway,
    },
    {
      id: 'ui',
      image: 'ui',
      command: ['/usr/bin/xbt-wallet-ui', 'serve'],
      env: {
        XBT_UI_ROLE: 'gateway',
        XBT_UI_BIND: `0.0.0.0:${PORTS.ui}`,
        XBT_UI_GW_PORT: String(PORTS.gateway),
        XBT_UI_GW_HEALTH_URL: `http://127.0.0.1:${PORTS.gateway}/x402/ticket/health`,
        XBT_UI_GW_PROXIES: cfg.proxies.join(','),
        ...(cfg.lightningRest ? { XBT_UI_GW_NODE_REST: cfg.lightningRest, XBT_UI_GW_NODE_TLS_CERT: LIGHTNING.cert, XBT_UI_GW_NODE_TLS_PIN: CERT_SOURCE === 'pin' ? '1' : '0' } : {}),
      },
      // the setup page writes run/gateway
      mounts: [vol('ui', '/data/ui'), vol('run/ui', '/data/run/ui'), vol('run/gateway', '/data/run/gateway'), ...cert],
      requires: ['init'],
      port: PORTS.ui,
    },
  ]
}
