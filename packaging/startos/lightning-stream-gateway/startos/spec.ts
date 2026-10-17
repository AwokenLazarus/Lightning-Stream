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
  dependency?: { packageId: string; volumeId: string; type: 'file' }
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

export const LIGHTNING = { packageId: 'lightning-fork', restPort: 8080, cert: '/data/lightning/tls.cert' } as const

/** The local image tags (scripts/oci_build.sh --load); the image set Umbrel and the wallet package use. */
export const IMAGES: Record<ImageKey, string> = {
  init: 'xbt-init:0.1.0',
  gateway: 'xbt-gateway:0.1.0',
  ui: 'xbt-wallet-ui:0.1.0',
}

const vol = (subpath: string | null, mountpoint: string, readonly = false): MountSpec => ({ subpath, mountpoint, readonly })
const lightningCert: MountSpec = {
  subpath: 'tls.cert',
  mountpoint: LIGHTNING.cert,
  readonly: true,
  dependency: { packageId: LIGHTNING.packageId, volumeId: 'main', type: 'file' },
}

export function services(cfg: Config): ServiceSpec[] {
  const cert = cfg.lightningRest ? [lightningCert] : []
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
        ...(cfg.lightningRest ? { XBT_UI_GW_NODE_REST: cfg.lightningRest, XBT_UI_GW_NODE_TLS_CERT: LIGHTNING.cert } : {}),
      },
      // the setup page writes run/gateway
      mounts: [vol('ui', '/data/ui'), vol('run/ui', '/data/run/ui'), vol('run/gateway', '/data/run/gateway'), ...cert],
      requires: ['init'],
      port: PORTS.ui,
    },
  ]
}
