/**
 * The package's containers as plain data: which image, which user, which parts of the `main`
 * volume each one mounts, its environment and what it waits for. `main.ts` turns this into daemons, and
 * packaging/startos/test runs exactly these on Docker (the StartOS-shaped regtest run), so the test and the
 * package cannot drift. No SDK import here: `node --experimental-strip-types` loads it on its own.
 *
 * The `main` volume is laid out as docs/CONTAINER.md §1. StartOS mounts a volume root-owned on every start,
 * so the `init` oneshot (xbt-init, as root) gives each component's sub-dir to its uid first. Every daemon
 * then runs as its image's own non-root user and mounts only its sub-dir and the socket dirs it needs.
 */
export const PORTS = { ui: 8480, mcp: 33510 } as const

export type ImageKey = 'init' | 'signer' | 'witness' | 'mcp' | 'ui'
export type DaemonId = 'init' | 'witness' | 'signer' | 'mcp' | 'ui'

/**
 * A part of the `main` volume, or (with `dependency`) one file of another package's volume: Lightning Fork's
 * `tls.cert`, the one file of its data the package mounts, read-only (`mountDependency`, type `file`).
 */
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
  /** the port the service listens on (for readiness), if any */
  port?: number
  /** readiness: a command in the service's own image (the images have no shell) */
  readyCommand?: [string, ...string[]]
}

export type NodeConfig = {
  host: string
  port: number
  user: string
  password: string
  chain: 'main' | 'test' | 'regtest'
}

export type Config = {
  node: NodeConfig
  /** shown on the UI's Agents page: the MCP interface's addresses */
  mcpUrls: string[]
  /** Lightning Fork's REST address (`https://<its container address>:8080`), empty while it is not installed */
  lightningRest: string
}

/**
 * How the Lightning node's certificate reaches the signer and the UI.
 * - 'pin' (now): StartOS 0.4 mounts another package's data only as a folder, and Lightning Fork keeps
 *   tls.cert beside its macaroons, the admin one among them. Nothing of it is mounted: the owner pins
 *   the certificate on the UI's Lightning page (it shows the fingerprint the node presents), which
 *   writes it into the wallet's own run/ln. A certificate that later changes is refused by the signer
 *   until the owner pins again.
 * - 'folder' (once Lightning Fork keeps tls.cert in a folder of its own): mount that folder read-only
 *   (LF_CERT_FOLDER: Lightning Fork's public/ folder, which holds only tls.cert and is kept current) and the page offers no pinning.
 */
export const CERT_SOURCE = 'pin' as 'pin' | 'folder'
const LF_CERT_FOLDER = 'public'

/** Where the Lightning node's certificate is in the signer and the UI, and where the rail macaroon is. */
export const LIGHTNING = {
  packageId: 'lightning-fork',
  restPort: 8080,
  cert: CERT_SOURCE === 'pin' ? '/data/run/ln/tls.cert' : '/data/lightning/tls.cert',
  macaroon: '/data/run/ln/rail.macaroon',
} as const

/**
 * The published images, pinned by digest (packaging/images.lock; packaging/pin_images.py writes them);
 * one image set for Umbrel, StartOS and xbt-compute.
 */
export const IMAGES: Record<ImageKey, string> = {
  init: 'ghcr.io/awokenlazarus/xbt-init:0.1.0-cc28002e474e@sha256:dd00b3194dd4c32e955aeae8b729b1e7460ce3f57214eda878f24e2b3c0c276b',
  signer: 'ghcr.io/awokenlazarus/xbt-signer:0.1.0-cc28002e474e@sha256:68823bb1e1895807c42aa90df2f2658ead4eaa7fd7b3630540fd41433fd9a011',
  witness: 'ghcr.io/awokenlazarus/xbt-anchor-witness:0.1.0-cc28002e474e@sha256:f09ab563ba4571055e52f0d9139c01057b2aa07c45d44ef82307a85daf57abe8',
  mcp: 'ghcr.io/awokenlazarus/xbt-wallet-mcp:0.1.0-cc28002e474e@sha256:bca54d260f3a3edb8ff2b14f278bcaa9f6ff5a2156ca9a8d8d6f7f6cef433ebe',
  ui: 'ghcr.io/awokenlazarus/xbt-wallet-ui:0.1.0-cc28002e474e@sha256:c71d62e384b01b3910d50c21c4f4ff3bc59b847806c0a9b04cc30b130ff6ea53',
}

const vol = (subpath: string | null, mountpoint: string, readonly = false): MountSpec => ({ subpath, mountpoint, readonly })
/** Lightning Fork's certificate folder, mounted only in the 'folder' mode (CERT_SOURCE) */
const lightningCert: MountSpec = {
  subpath: LF_CERT_FOLDER,
  mountpoint: '/data/lightning',
  readonly: true,
  dependency: { packageId: LIGHTNING.packageId, volumeId: 'main', type: 'directory' },
}
const certMounts = (rest: string): MountSpec[] => (rest && CERT_SOURCE === 'folder' ? [lightningCert] : [])

export function services(cfg: Config): ServiceSpec[] {
  const node = {
    XBT_NODE_RPC_HOST: cfg.node.host,
    XBT_NODE_RPC_PORT: String(cfg.node.port),
    XBT_CHAIN: cfg.node.chain,
  }
  const components = ['signer', 'witness', 'mcp', 'ui']
  return [
    {
      id: 'init',
      image: 'init',
      user: 'root',
      command: ['/usr/bin/xbt-init', 'init'],
      env: {
        XBT_INIT_COMPONENTS: components.join(','),
        XBT_INIT_NODE_RPC_AUTH: `${cfg.node.user}:${cfg.node.password}`,
      },
      mounts: [vol(null, '/data')],
      requires: [],
    },
    {
      id: 'witness',
      image: 'witness',
      command: ['/usr/bin/xbt-anchor-witness', 'serve'],
      env: {},
      mounts: [vol('witness', '/data/witness'), vol('run/anchor', '/data/run/anchor')],
      requires: ['init'],
      readyCommand: ['/usr/bin/xbt-anchor-witness', 'healthcheck'],
    },
    {
      id: 'signer',
      image: 'signer',
      // xbt-supervise restarts the signer when the rail macaroon the UI writes, or the certificate, changes
      command: ['/usr/bin/xbt-supervise', '--watch', LIGHTNING.macaroon, '--watch', LIGHTNING.cert, '--', '/usr/bin/xbt-signer'],
      env: {
        ...node,
        ...(cfg.lightningRest ? { B2_LN_REST: cfg.lightningRest, B2_LN_MACAROON: LIGHTNING.macaroon, B2_MAINNET_ACK_FILE: '/data/run/ln/mainnet-ack', B2_LN_TLS_CERT: LIGHTNING.cert } : {}),
      },
      // run/ln: the rail macaroon (group xbt-ln-rail: the UI writes it, the signer reads it, the MCP cannot)
      mounts: [
        vol('signer', '/data/signer'),
        vol('run/signer', '/data/run/signer'),
        vol('run/anchor', '/data/run/anchor', true),
        vol('run/ln', '/data/run/ln', true),
        ...certMounts(cfg.lightningRest),
      ],
      requires: ['witness'],
      readyCommand: ['/usr/bin/xbt-signer', 'healthcheck'],
    },
    {
      id: 'mcp',
      image: 'mcp',
      command: ['/usr/bin/xbt-wallet-mcp'],
      // an over-threshold payment waits this long for the owner's approval in the UI
      // the Lightning rail's and the tickets' own tools (status, stop) beside xbt402_pay
      env: { XBT_MCP_HTTP: `0.0.0.0:${PORTS.mcp}`, XBT_MCP_APPROVAL_WAIT_S: '300', XBT_MCP_LN: '1', XBT_MCP_TICKETS: '1' },
      // the bearer token is the UI's run/ui/mcp-http-token (0640, group xbt-wallet-ui): read-only here
      mounts: [vol('mcp', '/data/mcp'), vol('run/signer', '/data/run/signer', true), vol('run/ui', '/data/run/ui', true)],
      requires: ['signer'],
      port: PORTS.mcp,
    },
    {
      id: 'ui',
      image: 'ui',
      command: ['/usr/bin/xbt-wallet-ui', 'serve'],
      env: {
        XBT_UI_BIND: `0.0.0.0:${PORTS.ui}`,
        XBT_UI_SIGNER_SOCK: '/data/run/signer/signer.sock',
        XBT_UI_MCP_URL: cfg.mcpUrls.join(','),
        ...(cfg.lightningRest ? { XBT_UI_LN_REST: cfg.lightningRest, XBT_UI_LN_TLS_CERT: LIGHTNING.cert, XBT_UI_LN_TLS_PIN: CERT_SOURCE === 'pin' ? '1' : '0' } : {}),
      },
      // the UI owns the MCP token and rotates it on its Agents page; its Lightning page writes run/ln
      mounts: [
        vol('ui', '/data/ui'),
        vol('run/signer', '/data/run/signer', true),
        vol('run/ui', '/data/run/ui'),
        vol('run/ln', '/data/run/ln'),
        ...certMounts(cfg.lightningRest),
      ],
      requires: ['signer'],
      port: PORTS.ui,
    },
  ]
}
