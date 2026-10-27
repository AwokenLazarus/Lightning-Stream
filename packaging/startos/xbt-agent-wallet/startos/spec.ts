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
export type DaemonId = 'init' | 'node-keys' | 'witness' | 'signer' | 'mcp' | 'ui'

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
export const CERT_SOURCE = 'folder' as 'pin' | 'folder'
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
  init: 'ghcr.io/awokenlazarus/xbt-init:0.1.0-2fe4f1051c00@sha256:16e0c94b588dd93435779184862c788ba465d6d47cf5040468b784af047c9224',
  signer: 'ghcr.io/awokenlazarus/xbt-signer:0.1.0-2fe4f1051c00@sha256:830c973a897754c9a4256d0b326fcb20e1c0010972d6360b73f5e0ffbb341c7a',
  witness: 'ghcr.io/awokenlazarus/xbt-anchor-witness:0.1.0-2fe4f1051c00@sha256:ab50f74a9e68d28497445364545a936b564b820e61c2484782b04bb01266deae',
  mcp: 'ghcr.io/awokenlazarus/xbt-wallet-mcp:0.1.0-2fe4f1051c00@sha256:cc3218dc5f3dc941457a0d0087bc19d75baea4c37648942c8cb544e7481f131a',
  ui: 'ghcr.io/awokenlazarus/xbt-wallet-ui:0.1.0-2fe4f1051c00@sha256:f7c1fa2e9e4f4ebbc132b524a01ce992eb64a994a437619d3687135c07d58cbb',
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
/**
 * Lightning Fork's chain data, where its admin macaroon is: mounted read-only into the one-shot
 * node-keys only, which has the node bake the wallet's narrow rail macaroon (under a root key of its
 * own) and writes only that, into run/ln. No other service mounts it. Lightning Fork keeps its lnd
 * dir at the root of its main volume (tls.cert beside data/), so the chain data is `data/chain`.
 */
const lightningChainData: MountSpec = {
  subpath: 'data/chain',
  mountpoint: '/node/chain',
  readonly: true,
  dependency: { packageId: LIGHTNING.packageId, volumeId: 'main', type: 'directory' },
}

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
      // connects the wallet to the box's Lightning node with no step by the owner; it exits once the
      // rail macaroon is there (made now, made before, or the owner's own). Root: Lightning Fork's
      // files are its own user's, and this one-shot only reads them and writes run/ln (given its group)
      id: 'node-keys',
      image: 'ui',
      user: 'root',
      command: ['/usr/bin/xbt-wallet-ui', 'node-keys'],
      env: cfg.lightningRest
        ? { XBT_KEYS_NODE_REST: cfg.lightningRest, XBT_KEYS_TLS_CERT: LIGHTNING.cert, XBT_KEYS_ADMIN: '/node/chain', XBT_KEYS_RAIL_DIR: '/data/run/ln' }
        : {},
      mounts: cfg.lightningRest && CERT_SOURCE === 'folder' ? [vol('run/ln', '/data/run/ln'), lightningChainData, lightningCert] : [],
      requires: ['init'],
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
        // a copy of the one-time enrolment code for the setup page (run/enroll: the signer and the UI only)
        B2_ENROLL_CODE_COPY: '/data/run/enroll/enroll-code',
      },
      // run/ln: the rail macaroon (group xbt-ln-rail: the UI writes it, the signer reads it, the MCP cannot)
      mounts: [
        vol('signer', '/data/signer'),
        vol('run/signer', '/data/run/signer'),
        vol('run/anchor', '/data/run/anchor', true),
        vol('run/ln', '/data/run/ln', true),
        vol('run/enroll', '/data/run/enroll'),
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
        // the signer's one-time enrolment code: the setup page fills it in, so no log has to be read
        XBT_UI_ENROLL_CODE_FILE: '/data/run/enroll/enroll-code',
      },
      // the UI owns the MCP token and rotates it on its Agents page; its Lightning page writes run/ln
      mounts: [
        vol('ui', '/data/ui'),
        vol('run/signer', '/data/run/signer', true),
        vol('run/ui', '/data/run/ui'),
        vol('run/ln', '/data/run/ln'),
        vol('run/enroll', '/data/run/enroll', true),
        ...certMounts(cfg.lightningRest),
      ],
      requires: ['signer'],
      port: PORTS.ui,
    },
  ]
}
