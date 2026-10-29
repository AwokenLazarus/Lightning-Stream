/**
 * The package's containers as plain data: which image, which user, which parts of the `main`
 * volume each one mounts, its environment and what it waits for. `main.ts` turns this into daemons, and
 * packaging/startos/test runs exactly these on Docker (the StartOS-shaped regtest run), so the test and the
 * package cannot drift. No SDK import here: `node --experimental-strip-types` loads it on its own.
 *
 * One package for the whole app, as the Umbrel app is: the wallet (signer, anchor witness, MCP server, web
 * UI, the connector that plays what is bought), the shop (the gateway) and hashrate (the hashmaker, which
 * rents this owner's miners out, and the hashtaker, which rents others' into the owner's DATUM Gateway).
 * Every service of a StartOS package shares one network namespace, so they reach each other on 127.0.0.1.
 *
 * The `main` volume is laid out as docs/CONTAINER.md §1. StartOS mounts a volume root-owned on every start,
 * so the `init` oneshot (xbt-init, as root) gives each component's sub-dir to its uid first. Every daemon
 * then runs as its image's own non-root user and mounts only its sub-dir and the socket dirs it needs.
 */
export const PORTS = {
  ui: 8482,
  mcp: 33510,
  gateway: 8402,
  connector: 8484,
  ai: 33540,
  hashmakerControl: 23342,
  hashmakerSlices: 23344,
  hashtakerControl: 23343,
  miners: 23340,
  link: 23341,
} as const

export type ImageKey = 'init' | 'signer' | 'witness' | 'mcp' | 'ui' | 'gateway' | 'connector' | 'hashlink'
export type DaemonId =
  | 'init'
  | 'node-keys'
  | 'witness'
  | 'signer'
  | 'mcp'
  | 'ui'
  | 'connector'
  | 'gateway'
  | 'hashmaker'
  | 'hashtaker'

/** A part of the `main` volume, or (with `dependency`) a folder of another package's volume, read-only. */
export type MountSpec = {
  subpath: string | null
  mountpoint: string
  readonly: boolean
  dependency?: { packageId: string; volumeId: string; type: 'file' | 'directory' }
}

export type ServiceSpec = {
  id: DaemonId
  image: ImageKey
  /** the image's own user unless set (only `init` and `node-keys` run as root) */
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
  /** the addresses StartOS's proxy connects from, believed as the source of X-Forwarded-For at the gateway */
  proxies: string[]
  /** this server's address on the LAN, for the miners' and the link's addresses the hashrate pages show */
  lanHost: string
  /** the AI interface's addresses (`…/v1`), the first shown on the UI's AI page; empty before StartOS names one */
  aiUrls?: string[]
}

/** The Lightning node's certificate: Lightning Fork's public/ folder, which holds only tls.cert. */
const LF_CERT_FOLDER = 'public'

/** Where the Lightning node's certificate is in the services, and where the wallet's rail macaroon is. */
export const LIGHTNING = {
  packageId: 'lightning-fork',
  restPort: 8080,
  cert: '/data/lightning/tls.cert',
  macaroon: '/data/run/ln/rail.macaroon',
} as const

/**
 * Lightning Fork's grant (its `grant-app-access` action, from version `minVersion`): this package asks for its
 * key with a task in Lightning Fork (init/tasks.ts); the owner approves by running it there, and Lightning
 * Fork bakes a macaroon with exactly `permissions` under a root key of its own (revocable alone) and keeps it
 * at `apps/<this package's id>/access.macaroon` in its main volume. The package mounts `apps` (not
 * `apps/<id>`: StartOS does not start a package whose mount source does not exist yet), and node-keys watches
 * for the file, copies it into run/ln as the wallet's key, removes it again when the owner revokes it, and
 * never gives it to the gateway (it can pay). No admin macaroon is mounted or read.
 *
 * The permissions are the wallet's, and only those: the signer refuses a key that can do more than pay
 * (lnd's info:read, offchain:read, offchain:write, onchain:read). The selling side needs a key that can
 * only ask for payments (invoices); Lightning Fork grants one key per package, so the owner pastes the
 * shop's keys on the Sell page until it grants a second.
 */
export const LF_GRANT = {
  minVersion: '0.21.4-beta.21.1:2',
  actionId: 'grant-app-access',
  /** Lightning Fork's folder of granted keys, mounted read-only */
  grantsDir: 'apps',
  appDir: 'lightning-stream',
  permissions: ['info:read', 'offchain:read', 'offchain:write', 'onchain:read'],
  /** how often node-keys looks for a grant, or a revocation, in seconds */
  watchS: 10,
} as const

/** The DATUM Gateways the hashtaker sends rented work to, by their StartOS names (the BLAKE2b one first). */
export const DATUM_CANDIDATES = ['datum-blake2b.startos:23336', 'datum.startos:23334']

/** The Nostr relays listings are published on and found at. */
export const RELAYS = ['wss://relay.lazarus-xbt.xyz', 'wss://relay.kilombino.com', 'wss://relay.damus.io', 'wss://nos.lol']

/**
 * The published images, pinned by digest (packaging/images.lock; packaging/pin_images.py writes them);
 * one image set for Umbrel, StartOS, Linux and xbt-compute.
 */
export const IMAGES: Record<ImageKey, string> = {
  init: 'ghcr.io/awokenlazarus/xbt-init:0.1.0-961c085b8dca@sha256:2dc2ee5e38a303c6851a5e13ff73efc3f959968a6e3c8c2b72bad54a9efeea6e',
  signer: 'ghcr.io/awokenlazarus/xbt-signer:0.1.0-961c085b8dca@sha256:091b6612e32a6e9bbbbd7bcc1d66da965ffded2eddbe70a3b8fe580de3b52919',
  witness: 'ghcr.io/awokenlazarus/xbt-anchor-witness:0.1.0-961c085b8dca@sha256:8cb2fe984faf710def2a8d461d1cbdf00638f84c888ee96182ff0434489d2689',
  mcp: 'ghcr.io/awokenlazarus/xbt-wallet-mcp:0.1.0-961c085b8dca@sha256:a8871e35c4c7b17adf61860bb6b8f312364d4aad64c310bceade78e7d0e16010',
  ui: 'ghcr.io/awokenlazarus/xbt-wallet-ui:0.1.0-961c085b8dca@sha256:75212958200e976127e851aa1c9954fc8f8341586cba71df90a1049003034838',
  gateway: 'ghcr.io/awokenlazarus/xbt-gateway:0.1.0-961c085b8dca@sha256:8b930eff4ea28c3b50736bb3fef37afd01f72dc944268a296b8b6ab293939c06',
  connector: 'ghcr.io/awokenlazarus/lightning-stream:0.1.0-961c085b8dca@sha256:13fad6a45bb36e30502f3d39ad16b20fb1ecf8904af0836cc507ffa6214651b8',
  hashlink: 'ghcr.io/awokenlazarus/xbt-hashlink:0.1.0-961c085b8dca@sha256:7c881083f1bd7d84266def147671eaee50698ebbb97a085de1119d398b59324c',
}

const vol = (subpath: string | null, mountpoint: string, readonly = false): MountSpec => ({ subpath, mountpoint, readonly })
const fromLightningFork = (subpath: string, mountpoint: string): MountSpec => ({
  subpath,
  mountpoint,
  readonly: true,
  dependency: { packageId: LIGHTNING.packageId, volumeId: 'main', type: 'directory' },
})
/** Lightning Fork's certificate folder */
const lightningCert = fromLightningFork(LF_CERT_FOLDER, '/data/lightning')
/** The keys Lightning Fork granted (LF_GRANT): its whole `apps` folder, read-only, in node-keys only */
const GRANTS = '/mnt/lightning-fork-apps'
const lightningGrants = fromLightningFork(LF_GRANT.grantsDir, GRANTS)

const local = (port: number) => `127.0.0.1:${port}`

export function services(cfg: Config): ServiceSpec[] {
  const node = {
    XBT_NODE_RPC_HOST: cfg.node.host,
    XBT_NODE_RPC_PORT: String(cfg.node.port),
    XBT_CHAIN: cfg.node.chain,
  }
  const ln = !!cfg.lightningRest
  const cert = ln ? [lightningCert] : []
  const relays = RELAYS.join(',')
  const lan = cfg.lanHost || '127.0.0.1'
  const components = ['signer', 'witness', 'mcp', 'ui', 'gateway', 'hashrate']
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
      // connects the app to the box's Lightning node: it watches Lightning Fork's grant folder and takes the
      // key the owner approves there (and drops it when it is revoked), so the owner pastes nothing. A key
      // the owner pasted is never replaced. Root: Lightning Fork's files are its own user's; this reads
      // them and writes only run/ln
      id: 'node-keys',
      image: 'ui',
      user: 'root',
      command: ['/usr/bin/xbt-wallet-ui', 'node-keys'],
      env: ln
        ? {
            XBT_KEYS_NODE_REST: cfg.lightningRest,
            XBT_KEYS_TLS_CERT: LIGHTNING.cert,
            XBT_KEYS_GRANT_DIR: `${GRANTS}/${LF_GRANT.appDir}`,
            XBT_KEYS_WATCH_S: String(LF_GRANT.watchS),
            XBT_KEYS_RAIL_DIR: '/data/run/ln',
          }
        : {},
      mounts: ln ? [vol('run/ln', '/data/run/ln'), lightningGrants, lightningCert] : [],
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
        ...(ln
          ? { B2_LN_REST: cfg.lightningRest, B2_LN_MACAROON: LIGHTNING.macaroon, B2_MAINNET_ACK_FILE: '/data/run/ln/mainnet-ack', B2_LN_TLS_CERT: LIGHTNING.cert }
          : {}),
        B2_STREAM_DIR: '/data/run/signer/streams',
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
        ...cert,
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
        XBT_UI_RESTART_HINT: 'restart Lightning Stream from your StartOS dashboard (Services, Lightning Stream, Restart)',
        XBT_UI_MCP_URL: cfg.mcpUrls.join(','),
        XBT_UI_CONNECTOR: `http://${local(PORTS.connector)}`,
        // the Lightning page asks the owner to approve the app in Lightning Fork, not to paste a key
        XBT_UI_LN_GRANT: '1',
        ...(ln
          ? {
              XBT_UI_LN_REST: cfg.lightningRest,
              XBT_UI_LN_TLS_CERT: LIGHTNING.cert,
              XBT_UI_GW_NODE_REST: cfg.lightningRest,
              XBT_UI_GW_NODE_TLS_CERT: LIGHTNING.cert,
            }
          : {}),
        // selling: the shop's gateway, on this package's own Gateway interface
        XBT_UI_SELL: '1',
        XBT_UI_GW_PORT: String(PORTS.gateway),
        XBT_UI_GW_HEALTH_URL: `http://${local(PORTS.gateway)}/x402/ticket/health`,
        XBT_UI_GW_PROXIES: cfg.proxies.join(','),
        XBT_UI_SUGGESTED_SELLERS: 'https://stream.lazarus-xbt.xyz',
        XBT_UI_NOSTR_RELAYS: relays,
        // hashrate: the hashmaker's and the hashtaker's control ports (the token is xbt-init's run/hashrate/control-token)
        XBT_UI_HASHER: `http://${local(PORTS.hashmakerControl)}`,
        XBT_UI_HASHER_SETTINGS: '/data/run/hashrate/settings.json',
        XBT_UI_HASHER_SLICES: `http://${local(PORTS.hashmakerSlices)}`,
        XBT_UI_HASHER_TOKEN_FILE: '/data/run/hashrate/control-token',
        XBT_UI_HASHRENT: `http://${local(PORTS.hashtakerControl)}`,
        XBT_UI_HASHRENT_TOKEN_FILE: '/data/run/hashrate/control-token',
        // the signer's one-time enrolment code: the setup page fills it in, so no log has to be read
        XBT_UI_ENROLL_CODE_FILE: '/data/run/enroll/enroll-code',
        // AI: the address programs use (the connector serves it) and the files the AI page shares with it in run/ai
        ...(cfg.aiUrls?.length ? { XBT_UI_AI_ENDPOINT: cfg.aiUrls[0] } : {}),
        XBT_UI_AI_SELLERS: '/data/run/ai/sellers.json',
        XBT_UI_CREDENTIALS: '/data/run/ai/credentials.json',
        XBT_UI_AI_STATE: '/data/run/ai/state.json',
      },
      // the UI owns the MCP token and rotates it on its Agents page; its pages write run/ln, run/gateway and
      // run/hashrate (the shop's and the hashrate settings)
      mounts: [
        vol('ui', '/data/ui'),
        vol('run/signer', '/data/run/signer', true),
        vol('run/ui', '/data/run/ui'),
        vol('run/ln', '/data/run/ln'),
        vol('run/gateway', '/data/run/gateway'),
        vol('run/hashrate', '/data/run/hashrate'),
        vol('run/ai', '/data/run/ai'),
        vol('run/enroll', '/data/run/enroll', true),
        ...cert,
      ],
      requires: ['signer'],
      port: PORTS.ui,
    },
    {
      // plays what the owner buys in the web UI: pays through the signer, on loopback only
      id: 'connector',
      image: 'connector',
      command: ['/usr/bin/lightning-stream'],
      env: {
        B2_SIGNER_SOCK: '/data/run/signer/signer.sock',
        B2_STREAM_DIR: '/data/run/signer/streams',
        LS_TASK: 'default',
        LS_MAX_SATS: '20000',
        LS_LISTEN: local(PORTS.connector),
        // the AI endpoint for programs on the LAN, each with a key from the AI page (run/ai, shared by group with the UI)
        LS_AI_LISTEN: `0.0.0.0:${PORTS.ai}`,
        LS_CREDENTIALS: '/data/run/ai/credentials.json',
        LS_AI_SELLERS: '/data/run/ai/sellers.json',
        LS_AI_STATE: '/data/run/ai/state.json',
      },
      mounts: [vol('run/signer', '/data/run/signer', true), vol('run/signer/streams', '/data/run/signer/streams'), vol('run/ai', '/data/run/ai')],
      requires: ['signer'],
      port: PORTS.connector,
    },
    {
      id: 'gateway',
      image: 'gateway',
      // xbt-supervise starts the gateway once the Sell page has written its config, and again when the
      // config, a macaroon or the certificate changes
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
      // rents the owner's miners out (Sell → Hashrate): miners connect on the LAN, hashtakers on the link
      id: 'hashmaker',
      image: 'hashlink',
      command: [
        '/usr/bin/xbt-hashlink',
        'hashmaker',
        '--key',
        '/data/hashrate/link.key',
        '--nostr-key',
        '/data/hashrate/nostr.key',
        '--miners',
        `0.0.0.0:${PORTS.miners}`,
        '--link',
        `0.0.0.0:${PORTS.link}`,
        '--slices',
        local(PORTS.hashmakerSlices),
        '--control',
        local(PORTS.hashmakerControl),
        '--control-token-file',
        '/data/run/hashrate/control-token',
        '--config',
        '/data/run/hashrate/settings.json',
        '--relays',
        relays,
        '--gateway',
        `http://${local(PORTS.gateway)}`,
        '--miners-public',
        `${lan}:${PORTS.miners}`,
        '--link-lan',
        `${lan}:${PORTS.link}`,
        '--report',
        '/data/hashrate/hasher.json',
      ],
      env: {},
      mounts: [vol('hashrate', '/data/hashrate'), vol('run/hashrate', '/data/run/hashrate', true)],
      requires: ['init'],
      readyCommand: ['/usr/bin/xbt-hashlink', 'healthcheck', local(PORTS.hashmakerControl)],
    },
    {
      // rents others' miners into the owner's own DATUM Gateway (Services → Hashrate), paying each piece of
      // work through the signer as the "hashrate" task of the spending rules
      id: 'hashtaker',
      image: 'hashlink',
      command: [
        '/usr/bin/xbt-hashlink',
        'hashtaker',
        '--key',
        '/data/hashrate/renter.key',
        '--control',
        local(PORTS.hashtakerControl),
        '--control-token-file',
        '/data/run/hashrate/control-token',
        '--state',
        '/data/hashrate',
        '--upstream',
        'auto',
        '--datum-candidates',
        DATUM_CANDIDATES.join(','),
        '--user',
        'rented',
        '--relays',
        relays,
        '--signer',
        '/data/run/signer/signer.sock',
        '--task',
        'hashrate',
      ],
      env: {},
      mounts: [vol('hashrate', '/data/hashrate'), vol('run/hashrate', '/data/run/hashrate', true), vol('run/signer', '/data/run/signer', true)],
      requires: ['signer'],
    },
  ]
}
