/**
 * The package's containers as plain data: which image, which user, which parts of the `main`
 * volume each one mounts, its environment and what it waits for. `main.ts` turns this into daemons, and
 * packaging/startos/test runs exactly these on Docker (the StartOS-shaped regtest run), so the test and the
 * package cannot drift. No SDK import here: `node --experimental-strip-types` loads it on its own.
 *
 * One package for the whole app, as the Umbrel app is: the wallet (signer, anchor witness, MCP server, web
 * UI, the connector that plays what is bought), the shop (the gateway) and hashrate (the hashmaker, which
 * rents this owner's miners out, the hashtaker, which rents others' into a DATUM-protocol gateway, and that
 * gateway, `datum`, which masks every job so a hashmaker can't tell which shares win).
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
  /** the VPN service's WireGuard endpoint (UDP) inside the package */
  vpn: 51820,
  /** where devices reach it on the LAN (51820 is left to WireGuard packages) */
  vpnExternal: 51830,
  // the exit's tunnel endpoint: the gateway beside it joins buyers' paid tunnels here (never published)
  vpnTunnel: 51880,
  /** the masking gateway's Stratum, for the hashtaker only (127.0.0.1: never an interface) */
  datumStratum: 23339,
  /** the masking gateway's API: /xbt/job opens each job for the hashtaker's check (127.0.0.1 only) */
  datumApi: 7152,
} as const

export type ImageKey = 'init' | 'signer' | 'witness' | 'mcp' | 'ui' | 'gateway' | 'connector' | 'hashlink' | 'vpn' | 'datum'
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
  | 'vpn'
  | 'datum'

/** A part of the `main` volume, or (with `dependency`) a folder of another package's volume, read-only. */
export type MountSpec = {
  subpath: string | null
  mountpoint: string
  readonly: boolean
  dependency?: { packageId: string; volumeId: string; type: 'file' | 'directory' }
  /** ids on the volume shown as other ids in the mount (the SDK's idmap), for another package's files */
  idmap?: { fromId: number; toId: number; range?: number }[]
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
  /** the Files service shares a folder of File Browser's files (read-only) instead of the package's own */
  filesFromFileBrowser?: boolean
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

/**
 * File Browser's files, which the Files service can share instead of the package's own folder: its `data`
 * volume (what File Browser shows, at /srv in its own container), mounted read-only into the UI, as
 * Jellyfin's StartOS package mounts it for media. An optional dependency, needed only once the owner
 * chooses it in the "Files folder" action.
 */
export const FILE_BROWSER = {
  packageId: 'filebrowser',
  volumeId: 'data',
  // what File Browser serves (its /srv); the rest of the volume is its config and database
  subpath: 'data',
  // File Browser writes its files as its own user (1000) with 0640/0750. The UI reads them through its
  // group, 1000 (xbt-shared-files in the images' base layer); the mount's idmap below asks StartOS to show
  // them as the UI's (10005) as well, which StartOS 0.4.0.1 does not apply yet
  ownerId: 1000,
  uiId: 10005,
  minVersion: '2.63.18:0',
  mountpoint: '/mnt/filebrowser',
  words: 'File Browser',
} as const

/**
 * The masking gateway (the `datum` daemon, "Stream Gateway (DATUM-compatible)" to the owner): a DATUM-protocol gateway that gives every job a key of its own and
 * opens each job, without the key, on /xbt/job, so the hashtaker checks a job is masked before a miner gets it.
 * It reads the node through `rpc.cookie` (the Node connection action's user and password: xbt-init's `datum`
 * component writes it, 0600, owned by xbt-datum 10021) and the config the Hashrate page's "Your gateway" writes
 * (mode, payout address, the node's RPC URL; 0640, group xbt-datum; no secret). Its API has no admin password.
 * Contract: run-handoff/mg-contract.md (W5).
 * Both listen on 127.0.0.1 only, in this package's own network namespace: only its own services reach them.
 */
export const DATUM = {
  config: '/data/run/datum/config.json',
  cookie: '/data/run/datum/rpc.cookie',
  stratum: `127.0.0.1:${PORTS.datumStratum}`,
  api: `127.0.0.1:${PORTS.datumApi}`,
} as const

/**
 * The DATUM gateways the hashtaker sends rented work to: the masking gateway in this package first, then other
 * StartOS DATUM packages by their names (the BLAKE2b one first). Their jobs are checked on the masking gateway's
 * /xbt/job, so only the bundled gateway's pass: a rental never runs on jobs that aren't masked.
 */
export const DATUM_CANDIDATES = [DATUM.stratum, 'datum-blake2b.startos:23336', 'datum.startos:23334']

/** The Nostr relays listings are published on and found at. */
export const RELAYS = ['wss://relay.lazarus-xbt.xyz', 'wss://relay.kilombino.com', 'wss://relay.damus.io', 'wss://nos.lol']

/**
 * The published images, pinned by digest (packaging/images.lock; packaging/pin_images.py writes them);
 * one image set for Umbrel, StartOS, Linux and xbt-compute.
 */
export const IMAGES: Record<ImageKey, string> = {
  init: 'ghcr.io/awokenlazarus/xbt-init:0.1.0-c391c40e6f75@sha256:203d14283ab76388c6dd70a28d7f3957f4b61a5b60f5f8c4b71d35b13e0ee853',
  signer: 'ghcr.io/awokenlazarus/xbt-signer:0.1.0-c391c40e6f75@sha256:2dc891171b3770ff2e554420058397bb5320a635a10d65cc39f26b6451e0153e',
  witness: 'ghcr.io/awokenlazarus/xbt-anchor-witness:0.1.0-c391c40e6f75@sha256:db6360d5fc2840ea0eb4b4725909d9e433e265919b12605697fe23616bcf2b8c',
  mcp: 'ghcr.io/awokenlazarus/xbt-wallet-mcp:0.1.0-c391c40e6f75@sha256:05ddc504cfb4eaf73791a41ce8d02170612458c526f04833394acf7731c88fa6',
  ui: 'ghcr.io/awokenlazarus/xbt-wallet-ui:0.1.0-c391c40e6f75@sha256:097368ea5e8449f7428666cc429db38dd42bc07468e291623334d1b31a9ac1f9',
  gateway: 'ghcr.io/awokenlazarus/xbt-gateway:0.1.0-c391c40e6f75@sha256:c550289815044df818162430780499687d5174462a2c2f06f33ced6756632f11',
  connector: 'ghcr.io/awokenlazarus/lightning-stream:0.1.0-c391c40e6f75@sha256:ffabb25fc87a5ce8241f7f77eebf8c8016c032fe8b3f72adb9a86d7ac8834410',
  hashlink: 'ghcr.io/awokenlazarus/xbt-hashlink:0.1.0-c391c40e6f75@sha256:1711d25bb0cef41a682d468429f203a7eb1e7eaf1b5c46aa5c1522b671930ecd',
  // not published yet (no line in images.lock): oci_build.sh --load tags it
  vpn: 'ghcr.io/awokenlazarus/xbt-vpn:0.1.0-c391c40e6f75@sha256:994751817e8ef70bfb97804d4bdbdb1edf8b041dff418be7aa43a2bc644853b5',
  // not published yet (no line in images.lock): oci_build.sh --load tags it
  datum: 'ghcr.io/awokenlazarus/xbt-datum-gateway:0.1.0-c391c40e6f75@sha256:eb44953f97cf1a982a0e11942e5d13076fd6de03c68a3feec496c5ce8a6df8f4',
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
  const fb = !!cfg.filesFromFileBrowser
  const fileBrowser: MountSpec = {
    subpath: FILE_BROWSER.subpath,
    mountpoint: FILE_BROWSER.mountpoint,
    readonly: true,
    dependency: { packageId: FILE_BROWSER.packageId, volumeId: FILE_BROWSER.volumeId, type: 'directory' },
    idmap: [{ fromId: FILE_BROWSER.ownerId, toId: FILE_BROWSER.uiId }],
  }
  const relays = RELAYS.join(',')
  const lan = cfg.lanHost || '127.0.0.1'
  // datum: its folders, and run/datum/rpc.cookie from XBT_INIT_NODE_RPC_AUTH (the gateway's own, 0600)
  const components = ['signer', 'witness', 'mcp', 'ui', 'gateway', 'hashrate', 'vpn', 'datum']
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
        // shops reached by key: read for callers that pass no transport document (the AI address, agents)
        XBT_SHOPS_FILE: '/data/run/shops/shops.json',
      },
      // run/ln: the rail macaroon (group xbt-ln-rail: the UI writes it, the signer reads it, the MCP cannot)
      mounts: [
        vol('signer', '/data/signer'),
        vol('run/signer', '/data/run/signer'),
        // the hashrate renter's own socket: the one way to the "hashrate" task's rental terms
        vol('run/rental', '/data/run/rental'),
        vol('run/anchor', '/data/run/anchor', true),
        vol('run/ln', '/data/run/ln', true),
        vol('run/enroll', '/data/run/enroll'),
        vol('run/shops', '/data/run/shops', true),
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
      env: { XBT_MCP_HTTP: `0.0.0.0:${PORTS.mcp}`, XBT_MCP_APPROVAL_WAIT_S: '300', XBT_MCP_LN: '1', XBT_MCP_TICKETS: '1', XBT_SHOPS_FILE: '/data/run/shops/shops.json' },
      // the bearer token is the UI's run/ui/mcp-http-token (0640, group xbt-wallet-ui): read-only here
      mounts: [vol('mcp', '/data/mcp'), vol('run/signer', '/data/run/signer', true), vol('run/ui', '/data/run/ui', true), vol('run/shops', '/data/run/shops', true)],
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
        XBT_UI_SUGGESTED_SELLERS: 'npub1kqdrfmfg6mg52sy3ehu4vv7m3fjpa0830rhjdmvqrf09u3t3724q8cwr6a',
        // the built-in Stream relay needs the server's public port 443, which StartOS keeps for itself
        XBT_UI_RELAY_UNAVAILABLE:
          "StartOS keeps the server's port 443 for itself, and a relay needs it. Run one with the Linux package on a server with a public address (see the setup guide).",
        XBT_UI_NOSTR_RELAYS: relays,
        // hashrate: the hashmaker's and the hashtaker's control ports (the token is xbt-init's run/hashrate/control-token)
        XBT_UI_HASHER: `http://${local(PORTS.hashmakerControl)}`,
        XBT_UI_HASHER_SETTINGS: '/data/run/hashrate/settings.json',
        XBT_UI_HASHER_SLICES: `http://${local(PORTS.hashmakerSlices)}`,
        XBT_UI_HASHER_TOKEN_FILE: '/data/run/hashrate/control-token',
        XBT_UI_HASHRENT: `http://${local(PORTS.hashtakerControl)}`,
        XBT_UI_HASHRENT_TOKEN_FILE: '/data/run/hashrate/control-token',
        // the masking gateway: Services → Hashrate writes its config (no secret) into run/datum; the node it
        // reads is the Node connection action's, its credentials in init's rpc.cookie
        XBT_UI_DATUM_DIR: '/data/run/datum',
        XBT_UI_DATUM_RPCURL: `http://${cfg.node.host}:${cfg.node.port}`,
        XBT_UI_DATUM_API_PORT: String(PORTS.datumApi),
        // the signer's one-time enrolment code: the setup page fills it in, so no log has to be read
        XBT_UI_ENROLL_CODE_FILE: '/data/run/enroll/enroll-code',
        // the shops without a web address the owner adds; the connector and the MCP read it
        XBT_SHOPS_FILE: '/data/run/shops/shops.json',
        // AI: the address programs use (the connector serves it) and the files the AI page shares with it in run/ai
        ...(cfg.aiUrls?.length ? { XBT_UI_AI_ENDPOINT: cfg.aiUrls[0] } : {}),
        XBT_UI_AI_SELLERS: '/data/run/ai/sellers.json',
        XBT_UI_CREDENTIALS: '/data/run/ai/credentials.json',
        XBT_UI_AI_STATE: '/data/run/ai/state.json',
        // Files: with File Browser chosen, the owner picks a folder of its files on the Sell page (read-only);
        // otherwise the folder is the UI's own (<data dir>/files), reached with StartOS's file tools
        ...(fb ? { XBT_UI_FILES_ROOT: FILE_BROWSER.mountpoint, XBT_UI_FILES_ROOT_WORDS: FILE_BROWSER.words } : {}),
        // the VPN pages: the devices and exit they write for the vpn service, its status they read, and
        // where devices reach its WireGuard endpoint on the LAN
        XBT_UI_VPN_DIR: '/data/run/vpn',
        XBT_UI_VPN_STATUS_DIR: '/data/run/vpn-status',
        ...(cfg.lanHost ? { XBT_UI_VPN_ENDPOINT: `${cfg.lanHost}:${PORTS.vpnExternal}` } : {}),
        // where the shop's gateway reaches the VPN service's tunnel endpoint, to sell this box's exit
        XBT_UI_VPN_TUNNEL_UPSTREAM: `http://${local(PORTS.vpnTunnel)}`,
      },
      // the UI owns the MCP token and rotates it on its Agents page; its pages write run/ln, run/gateway,
      // run/hashrate and run/datum (the shop's, the hashrate and the masking gateway's settings)
      mounts: [
        vol('ui', '/data/ui'),
        vol('run/signer', '/data/run/signer', true),
        vol('run/ui', '/data/run/ui'),
        vol('run/ln', '/data/run/ln'),
        vol('run/gateway', '/data/run/gateway'),
        vol('run/hashrate', '/data/run/hashrate'),
        vol('run/datum', '/data/run/datum'),
        vol('run/shops', '/data/run/shops'),
        vol('run/ai', '/data/run/ai'),
        vol('run/vpn', '/data/run/vpn'),
        vol('run/vpn-status', '/data/run/vpn-status', true),
        vol('run/enroll', '/data/run/enroll', true),
        ...cert,
        ...(fb ? [fileBrowser] : []),
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
        XBT_SHOPS_FILE: '/data/run/shops/shops.json',
        // the AI endpoint for programs on the LAN, each with a key from the AI page (run/ai, shared by group with the UI)
        LS_AI_LISTEN: `0.0.0.0:${PORTS.ai}`,
        LS_CREDENTIALS: '/data/run/ai/credentials.json',
        LS_AI_SELLERS: '/data/run/ai/sellers.json',
        LS_AI_STATE: '/data/run/ai/state.json',
      },
      mounts: [vol('run/signer', '/data/run/signer', true), vol('run/signer/streams', '/data/run/signer/streams'), vol('run/shops', '/data/run/shops', true), vol('run/ai', '/data/run/ai')],
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
      // rents others' miners into the masking gateway (Services → Hashrate), paying each piece of work through
      // the signer as the "hashrate" task of the spending rules, on its own socket (run/rental), which no other
      // service reaches and which the task's rental terms need. Every job is held to what the masking
      // gateway's /xbt/job opens before a miner gets it; one that isn't masked ends the rental (never
      // --allow-unblinded)
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
        '--gateway-api',
        DATUM.api,
        '--user',
        'rented',
        '--relays',
        relays,
        '--signer',
        '/data/run/rental/signer.sock',
        '--task',
        'hashrate',
      ],
      env: {},
      mounts: [vol('hashrate', '/data/hashrate'), vol('run/hashrate', '/data/run/hashrate', true), vol('run/rental', '/data/run/rental', true)],
      // not after the gateway: the renter takes 127.0.0.1:23339 as the bundled gateway whether it answers yet or
      // not, and its page says in words what the gateway is doing (not running, waiting for the node, masking),
      // so a node that can't be reached never leaves the renter's page dead
      requires: ['signer'],
    },
    {
      // the VPN service: the WireGuard endpoint the owner's devices pair with, and this box's exit if the
      // owner offers one. Userspace WireGuard and TCP/IP: no TUN device, no capabilities. It exits when the
      // devices or the exit change, and StartOS starts it again with them
      id: 'vpn',
      image: 'vpn',
      command: ['/usr/bin/xbt-vpn', 'serve'],
      env: {
        XBT_VPN_DIR: '/data/run/vpn',
        XBT_VPN_STATUS: '/data/run/vpn-status',
        XBT_VPN_KEYS: '/data/vpn',
        XBT_VPN_WG_LISTEN: `0.0.0.0:${PORTS.vpn}`,
        XBT_VPN_NOSTR_RELAYS: relays,
        // priced exits are paid through the owner's wallet; this box's exit's tunnel endpoint, for the gateway beside it
        B2_SIGNER_SOCK: '/data/run/signer/signer.sock',
        B2_STREAM_DIR: '/data/run/signer/streams',
        XBT_SHOPS_FILE: '/data/run/shops/shops.json',
        XBT_VPN_TUNNEL_LISTEN: local(PORTS.vpnTunnel),
      },
      mounts: [vol('vpn', '/data/vpn'), vol('run/vpn', '/data/run/vpn', true), vol('run/vpn-status', '/data/run/vpn-status'),
               vol('run/signer', '/data/run/signer', true), vol('run/signer/streams', '/data/run/signer/streams'), vol('run/shops', '/data/run/shops', true)],
      requires: ['init'],
    },
    {
      // the masking gateway: started once Services → Hashrate has written its config, and again when the config
      // or the node's credentials change. Its submitted blocks are kept in datum/submitblocks (a found block
      // survives a failed submitblock). Its Stratum and API are on 127.0.0.1 only (the config says so), so
      // only this package's services reach them; /xbt/job answers loopback only (api.xbt_job_allow empty)
      id: 'datum',
      image: 'datum',
      command: ['/usr/bin/xbt-supervise', '--wait', DATUM.config, '--watch', DATUM.cookie, '--', '/usr/bin/xbt-datum-gateway', '-c', DATUM.config],
      env: {},
      mounts: [vol('datum', '/data/datum'), vol('run/datum', '/data/run/datum', true)],
      requires: ['init'],
      port: PORTS.datumApi,
      // its API answers, or it is idle by design: no config yet
      readyCommand: ['/usr/bin/xbt-supervise', 'probe', `http://${DATUM.api}/`, '--waiting-for', DATUM.config],
    },
  ]
}
