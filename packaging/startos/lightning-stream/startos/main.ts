import { i18n } from './i18n'
import { sdk } from './sdk'
import { storeJson } from './fileModels/store.json'
import { LIGHTNING, PORTS, services, ServiceSpec } from './spec'

export const main = sdk.setupMain(async ({ effects }) => {
  const store = await storeJson.read().const(effects)
  if (!store) throw new Error('store.json is missing')

  // an interface's addresses on the LAN (main re-runs when they change)
  const addresses = async (hostId: string, ifaceId: string) => {
    const host = await sdk.host.getOwn(effects, hostId).const()
    const iface = Object.values(host?.bindings ?? {})
      .flatMap((b) => Object.values(b.interfaces))
      .find((i) => i.id === ifaceId)
    return iface?.addressInfo?.nonLocal.format('urlstring') ?? []
  }
  // the MCP interface's addresses, for the UI's Agents page
  const mcpUrls = (await addresses('mcp', 'mcp')).map((u) => u.replace(/\/$/, '') + '/mcp')
  // the AI interface's addresses, for the UI's AI page (http first: programs on the LAN rarely trust the OS's certificate)
  const aiUrls = (await addresses('ai', 'ai')).map((u) => u.replace(/\/$/, '') + '/v1').sort((x, y) => Number(y.startsWith('http:')) - Number(x.startsWith('http:')))
  // this server's IPv4 address on the LAN, for the miners' and the link's addresses the hashrate pages show
  const lanHost =
    (await addresses('ui', 'ui'))
      .map((u) => {
        try {
          return new URL(u).hostname
        } catch {
          return ''
        }
      })
      .find((h) => /^\d+\.\d+\.\d+\.\d+$/.test(h)) ?? ''

  // Lightning Fork's own REST listener at its container address, which its certificate names
  // (lightning-fork-startos init/setupCerts.ts); the OS proxy's address would present another certificate
  const lfIp = await sdk.getContainerIp(effects, { packageId: LIGHTNING.packageId }).const().catch(() => null)
  const lightningRest = lfIp ? `https://${lfIp}:${LIGHTNING.restPort}` : ''
  // StartOS's proxy reaches this package from the OS's address on the bridge: its X-Forwarded-For is the buyer's
  const osIp = await sdk.getOsIp(effects).catch(() => '')

  const specs = services({ node: store.node, mcpUrls, lightningRest, proxies: osIp ? [osIp] : [], lanHost, aiUrls })
  const spec = (id: ServiceSpec['id']) => specs.find((s) => s.id === id) as ServiceSpec

  const sub = (s: ServiceSpec) => {
    let mounts = sdk.Mounts.of()
    for (const m of s.mounts) {
      mounts = m.dependency
        ? mounts.mountDependency({
            dependencyId: m.dependency.packageId,
            volumeId: m.dependency.volumeId,
            subpath: m.subpath,
            mountpoint: m.mountpoint,
            readonly: true,
            type: m.dependency.type,
          })
        : mounts.mountVolume({ volumeId: 'main', subpath: m.subpath, mountpoint: m.mountpoint, readonly: m.readonly })
    }
    return sdk.SubContainer.of(effects, { imageId: s.image }, mounts, `${s.id}-sub`)
  }
  const exec = (s: ServiceSpec) => ({ command: s.command, env: s.env, ...(s.user ? { user: s.user } : {}) })
  const portReady = (s: ServiceSpec, display: string | null) => ({
    display,
    fn: () =>
      sdk.healthCheck.checkPortListening(effects, s.port as number, {
        successMessage: i18n('Listening'),
        errorMessage: i18n('Not listening yet'),
      }),
    gracePeriod: 30_000,
  })
  const scriptReady = (s: ServiceSpec, subc: ReturnType<typeof sub>, gracePeriod: number) => ({
    display: null,
    fn: () => sdk.healthCheck.runHealthScript(s.readyCommand as [string, ...string[]], subc, { errorMessage: i18n('Not ready yet') }),
    gracePeriod,
  })

  const [init, witness, signer, mcp, ui, connector, gateway, hashmaker, hashtaker] = (
    ['init', 'witness', 'signer', 'mcp', 'ui', 'connector', 'gateway', 'hashmaker', 'hashtaker'] as const
  ).map(spec)
  const witnessSub = sub(witness)
  const signerSub = sub(signer)
  const hashmakerSub = sub(hashmaker)

  // init first (xbt-init: owners and modes on the root-owned volume, the node credentials, the MCP token,
  // the hashrate control token), then the witness, the signer, and the services on the signer's socket
  return (
    sdk.Daemons.of(effects)
      .addOneshot('init', { subcontainer: sub(init), exec: exec(init), requires: [] })
      // the wallet's key, granted by Lightning Fork: node-keys watches for it (nothing waits for it: the
      // signer picks the file up when it appears). With no Lightning Fork it has nothing to watch and exits
      .addDaemon('node-keys', {
        subcontainer: sub(spec('node-keys')),
        exec: exec(spec('node-keys')),
        ready: { display: null, fn: () => ({ result: 'success', message: null }) },
        requires: ['init'],
      })
      .addDaemon('witness', {
        subcontainer: witnessSub,
        exec: exec(witness),
        ready: scriptReady(witness, witnessSub, 30_000),
        requires: ['init'],
      })
      .addDaemon('signer', {
        subcontainer: signerSub,
        exec: exec(signer),
        ready: scriptReady(signer, signerSub, 60_000),
        requires: ['witness'],
      })
      .addDaemon('mcp', { subcontainer: sub(mcp), exec: exec(mcp), ready: portReady(mcp, i18n('MCP server for agents')), requires: ['signer'] })
      .addDaemon('ui', { subcontainer: sub(ui), exec: exec(ui), ready: portReady(ui, i18n('Web interface')), requires: ['signer'] })
      .addDaemon('connector', { subcontainer: sub(connector), exec: exec(connector), ready: portReady(connector, null), requires: ['signer'] })
      // the gateway waits for the config the Sell page writes: until then it is idle, which is healthy
      .addDaemon('gateway', {
        subcontainer: sub(gateway),
        exec: exec(gateway),
        ready: {
          display: i18n('Shop'),
          fn: async () => {
            try {
              const r = await fetch(`http://127.0.0.1:${PORTS.gateway}/x402/ticket/health`)
              if (r.status === 200) return { result: 'success', message: i18n('Selling') }
              return { result: 'success', message: i18n('Not selling yet: add a service on the Sell page') }
            } catch {
              return { result: 'success', message: i18n('Not selling yet: add a service on the Sell page') }
            }
          },
          gracePeriod: 30_000,
        },
        requires: ['init'],
      })
      .addDaemon('hashmaker', {
        subcontainer: hashmakerSub,
        exec: exec(hashmaker),
        ready: scriptReady(hashmaker, hashmakerSub, 30_000),
        requires: ['init'],
      })
      .addDaemon('hashtaker', { subcontainer: sub(hashtaker), exec: exec(hashtaker), ready: { display: null, fn: () => ({ result: 'success', message: null }) }, requires: ['signer'] })
      // Readiness as the wallet sees it: the MCP's /readyz (the signer is up, the node is reachable and synced,
      // the keys are unlocked, the witness answers). A 503 while the node syncs is "loading", with the reason.
      .addHealthCheck('wallet-ready', {
        ready: {
          display: i18n('Wallet ready to pay'),
          fn: async () => {
            try {
              const r = await fetch(`http://127.0.0.1:${PORTS.mcp}/readyz`)
              if (r.status === 200) return { result: 'success', message: i18n('Ready: the node is synced and the keys are unlocked') }
              const body = (await r.json().catch(() => ({}))) as {
                signer_ready?: { node?: { reachable?: boolean; synced?: boolean }; witness?: { reachable?: boolean } }
              }
              const sr = body.signer_ready ?? {}
              const why = !sr.node?.reachable
                ? i18n('The XBT node is not reachable: check the Node connection action')
                : !sr.node?.synced
                  ? i18n('The XBT node is syncing')
                  : sr.witness?.reachable === false
                    ? i18n('The anchor witness is not answering')
                    : i18n('The signer is starting')
              return { result: 'loading', message: why }
            } catch {
              return { result: 'starting', message: i18n('The MCP server is starting') }
            }
          },
        },
        requires: ['mcp'],
      })
  )
})
