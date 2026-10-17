import { i18n } from './i18n'
import { sdk } from './sdk'
import { LIGHTNING, PORTS, services, ServiceSpec } from './spec'

export const main = sdk.setupMain(async ({ effects }) => {
  // Lightning Fork's own REST listener at its container address, which its certificate names
  // (lightning-fork-startos init/setupCerts.ts); the OS proxy's address would present another certificate
  const lfIp = await sdk.getContainerIp(effects, { packageId: LIGHTNING.packageId }).const().catch(() => null)
  const lightningRest = lfIp ? `https://${lfIp}:${LIGHTNING.restPort}` : ''
  // StartOS's proxy reaches this package from the OS's address on the bridge: its X-Forwarded-For is the buyer's
  const osIp = await sdk.getOsIp(effects).catch(() => '')

  const specs = services({ lightningRest, proxies: osIp ? [osIp] : [] })
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
  const [init, gateway, ui] = (['init', 'gateway', 'ui'] as const).map(spec)

  return sdk.Daemons.of(effects)
    .addOneshot('init', { subcontainer: sub(init), exec: exec(init), requires: [] })
    .addDaemon('ui', {
      subcontainer: sub(ui),
      exec: exec(ui),
      ready: {
        display: i18n('Setup page'),
        fn: () =>
          sdk.healthCheck.checkPortListening(effects, PORTS.ui, {
            successMessage: i18n('Listening'),
            errorMessage: i18n('Not listening yet'),
          }),
        gracePeriod: 30_000,
      },
      requires: ['init'],
    })
    // the gateway waits for the config the setup page writes: until then it is "loading", with the reason
    .addDaemon('gateway', {
      subcontainer: sub(gateway),
      exec: exec(gateway),
      ready: {
        display: i18n('Gateway for buyers'),
        fn: async () => {
          try {
            const r = await fetch(`http://127.0.0.1:${PORTS.gateway}/x402/ticket/health`)
            if (r.status === 200) return { result: 'success', message: i18n('Taking stream tickets') }
            return { result: 'loading', message: i18n('The gateway answers but is not ready: see the setup page') }
          } catch {
            return { result: 'loading', message: i18n('Waiting for the setup page: set the service, the price and the macaroons') }
          }
        },
        gracePeriod: 30_000,
      },
      requires: ['init'],
    })
})
