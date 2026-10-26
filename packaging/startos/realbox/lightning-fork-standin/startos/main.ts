import { sdk } from './sdk'

const RPC = ['--bitcoind.rpchost=127.0.0.1:18443', '--bitcoind.rpcuser=lab', '--bitcoind.rpcpass=lab',
  '--bitcoind.zmqpubrawblock=tcp://127.0.0.1:28332', '--bitcoind.zmqpubrawtx=tcp://127.0.0.1:28333']
const lnd = (alias: string, grpc: number, rest: number, p2p: number): [string, ...string[]] => ['/usr/local/bin/lnd', '--lnddir=/data', '--noseedbackup',
  '--bitcoin.regtest', '--bitcoin.node=bitcoind', '--bitcoin.blake2b-activation-height=20', ...RPC,
  `--rpclisten=0.0.0.0:${grpc}`, `--restlisten=0.0.0.0:${rest}`, `--listen=0.0.0.0:${p2p}`, `--alias=${alias}`,
  '--protocol.simple-taproot-chans', '--accept-keysend', '--tlsautorefresh']

export const main = sdk.setupMain(async ({ effects }) => {
  const vol = (subpath: string | null) => sdk.Mounts.of().mountVolume({ volumeId: 'main', subpath, mountpoint: '/data', readonly: false })
  const port = (p: number, what: string) => () =>
    sdk.healthCheck.checkPortListening(effects, p, { successMessage: `${what} listening`, errorMessage: `${what} not listening yet` })
  return sdk.Daemons.of(effects)
    .addDaemon('knots', {
      subcontainer: sdk.SubContainer.of(effects, { imageId: 'knots' }, vol('knots'), 'knots-sub'),
      exec: {
        command: ['/usr/local/bin/entrypoint.sh', '-zmqpubrawblock=tcp://127.0.0.1:28332', '-zmqpubrawtx=tcp://127.0.0.1:28333', '-txindex=1'],
        env: { CHAIN: 'regtest', RPC_USER: 'lab', RPC_PASSWORD: 'lab', BLAKE2B_HEADLINE: 'Lightning Fork lab', BLAKE2B_ACTIVATION_HEIGHT: '20', RPC_ALLOW_IP: '0.0.0.0/0' },
        user: 'root',
      },
      ready: { display: 'Chain node (regtest)', fn: port(18443, 'RPC'), gracePeriod: 60_000 },
      requires: [],
    })
    // the node dependents use: REST 8080, tls.cert at the volume's root
    .addDaemon('lf1', {
      subcontainer: sdk.SubContainer.of(effects, { imageId: 'lnd' }, vol(null), 'lf1-sub'),
      exec: { command: lnd('standin-lf1', 10009, 8080, 9735), user: 'root' },
      ready: { display: 'Lightning node (box)', fn: port(8080, 'REST'), gracePeriod: 120_000 },
      requires: ['knots'],
    })
    // a copy of tls.cert alone in public/, as the real package keeps it for packages that depend on it
    .addOneshot('public-tls-cert', {
      subcontainer: sdk.SubContainer.of(effects, { imageId: 'lnd' }, vol(null), 'cert-sub'),
      exec: { command: ['sh', '-c', 'mkdir -p /data/public && cp /data/tls.cert /data/public/tls.cert.tmp && mv /data/public/tls.cert.tmp /data/public/tls.cert'], user: 'root' },
      requires: ['lf1'],
    })
    // the far end of the channel
    .addDaemon('lf2', {
      subcontainer: sdk.SubContainer.of(effects, { imageId: 'lnd' }, vol('lf2'), 'lf2-sub'),
      exec: { command: lnd('standin-lf2', 10011, 8081, 9736), user: 'root' },
      ready: { display: 'Lightning node (peer)', fn: port(8081, 'REST'), gracePeriod: 120_000 },
      requires: ['knots'],
    })
})
