import { i18n } from '../i18n'
import { sdk } from '../sdk'
import { storeJson } from '../fileModels/store.json'

const { InputSpec, Value } = sdk

/**
 * Knots BLAKE2b on StartOS (package `knots-blake2b`): the XBT node, reached from this package by its name on
 * the server, its RPC on port 18443. The form offers these while no node is set and Knots BLAKE2b is
 * installed. Its RPC user and password come from its own "Generate RPC User Credentials" action.
 */
export const KNOTS = { packageId: 'knots-blake2b', host: 'knots-blake2b.startos', rpcPort: 18443 } as const

const inputSpec = InputSpec.of({
  host: Value.text({
    name: i18n('Node host'),
    description: i18n(
      'The XBT (BLAKE2b) node RPC host: an IP or a name this server can reach. Knots BLAKE2b on this server: knots-blake2b.startos',
    ),
    required: true,
    default: null,
    placeholder: KNOTS.host,
  }),
  port: Value.number({
    name: i18n('RPC port'),
    description: i18n('The node RPC port. Knots BLAKE2b on this server: 18443'),
    required: true,
    default: KNOTS.rpcPort,
    min: 1,
    max: 65535,
    step: 1,
    integer: true,
    units: null,
    placeholder: null,
  }),
  user: Value.text({
    name: i18n('RPC user'),
    description: i18n(
      'The user of the node RPC credentials. Knots BLAKE2b: run its "Generate RPC User Credentials" action first, and copy the user and password it shows',
    ),
    required: true,
    default: null,
  }),
  password: Value.text({
    name: i18n('RPC password'),
    description: i18n('The password of the node RPC credentials (from Knots BLAKE2b\'s "Generate RPC User Credentials" action)'),
    required: true,
    default: null,
    masked: true,
  }),
  chain: Value.select({
    name: i18n('Chain'),
    description: i18n('The chain the node runs; the signer refuses to start on a different one'),
    default: 'main',
    values: { main: 'XBT main', test: 'test', regtest: 'regtest' },
  }),
})

export const nodeConfig = sdk.Action.withInput(
  'node-config',
  {
    name: i18n('Node connection'),
    description: i18n('The XBT node the signer and the Stream Gateway use: host, RPC port, credentials and chain'),
    warning: i18n(
      'With Knots BLAKE2b on this server: first run its "Generate RPC User Credentials" action (in Knots BLAKE2b, Actions), and enter the user and password it shows here. Its host is knots-blake2b.startos and its RPC port 18443.',
    ),
    allowedStatuses: 'any',
    group: null,
    visibility: 'enabled',
  },
  inputSpec,
  async ({ effects }) => {
    const n = await storeJson.read((s) => s.node).once()
    // no node yet: Knots BLAKE2b's address and port when it is installed on this server
    if (!n?.host) {
      const knots = await effects.getInstalledPackages().then(
        (ids) => ids.includes(KNOTS.packageId),
        () => false,
      )
      return knots ? { host: KNOTS.host, port: KNOTS.rpcPort, chain: n?.chain ?? 'main' } : { port: KNOTS.rpcPort }
    }
    return { host: n.host, port: n.port, user: n.user || undefined, password: n.password || undefined, chain: n.chain }
  },
  async ({ effects, input }) => {
    if (input.user.includes(':')) throw new Error(i18n('The RPC user cannot contain a colon'))
    await storeJson.merge(effects, {
      node: { host: input.host.trim(), port: input.port, user: input.user, password: input.password, chain: input.chain as 'main' },
    })
  },
)
