import { i18n } from '../i18n'
import { sdk } from '../sdk'
import { nodeConfig } from '../actions/nodeConfig'
import { showSetupCode } from '../actions/showSetupCode'
import { nodeConfigured, storeJson } from '../fileModels/store.json'
import { access } from 'node:fs/promises'
import { LF_GRANT, LIGHTNING } from '../spec'
import { lightningForkGrant } from '../grant'

/** Seed the store on install (defaults from the file model's shape). */
export const seedStore = sdk.setupOnInit(async (effects, kind) => {
  if (kind !== 'install') return
  await storeJson.merge(effects, {})
})

/** The service cannot start without a node: a critical task until the Node connection action is saved. */
export const watchNode = sdk.setupOnInit(async (effects) => {
  const node = await storeJson.read((s) => s.node).const(effects)
  if (!nodeConfigured(node)) {
    await sdk.action.createOwnTask(effects, nodeConfig, 'critical', {
      reason: i18n('Connect the wallet to your XBT node before starting it'),
    })
  }
})

/** After install: the UI asks for a setup code before the owner chooses its password. */
export const taskSetupCode = sdk.setupOnInit(async (effects, kind) => {
  if (kind !== 'install') return
  await sdk.action.createOwnTask(effects, showSetupCode, 'important', {
    reason: i18n('Once the service runs, get the web UI setup code and choose your password'),
  })
})

/**
 * Lightning Fork's grant-app-access (spec.ts LF_GRANT): ask for the wallet's key with a task in Lightning
 * Fork, only while this package has no key yet (StartOS makes the task active again on every call).
 * 'important', not 'critical': the app runs without it, so its pages can say what to do (approve the task,
 * or paste a key), and the hashrate and selling pages work meanwhile. Only the action's id is needed here.
 *
 * Only where Lightning Fork has the action (grant.ts asks the OS): a mainline Lightning Fork has none, and a
 * task for it showed "Action not found" (0.2.14). Without it, a task made before is cleared, and the Your node
 * page walks the owner through pasting Lightning Fork's connection address. This re-runs when Lightning Fork
 * changes version or restarts, so one updated to a version with the action gets the task then.
 */
const grantAppAccess = { id: LF_GRANT.actionId } as unknown as Parameters<typeof sdk.action.createTask>[2]
const grantTaskId = `${LIGHTNING.packageId}:${LF_GRANT.actionId}`
export const requestGrant = sdk.setupOnInit(async (effects) => {
  // watched, so a Lightning Fork installed, updated or restarted later is looked at again
  await sdk
    .getServiceManifest(effects, LIGHTNING.packageId, (m) => m?.version ?? null)
    .const()
    .catch(() => null)
  await sdk
    .getContainerIp(effects, { packageId: LIGHTNING.packageId })
    .const()
    .catch(() => null)
  if ((await lightningForkGrant(effects)) !== 'present') {
    await sdk.action.clearTask(effects, grantTaskId)
    return
  }
  const have = await access(sdk.volumes.main.subpath('run/ln/rail.macaroon')).then(
    () => true,
    () => false,
  )
  if (have) return
  const ask = { packageId: 'lightning-stream', permissions: [...LF_GRANT.permissions], label: 'Lightning Stream wallet' }
  await sdk.action.createTask(effects, LIGHTNING.packageId, grantAppAccess, 'important', {
    input: { kind: 'partial', accept: [ask], set: ask } as never,
    when: { condition: 'input-not-matches', once: true },
    reason: i18n('Let Lightning Stream pay through this node, within the spending rules you sign. It cannot open or close channels.'),
  })
})
