import { T } from '@start9labs/start-sdk'
import { sdk } from './sdk'
import { grantFromAnswer, GrantAnswer, LF_GRANT, LIGHTNING } from './spec'

/**
 * Whether the installed Lightning Fork has the grant action (spec.ts LF_GRANT), asked of the OS at run time:
 * no version range tells (the action is on a branch's pre-releases, not on the mainline releases after them).
 *
 * The OS keeps every package's list of actions, so the question is "give me the grant action's input": it
 * looks the action up in that list first and answers "Not Found" without it (grantFromAnswer reads the
 * answer). The list is there whether Lightning Fork runs or not, and it is the action itself that the task
 * needs, which is why this asks for it rather than for its `apps` folder: that folder can only be seen by
 * mounting it, and a mount that fails is what stopped node-keys at every start (0.2.14 on a mainline
 * Lightning Fork). The mount is tried too, the same way in init and main ([`appsMountable`]).
 */
export async function lightningForkGrant(effects: T.Effects): Promise<GrantAnswer> {
  try {
    await effects.action.getInput({ packageId: LIGHTNING.packageId, actionId: LF_GRANT.actionId })
    return grantFromAnswer(null)
  } catch (e) {
    return grantFromAnswer(e)
  }
}

/** Lightning Fork's `apps` folder (its granted keys), read-only, where node-keys mounts it (spec.ts). */
export const appsMounts = () =>
  sdk.Mounts.of().mountDependency({
    dependencyId: LIGHTNING.packageId,
    volumeId: 'main',
    subpath: LF_GRANT.grantsDir,
    mountpoint: '/mnt/lightning-fork-apps',
    readonly: true,
    type: 'directory',
  })

/**
 * Whether Lightning Fork's `apps` folder mounts, tried in a throwaway subcontainer: init asks this before it
 * makes the grant task, so it never asks for a grant that main, whose own mount of it failed, could not take.
 */
export async function appsMountable(effects: T.Effects): Promise<boolean> {
  try {
    await sdk.SubContainer.withTemp(effects, { imageId: 'ui' }, appsMounts(), 'lightning-fork-apps-probe', async () => null)
    return true
  } catch {
    return false
  }
}
