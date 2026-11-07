import { sdk } from './sdk'
import { storeJson } from './fileModels/store.json'
import { FILE_BROWSER, LIGHTNING } from './spec'

// The Lightning node is Lightning Fork (the XBT chain's lnd), required running: the app pays and sells over it.
// The range asks only for what every Lightning Fork from that version on has (public/ with its certificate): it says
// nothing of the grant action (spec.ts LF_GRANT), which some later versions lack. Whether the installed one
// has it is found at run time (grant.ts), not from its version.
// The XBT node is still an external connection set in the Node connection action (Paul's knots-blake2b is
// not declared yet; Lightning Fork does, and declaring it is the next step).
// File Browser is needed only when the owner shares its files with Files (the "Files folder" action): it has
// to be installed, not running, since the UI only reads its volume.
export const setDependencies = sdk.setupDependencies(async ({ effects }) => {
  const filesSource = await storeJson.read((s) => s.filesSource).const(effects)
  return {
    'lightning-fork': { kind: 'running', versionRange: `>=${LIGHTNING.minVersion}`, healthChecks: [] },
    ...(filesSource === 'filebrowser' ? { [FILE_BROWSER.packageId]: { kind: 'exists', versionRange: `>=${FILE_BROWSER.minVersion}` } } : {}),
  }
})
