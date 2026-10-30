import { sdk } from './sdk'
import { storeJson } from './fileModels/store.json'
import { FILE_BROWSER, LF_GRANT } from './spec'

// The Lightning node is Lightning Fork (the XBT chain's lnd), required running: the app pays and sells over it.
// Once Lightning Fork grants keys (spec.ts LF_GRANT), the app asks for at least that version, so the grant
// folder it mounts is always there.
// The XBT node is still an external connection set in the Node connection action (Paul's knots-blake2b is
// not declared yet; Lightning Fork does, and declaring it is the next step).
// File Browser is needed only when the owner shares its files with Files (the "Files folder" action): it has
// to be installed, not running, since the UI only reads its volume.
export const setDependencies = sdk.setupDependencies(async ({ effects }) => {
  const filesSource = await storeJson.read((s) => s.filesSource).const(effects)
  return {
    'lightning-fork': { kind: 'running', versionRange: LF_GRANT.minVersion ? `>=${LF_GRANT.minVersion}` : '>=0.21.4-beta.21.1:1', healthChecks: [] },
    ...(filesSource === 'filebrowser' ? { [FILE_BROWSER.packageId]: { kind: 'exists', versionRange: `>=${FILE_BROWSER.minVersion}` } } : {}),
  }
})
