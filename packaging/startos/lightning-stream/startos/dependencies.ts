import { sdk } from './sdk'
import { LF_GRANT } from './spec'

// The Lightning node is Lightning Fork (the XBT chain's lnd), required running: the app pays and sells over it.
// Once Lightning Fork grants keys (spec.ts LF_GRANT), the app asks for at least that version, so the grant
// folder it mounts is always there.
// The XBT node is still an external connection set in the Node connection action (Paul's knots-blake2b is
// not declared yet; Lightning Fork does, and declaring it is the next step).
export const setDependencies = sdk.setupDependencies(async () => ({
  'lightning-fork': { kind: 'running', versionRange: LF_GRANT.minVersion ? `>=${LF_GRANT.minVersion}` : '>=0.21.4-beta.21.1:1', healthChecks: [] },
}))
