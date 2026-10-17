import { sdk } from './sdk'

// The Lightning node is Lightning Fork (the XBT chain's lnd), required running: the wallet pays over it.
// The XBT node is still an external connection set in the Node connection action (no package here declares
// Paul's knots-blake2b yet; Lightning Fork does, and declaring it is the next step).
export const setDependencies = sdk.setupDependencies(async () => ({
  'lightning-fork': { kind: 'running', versionRange: '>=0.21.0:0', healthChecks: [] },
}))
