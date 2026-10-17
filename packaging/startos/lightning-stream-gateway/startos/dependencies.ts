import { sdk } from './sdk'

// Lightning Fork (the XBT chain's lnd), required running: the gateway's tickets are hold invoices on it.
export const setDependencies = sdk.setupDependencies(async () => ({
  'lightning-fork': { kind: 'running', versionRange: '>=0.21.0:0', healthChecks: [] },
}))
