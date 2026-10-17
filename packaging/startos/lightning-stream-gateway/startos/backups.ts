import { sdk } from './sdk'

/**
 * The `main` volume: the gateway's receipt key, its sessions and journal (what buyers are owed), its config
 * and macaroons, and the setup page's login hash. On restore, xbt-init (every start) re-applies the owners.
 */
export const { createBackup, restoreInit } = sdk.setupBackups(async () => sdk.Backups.ofVolumes('main'))
