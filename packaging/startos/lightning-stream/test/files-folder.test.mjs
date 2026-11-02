// The Files service's File Browser folder: only what File Browser serves, read-only, its files shown as
// the UI's. `npm test` (node --experimental-strip-types --test).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { FILE_BROWSER, services } from '../startos/spec.ts'

const cfg = (filesFromFileBrowser) => ({
  node: { host: 'knots.startos', port: 9332, user: 'u', password: 'p', chain: 'main' },
  mcpUrls: [],
  lightningRest: '',
  proxies: [],
  lanHost: '',
  aiUrls: [],
  filesFromFileBrowser,
})
const ui = (c) => services(c).find((s) => s.id === 'ui')
const fbMount = (c) => ui(c).mounts.find((m) => m.mountpoint === FILE_BROWSER.mountpoint)

test('the File Browser mount is the folder File Browser serves, not its config and database', () => {
  const m = fbMount(cfg(true))
  assert.ok(m, 'the UI mounts File Browser once it is chosen')
  assert.equal(m.subpath, 'data')
  assert.equal(m.readonly, true)
  assert.deepEqual(m.dependency, { packageId: 'filebrowser', volumeId: 'data', type: 'directory' })
})

test("File Browser's own files (its user, 0640) are shown as the UI's, so the UI can read them", () => {
  assert.deepEqual(fbMount(cfg(true)).idmap, [{ fromId: 1000, toId: 10005 }])
})

test('with its own folder chosen, nothing of File Browser is mounted', () => {
  assert.equal(fbMount(cfg(false)), undefined)
})
