// Lightning Fork's grant action, found at run time: with it, node-keys watches the granted keys and the page asks
// for the grant; without it (a mainline Lightning Fork), nothing of its `apps` folder is mounted, node-keys has
// nothing to run, and the page takes Lightning Fork's connection address. `npm test`.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import {
  GRANT_ABSENT_LINE,
  GRANT_PROBE_LINE,
  grantFromAnswer,
  LF_CONNECT_ADDRESS,
  LF_GRANT,
  LIGHTNING,
  SETUP_CODE_HINT,
  services,
} from '../startos/spec.ts'

const cfg = (over) => ({
  node: { host: 'knots-blake2b.startos', port: 18443, user: 'u', password: 'p', chain: 'main' },
  mcpUrls: [],
  lightningRest: 'https://10.0.3.7:8080',
  proxies: [],
  lanHost: '',
  aiUrls: [],
  ...over,
})
const by = (c, id) => services(c).find((s) => s.id === id)
const lfMounts = (s) => s.mounts.filter((m) => m.dependency?.packageId === 'lightning-fork').map((m) => m.subpath)

test('with the grant action: node-keys watches the apps folder, and the page asks for the grant', () => {
  const c = cfg({ lightningGrant: true })
  const keys = by(c, 'node-keys')
  assert.deepEqual(lfMounts(keys).sort(), ['apps', 'public'])
  assert.equal(keys.env.XBT_KEYS_GRANT_DIR, '/mnt/lightning-fork-apps/lightning-stream')
  assert.equal(keys.env.XBT_KEYS_ADMIN, undefined)
  const ui = by(c, 'ui').env
  assert.equal(ui.XBT_UI_LN_GRANT, '1')
  assert.equal(ui.XBT_UI_LN_CONNECT_ADDRESS, undefined)
})

test('without it: nothing of apps is mounted anywhere, node-keys has no node to watch, and the page takes the address', () => {
  for (const c of [cfg({ lightningGrant: false }), cfg({})]) {
    for (const s of services(c)) assert.ok(!lfMounts(s).includes('apps'), `${s.id} mounts apps`)
    const keys = by(c, 'node-keys')
    assert.deepEqual(keys.mounts, [])
    assert.deepEqual(keys.env, {})
    const ui = by(c, 'ui').env
    assert.equal(ui.XBT_UI_LN_GRANT, undefined)
    assert.equal(ui.XBT_UI_LN_CONNECT_ADDRESS, LF_CONNECT_ADDRESS)
    assert.match(LF_CONNECT_ADDRESS, /Lightning Fork.*Interfaces.*REST LND Connect/)
    // the UI still reaches the node, to make its key from the address
    assert.equal(ui.XBT_UI_LN_REST, 'https://10.0.3.7:8080')
  }
})

test('with no Lightning Fork at all: neither the grant nor the address', () => {
  const ui = by(cfg({ lightningRest: '', lightningGrant: true }), 'ui').env
  assert.equal(ui.XBT_UI_LN_GRANT, undefined)
  assert.equal(ui.XBT_UI_LN_CONNECT_ADDRESS, undefined)
  assert.deepEqual(by(cfg({ lightningRest: '', lightningGrant: true }), 'node-keys').mounts, [])
})

test("the OS's answer: present only on an answer, absent only on its Not Found, unknown otherwise", () => {
  assert.equal(grantFromAnswer(null), 'present')
  // StartOS 0.4.1: the action list has no such id (code 6, "Not Found", details the id), as the host RPC words it
  assert.equal(grantFromAnswer(new Error('Not Found: grant-app-access@get-action-input')), 'absent')
  assert.equal(grantFromAnswer(new Error('Not Found: lightning-fork@get-action-input')), 'no-node')
  // anything else is not sure: neither the grant nor its absence
  assert.equal(grantFromAnswer(new Error('Timeout: get-action-input')), 'unknown')
  assert.equal(grantFromAnswer('Error: Filesystem I/O Error'), 'unknown')
  assert.equal(grantFromAnswer(new Error('Action not found')), 'unknown')
  assert.equal(grantFromAnswer(new Error('Not Found@get-action-input')), 'unknown')
})

test('init makes or clears the task only on a sure answer, and never asks for a grant main cannot mount', () => {
  const src = readFileSync(new URL('../startos/init/tasks.ts', import.meta.url), 'utf8')
  const body = src.slice(src.indexOf('export const requestGrant'))
  const unknown = body.indexOf("if (answer === 'unknown') return")
  const clear = body.indexOf('clearTask')
  const create = body.indexOf('createTask')
  assert.ok(unknown > 0 && unknown < clear && clear < create, 'unknown returns before the task is cleared or made')
  assert.match(body, /answer !== 'present' \|\| !\(await appsMountable\(effects\)\)/)
  const main = readFileSync(new URL('../startos/main.ts', import.meta.url), 'utf8')
  assert.match(main, /lightningForkGrant\(effects\)\) === 'present'/, "main's grant mode needs a sure answer")
  assert.match(main, /getServiceManifest\(effects, LIGHTNING\.packageId/, 'main re-decides when Lightning Fork changes version')
})

test("the look for the grant action explains StartOS's Not Found trace in the log, before it and after it", () => {
  const src = readFileSync(new URL('../startos/grant.ts', import.meta.url), 'utf8')
  const body = src.slice(src.indexOf('export async function lightningForkGrant'), src.indexOf('export const appsMounts'))
  const before = body.indexOf('console.info(GRANT_PROBE_LINE)')
  const ask = body.indexOf('effects.action.getInput(')
  const after = body.indexOf("if (answer === 'absent') console.info(GRANT_ABSENT_LINE)")
  assert.ok(before > 0 && before < ask && ask < after, 'the line before the host call, the answer after it')
  assert.match(GRANT_PROBE_LINE, /Grant app access.*"Not Found".*grant-app-access.*expected/)
  assert.equal(GRANT_ABSENT_LINE, 'Lightning Fork has no Grant app access action; Lightning Stream connects by its address instead')
  // still one answer of the three (and no-node), read from the host call's words: the logging changes none
  assert.match(body, /answer = grantFromAnswer\(null\)/)
  assert.match(body, /answer = grantFromAnswer\(e\)/)
})

test('the dependency range does not stand for the grant (mainline Lightning Fork lacks it)', () => {
  assert.equal(LF_GRANT.minVersion, undefined)
  assert.equal(LIGHTNING.minVersion, '0.21.4-beta.21.1:1')
  const deps = readFileSync(new URL('../startos/dependencies.ts', import.meta.url), 'utf8')
  assert.ok(!/LF_GRANT[.,}]/.test(deps), 'dependencies.ts reads nothing of the grant')
  assert.ok(deps.includes('`>=${LIGHTNING.minVersion}`'))
})

test("the setup code page names StartOS's own place for the code only", () => {
  const ui = by(cfg({}), 'ui').env
  assert.equal(ui.XBT_UI_SETUP_CODE_HINT, SETUP_CODE_HINT)
  assert.match(SETUP_CODE_HINT, /StartOS/)
  assert.doesNotMatch(SETUP_CODE_HINT, /Umbrel/)
})
