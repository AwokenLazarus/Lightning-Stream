// The Node connection form: empty user and password until a node is saved, and a banner that says which it
// shows. `npm test` (node --experimental-strip-types --test). The action imports the SDK, so its source is read.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const src = readFileSync(new URL('../startos/actions/nodeConfig.ts', import.meta.url), 'utf8')
const dict = readFileSync(new URL('../startos/i18n/dictionaries/default.ts', import.meta.url), 'utf8')

test('no node saved: Knots BLAKE2b host and port only, never a user or password', () => {
  const unset = src.slice(src.indexOf('if (!n?.host)'), src.indexOf('return { host: n.host'))
  assert.ok(unset.length > 0, 'the no-node prefill is found')
  assert.doesNotMatch(unset, /user|password/)
  assert.match(unset, /host: KNOTS\.host, port: KNOTS\.rpcPort/)
  // the inputs themselves default to nothing
  for (const f of ['user', 'password']) {
    const spec = src.slice(src.indexOf(`  ${f}: Value.text(`))
    assert.match(spec.slice(0, spec.indexOf('}),')), /default: null/, `${f} has no default`)
  }
})

test('the banner asks for new credentials only while no node is saved, and says so when one is', () => {
  assert.match(src, /warning: i18n\(nodeConfigured\(n\) \? NODE_BANNER\.saved : NODE_BANNER\.unset\)/)
  assert.match(src, /storeJson\.read\(\(s\) => s\.node\)\.const\(effects\)/, 'the banner follows the saved node')
  const banner = (k) => {
    const m = src.match(new RegExp(`${k}:\\s*\\n?\\s*'((?:[^'\\\\]|\\\\.)*)'`))
    assert.ok(m, `banner ${k}`)
    return m[1].replace(/\\'/g, "'")
  }
  assert.match(banner('unset'), /enter the user and password it shows here/)
  assert.match(banner('saved'), /saved now/)
  assert.doesNotMatch(banner('saved'), /enter the user and password it shows here/)
  // both are in the dictionary i18n reads
  for (const k of ['unset', 'saved']) assert.ok(dict.includes(`'${banner(k)}'`), `${k} is in the dictionary`)
})
