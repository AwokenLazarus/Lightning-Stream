// The masking gateway (the `datum` daemon) and the hashtaker that sends rented work to it: on the package's
// loopback only, the node from the Node connection action, every job checked. `npm test`.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { DATUM, DATUM_CANDIDATES, IMAGES, PORTS, services } from '../startos/spec.ts'

const cfg = {
  node: { host: 'knots.startos', port: 9332, user: 'u', password: 'p', chain: 'main' },
  mcpUrls: [],
  lightningRest: '',
  proxies: [],
  lanHost: '192.168.1.5',
  aiUrls: [],
}
const all = services(cfg)
const by = (id) => all.find((s) => s.id === id)
const arg = (cmd, flag) => cmd[cmd.indexOf(flag) + 1]

test('the masking gateway is a daemon of the package, on its own image', () => {
  const d = by('datum')
  assert.ok(d)
  assert.equal(d.image, 'datum')
  assert.match(IMAGES.datum, /(^|\/)xbt-datum-gateway:/)
  assert.equal(d.user, undefined, "it runs as its image's own non-root user")
  assert.deepEqual(d.requires, ['init'])
})

test('it starts once Services → Hashrate wrote its config, and again when the config or the cookie changes', () => {
  const c = by('datum').command
  assert.deepEqual(c, ['/usr/bin/xbt-supervise', '--wait', '/data/run/datum/config.json', '--watch', '/data/run/datum/rpc.cookie', '--',
    '/usr/bin/xbt-datum-gateway', '-c', '/data/run/datum/config.json'])
})

test('its data is on the package volume: its own folder, and the settings and cookie read-only', () => {
  assert.deepEqual(by('datum').mounts, [
    { subpath: 'datum', mountpoint: '/data/datum', readonly: false },
    { subpath: 'run/datum', mountpoint: '/data/run/datum', readonly: true },
  ])
  assert.ok(!by('datum').mounts.some((m) => m.dependency), 'nothing of another package')
})

test('its health: the API answers, or it is idle by design with no config yet', () => {
  assert.deepEqual(by('datum').readyCommand, ['/usr/bin/xbt-supervise', 'probe', 'http://127.0.0.1:7152/', '--waiting-for', '/data/run/datum/config.json'])
  assert.equal(by('datum').port, PORTS.datumApi)
})

test('init makes its folders and writes the cookie from the Node connection action', () => {
  const i = by('init')
  assert.ok(i.env.XBT_INIT_COMPONENTS.split(',').includes('datum'))
  assert.equal(i.env.XBT_INIT_NODE_RPC_AUTH, 'u:p')
})

test('the UI writes its config (no secret) and is told the node from the Node connection action', () => {
  const u = by('ui')
  assert.ok(u.mounts.some((m) => m.subpath === 'run/datum' && !m.readonly))
  assert.equal(u.env.XBT_UI_DATUM_DIR, '/data/run/datum')
  assert.equal(u.env.XBT_UI_DATUM_RPCURL, 'http://knots.startos:9332')
  assert.equal(u.env.XBT_UI_DATUM_API_PORT, '7152')
  assert.ok(!Object.values(u.env).some((v) => v.includes('u:p')), 'no credential in the UI')
})

test('no other service sees the cookie', () => {
  for (const s of all) {
    if (s.id === 'datum' || s.id === 'ui' || s.id === 'init') continue
    assert.ok(!s.mounts.some((m) => m.subpath === 'run/datum' || m.subpath === 'datum' || m.subpath === null), `${s.id} mounts run/datum`)
  }
})

test('ports: loopback only, and none collides with another service', () => {
  assert.equal(PORTS.datumStratum, 23339)
  assert.equal(PORTS.datumApi, 7152)
  const ports = Object.values(PORTS)
  assert.equal(new Set(ports).size, ports.length)
  assert.equal(DATUM.stratum, '127.0.0.1:23339')
  assert.equal(DATUM.api, '127.0.0.1:7152')
})

test('the hashtaker tries the bundled gateway first, checks every job on its API, and never runs unmasked', () => {
  assert.deepEqual(DATUM_CANDIDATES, ['127.0.0.1:23339', 'datum-blake2b.startos:23336', 'datum.startos:23334'])
  const c = by('hashtaker').command
  assert.equal(arg(c, '--upstream'), 'auto')
  assert.equal(arg(c, '--datum-candidates'), '127.0.0.1:23339,datum-blake2b.startos:23336,datum.startos:23334')
  assert.equal(arg(c, '--gateway-api'), '127.0.0.1:7152')
  for (const s of all) assert.ok(!s.command.includes('--allow-unblinded'), `${s.id} runs with --allow-unblinded`)
  assert.deepEqual(by('hashtaker').requires, ['signer', 'datum'])
})
