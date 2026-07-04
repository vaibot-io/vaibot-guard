import { test } from 'node:test'
import assert from 'node:assert/strict'
import { systemdUnit, launchdPlist } from '../scripts/lib/guard-units.mjs'

test('systemdUnit: user scope', () => {
  const u = systemdUnit({ execStart: '/usr/bin/foo', envFile: '/e', scope: 'user' })
  assert.match(u, /WantedBy=default\.target/)
  assert.match(u, /ExecStart=\/usr\/bin\/foo/)
  assert.match(u, /EnvironmentFile=\/e/)
  assert.doesNotMatch(u, /^User=/m)
})

test('systemdUnit: system scope runs as user + multi-user target', () => {
  const s = systemdUnit({ execStart: '/x', scope: 'system', user: 'bob' })
  assert.match(s, /WantedBy=multi-user\.target/)
  assert.match(s, /User=bob/)
})

test('systemdUnit: requires execStart', () => {
  assert.throws(() => systemdUnit({}))
})

test('launchdPlist: label + args + env + XML escaping', () => {
  const p = launchdPlist({ label: 'io.vaibot.guard', programArgs: ['/usr/bin/node', 'a & <b>'], envVars: { A: '1' } })
  assert.match(p, /<string>io\.vaibot\.guard<\/string>/)
  assert.match(p, /<string>\/usr\/bin\/node<\/string>/)
  assert.match(p, /a &amp; &lt;b&gt;/)
  assert.match(p, /<key>A<\/key>\s*<string>1<\/string>/)
  assert.match(p, /RunAtLoad/)
  assert.match(p, /KeepAlive/)
})

test('launchdPlist: requires label + non-empty programArgs', () => {
  assert.throws(() => launchdPlist({}))
  assert.throws(() => launchdPlist({ label: 'x', programArgs: [] }))
})
