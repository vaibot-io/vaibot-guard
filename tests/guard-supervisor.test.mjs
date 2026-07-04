import { test } from 'node:test'
import assert from 'node:assert/strict'
import { serviceTiers, detectContainer, detectCI } from '../scripts/lib/guard-supervisor.mjs'

const base = { isContainer: false, isCI: false, hasCmd: () => true, env: {} }

test('serviceTiers: container / CI → self only (no supervisor)', () => {
  assert.deepEqual(serviceTiers({ ...base, isContainer: true, platform: 'linux' }), ['self'])
  assert.deepEqual(serviceTiers({ ...base, isCI: true, platform: 'linux' }), ['self'])
})

test('serviceTiers: linux non-root → user unit', () => {
  assert.deepEqual(
    serviceTiers({ ...base, platform: 'linux', uid: 1000, env: { XDG_RUNTIME_DIR: '/run/user/1000' } }),
    ['user', 'self'],
  )
})

test('serviceTiers: linux root → system tamper boundary', () => {
  assert.deepEqual(serviceTiers({ ...base, platform: 'linux', uid: 0 }), ['system', 'self'])
})

test('serviceTiers: linux non-root + sudo → system then user', () => {
  assert.deepEqual(
    serviceTiers({ ...base, platform: 'linux', uid: 1000, canSudo: true, env: { XDG_RUNTIME_DIR: '/x' } }),
    ['system', 'user', 'self'],
  )
})

test('serviceTiers: darwin non-root → LaunchAgent; root → LaunchDaemon', () => {
  assert.deepEqual(serviceTiers({ ...base, platform: 'darwin', uid: 501 }), ['user', 'self'])
  assert.deepEqual(serviceTiers({ ...base, platform: 'darwin', uid: 0 }), ['system', 'self'])
})

test('serviceTiers: windows / no supervisor binary → self only', () => {
  assert.deepEqual(serviceTiers({ ...base, platform: 'win32' }), ['self'])
  assert.deepEqual(
    serviceTiers({ ...base, platform: 'linux', uid: 1000, hasCmd: () => false, env: { XDG_RUNTIME_DIR: '/x' } }),
    ['self'],
  )
})

test('detectContainer: dockerenv / cgroup / env', () => {
  assert.equal(detectContainer({ env: {}, exists: (p) => p === '/.dockerenv', read: () => '' }), true)
  assert.equal(detectContainer({ env: {}, exists: () => false, read: () => '12:cpu:/kubepods/pod123' }), true)
  assert.equal(detectContainer({ env: { container: 'podman' }, exists: () => false, read: () => '' }), true)
  assert.equal(detectContainer({ env: {}, exists: () => false, read: () => '12:cpu:/user.slice' }), false)
})

test('detectCI: common runners', () => {
  assert.equal(detectCI({ env: { GITHUB_ACTIONS: 'true' } }), true)
  assert.equal(detectCI({ env: { CI: 'true' } }), true)
  assert.equal(detectCI({ env: {} }), false)
})
