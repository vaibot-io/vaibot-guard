import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { writeGuardEndpoint, readGuardEndpoint, loadStore, migrateStore } from '../scripts/lib/creds.mjs'

// Port-as-data: the host-level guard endpoint persists in credentials.json so the
// resolved port survives restarts and is discoverable without a hardcoded default.

test('guard endpoint: write/read round-trips host/port/token', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vaibot-creds-guard-'))
  const opts = { dir }
  assert.equal(readGuardEndpoint(opts), null)
  const w = writeGuardEndpoint({ host: '127.0.0.1', port: 41234, token: 'abc' }, opts)
  assert.equal(w.port, 41234)
  const r = readGuardEndpoint(opts)
  assert.equal(r.port, 41234)
  assert.equal(r.host, '127.0.0.1')
  assert.equal(r.token, 'abc')
})

test('guard endpoint: rejects a malformed port', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vaibot-creds-guard-'))
  assert.throws(() => writeGuardEndpoint({ port: 0 }, { dir }))
  assert.throws(() => writeGuardEndpoint({ port: 99999 }, { dir }))
  assert.equal(writeGuardEndpoint({ port: 5555 }, { dir }).host, '127.0.0.1')
})

test('guard endpoint: migrateStore preserves guard + env, drops malformed guard', () => {
  const m = migrateStore({
    version: 3,
    active_env: 'production',
    environments: { production: { api_key: 'vb_live_x' } },
    guard: { host: '127.0.0.1', port: 5000 },
  })
  assert.equal(m.guard.port, 5000)
  assert.equal(m.environments.production.api_key, 'vb_live_x')
  assert.ok(!migrateStore({ version: 3, environments: {}, guard: { port: 'x' } }).guard)
})

test('guard endpoint: merge-on-write keeps existing env creds', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vaibot-creds-guard-'))
  writeFileSync(
    join(dir, 'credentials.json'),
    JSON.stringify({ version: 3, active_env: 'production', environments: { production: { api_key: 'vb_live_seed' } } }),
  )
  writeGuardEndpoint({ port: 42000 }, { dir })
  const s = loadStore({ dir })
  assert.equal(s.environments.production.api_key, 'vb_live_seed')
  assert.equal(s.guard.port, 42000)
})
