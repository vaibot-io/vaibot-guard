// v3 credentials: split V1 provenance / V2 governance bases per env.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  loadStore,
  saveCredsForEnv,
  governanceBaseForEnv,
  provenanceBaseForEnv,
  resolveCredentials,
  urlOverrideAllowed,
  gateUrlOverride,
  migrateFileIfNeeded,
} from '../scripts/lib/creds.mjs'

const tmp = () => mkdtempSync(join(tmpdir(), 'vaibot-creds-'))

test('a v2 file (no governance/provenance slots) loads and resolves canonical URLs', () => {
  const dir = tmp()
  writeFileSync(
    join(dir, 'credentials.json'),
    JSON.stringify({ version: 2, active_env: 'staging', environments: { staging: { api_key: 'vb_stg_x' } } }),
  )
  const store = loadStore({ dir })
  assert.equal(store.active_env, 'staging')
  assert.equal(store.environments.staging.api_key, 'vb_stg_x')
  assert.equal(governanceBaseForEnv(store, 'staging'), 'https://staging-api.vaibot.io')
  assert.equal(provenanceBaseForEnv(store, 'staging'), 'https://vaibot-api-v1.fly.dev/api')
})

test('canonical bases per env', () => {
  assert.equal(governanceBaseForEnv(undefined, 'production'), 'https://api.vaibot.io')
  assert.equal(provenanceBaseForEnv(undefined, 'production'), 'https://provenance.vaibot.io/api')
  assert.equal(provenanceBaseForEnv(undefined, 'staging'), 'https://vaibot-api-v1.fly.dev/api')
})

test('stored slot urls override canonical and roundtrip as v3', () => {
  const dir = tmp()
  saveCredsForEnv(
    'staging',
    { api_key: 'vb_stg_x', governance: { url: 'https://gov.example' }, provenance: { url: 'https://prov.example/api' } },
    { dir },
  )
  const store = loadStore({ dir })
  assert.equal(governanceBaseForEnv(store, 'staging'), 'https://gov.example')
  assert.equal(provenanceBaseForEnv(store, 'staging'), 'https://prov.example/api')
  const raw = JSON.parse(readFileSync(join(dir, 'credentials.json'), 'utf-8'))
  assert.equal(raw.version, 3)
  assert.equal(raw.environments.staging.provenance.url, 'https://prov.example/api')
})

test('explicit override beats stored and canonical (trailing slash trimmed)', () => {
  assert.equal(governanceBaseForEnv(undefined, 'production', 'https://override.example/'), 'https://override.example')
  assert.equal(provenanceBaseForEnv(undefined, 'production', 'https://prov.override/api'), 'https://prov.override/api')
})

test('§5 gate: urlOverrideAllowed parses the deliberate-act flag', () => {
  assert.equal(urlOverrideAllowed({ VAIBOT_ALLOW_URL_OVERRIDE: '1' }), true)
  assert.equal(urlOverrideAllowed({ VAIBOT_ALLOW_URL_OVERRIDE: 'true' }), true)
  assert.equal(urlOverrideAllowed({ VAIBOT_ALLOW_URL_OVERRIDE: 'yes' }), true)
  assert.equal(urlOverrideAllowed({ VAIBOT_ALLOW_URL_OVERRIDE: '0' }), false)
  assert.equal(urlOverrideAllowed({}), false)
})

test('§5 gate: gateUrlOverride suppresses a prod override without the flag', () => {
  // production: dropped without the flag, honored with it.
  assert.equal(gateUrlOverride('production', 'https://evil', false), null)
  assert.equal(gateUrlOverride('production', 'https://ok', true), 'https://ok')
  // staging: always honored (the flag is a production-only gate).
  assert.equal(gateUrlOverride('staging', 'https://stg', false), 'https://stg')
  // falsy/empty ⇒ null.
  assert.equal(gateUrlOverride('production', '', true), null)
  assert.equal(gateUrlOverride('production', undefined, true), null)
})

test('§5: resolveCredentials suppresses a prod url override without the flag (closes the plugin-bearer leak)', () => {
  const store = { environments: { production: { api_key: 'vb_live_x' } } }
  // prod env + attacker-injected governance/provenance override, NO flag → canonical.
  const leaked = resolveCredentials({
    env: { VAIBOT_ENV: 'production', VAIBOT_GOVERNANCE_URL: 'https://attacker.example', VAIBOT_PROVENANCE_URL: 'https://attacker.example/api' },
    store,
  })
  assert.equal(leaked.apiBaseUrl, 'https://api.vaibot.io')
  assert.equal(leaked.provenanceBaseUrl, 'https://provenance.vaibot.io/api')
  // deprecated VAIBOT_API_URL overrides NO base (env inference only) — even WITH the
  // flag it cannot redirect governance or provenance.
  const apiUrlOnly = resolveCredentials({
    env: { VAIBOT_ENV: 'production', VAIBOT_API_URL: 'https://attacker.example', VAIBOT_ALLOW_URL_OVERRIDE: '1' },
    store,
  })
  assert.equal(apiUrlOnly.apiBaseUrl, 'https://api.vaibot.io')
  assert.equal(apiUrlOnly.provenanceBaseUrl, 'https://provenance.vaibot.io/api')
  // WITH the flag the prod override is honored (admin half is the caller's job).
  const allowed = resolveCredentials({
    env: { VAIBOT_ENV: 'production', VAIBOT_GOVERNANCE_URL: 'https://ok.example', VAIBOT_ALLOW_URL_OVERRIDE: '1' },
    store,
  })
  assert.equal(allowed.apiBaseUrl, 'https://ok.example')
})

test('migrateFileIfNeeded upgrades a v2 file to v3 losslessly (both env records + .bak)', () => {
  const dir = tmp()
  writeFileSync(
    join(dir, 'credentials.json'),
    JSON.stringify({
      version: 2,
      active_env: 'staging',
      environments: { production: { api_key: 'vb_live_p' }, staging: { api_key: 'vb_stg_s', wallet_address: '0xabc' } },
    }),
  )
  const res = migrateFileIfNeeded({ dir })
  assert.equal(res.migrated, true)
  const raw = JSON.parse(readFileSync(join(dir, 'credentials.json'), 'utf-8'))
  assert.equal(raw.version, 3)
  assert.equal(raw.active_env, 'staging')
  assert.equal(raw.environments.production.api_key, 'vb_live_p')
  assert.equal(raw.environments.staging.api_key, 'vb_stg_s')
  assert.equal(raw.environments.staging.wallet_address, '0xabc')
  assert.ok(existsSync(join(dir, 'credentials.json.bak')), 'a .bak snapshot is written')
  // idempotent: a second call is a no-op on the now-current file.
  assert.equal(migrateFileIfNeeded({ dir }).migrated, false)
})

test('resolveCredentials carries both bases and honors env overrides', () => {
  const r = resolveCredentials({ env: { VAIBOT_ENV: 'production' }, store: { environments: {} } })
  assert.equal(r.apiBaseUrl, 'https://api.vaibot.io')
  assert.equal(r.provenanceBaseUrl, 'https://provenance.vaibot.io/api')

  const r2 = resolveCredentials({
    env: { VAIBOT_ENV: 'staging', VAIBOT_PROVENANCE_URL: 'https://p.example/api' },
    store: { environments: {} },
  })
  assert.equal(r2.apiBaseUrl, 'https://staging-api.vaibot.io')
  assert.equal(r2.provenanceBaseUrl, 'https://p.example/api')
})
