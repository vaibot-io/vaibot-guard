import { test } from 'node:test'
import assert from 'node:assert/strict'
import { unitPath, startCommands, installTier, installGuardService } from '../scripts/lib/guard-install.mjs'

test('unitPath: linux/darwin × user/system', () => {
  assert.equal(unitPath('linux', 'user', '/home/x'), '/home/x/.config/systemd/user/vaibot-guard.service')
  assert.equal(unitPath('linux', 'system'), '/etc/systemd/system/vaibot-guard.service')
  assert.equal(unitPath('darwin', 'user', '/Users/x'), '/Users/x/Library/LaunchAgents/io.vaibot.guard.plist')
  assert.equal(unitPath('darwin', 'system'), '/Library/LaunchDaemons/io.vaibot.guard.plist')
  assert.equal(unitPath('win32', 'user'), null)
})

test('startCommands: linux user = --user; system = sudo -n', () => {
  assert.deepEqual(startCommands('linux', 'user')[1], ['systemctl', ['--user', 'enable', '--now', 'vaibot-guard']])
  assert.deepEqual(startCommands('linux', 'system')[1], ['sudo', ['-n', 'systemctl', 'enable', '--now', 'vaibot-guard']])
})

test('startCommands: darwin user = launchctl gui domain; system = sudo LaunchDaemon', () => {
  const u = startCommands('darwin', 'user', 501)
  assert.deepEqual(u[0].slice(0, 1).concat(u[0][1].slice(0, 2)), ['launchctl', 'bootstrap', 'gui/501'])
  assert.match(u[0][1][2], /Library\/LaunchAgents\/io\.vaibot\.guard\.plist$/)
  assert.deepEqual(u[1], ['launchctl', ['kickstart', '-k', 'gui/501/io.vaibot.guard']])
  const s = startCommands('darwin', 'system')
  assert.deepEqual(s[0][1].slice(0, 3), ['-n', 'launchctl', 'bootstrap'])
})

test('installTier: writes unit + runs enable (injected)', async () => {
  const writes = [], runs = []
  const res = await installTier(
    { platform: 'linux', scope: 'user', execStart: '/usr/bin/node x.mjs', envFile: '/e', home: '/home/x' },
    { write: (p, c) => writes.push([p, c]), mkdir: () => {}, run: async (c, a) => { runs.push([c, ...a]); return true } },
  )
  assert.equal(res.ok, true)
  assert.equal(writes[0][0], '/home/x/.config/systemd/user/vaibot-guard.service')
  assert.match(writes[0][1], /ExecStart=\/usr\/bin\/node x\.mjs/)
  assert.deepEqual(runs[0], ['systemctl', '--user', 'reset-failed', 'vaibot-guard']) // pre-clean first
  assert.equal(runs.length, 3) // reset-failed + daemon-reload + enable
})

test('installTier: enable failure → ok:false + error', async () => {
  const res = await installTier(
    { platform: 'linux', scope: 'user', execStart: '/x', home: '/home/x' },
    { write: () => {}, mkdir: () => {}, run: async () => { throw new Error('no user bus') } },
  )
  assert.equal(res.ok, false)
  assert.match(res.error, /no user bus/)
})

test('installGuardService: ladder falls through failing tiers to self', async () => {
  const res = await installGuardService(
    { platform: 'linux', tiers: ['system', 'user', 'self'], execStart: '/x', home: '/home/x' },
    { write: () => {}, mkdir: () => {}, run: async () => { throw new Error('denied') } },
  )
  assert.equal(res.tier, 'self')
  assert.equal(res.selfSpawn, true)
})

test('installGuardService: first working tier wins', async () => {
  const res = await installGuardService(
    { platform: 'linux', tiers: ['user', 'self'], execStart: '/x', home: '/home/x' },
    { write: () => {}, mkdir: () => {}, run: async () => true },
  )
  assert.equal(res.tier, 'user')
  assert.equal(res.ok, true)
})
