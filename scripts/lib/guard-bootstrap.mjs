// @vaibot/shared — universal guard daemon bootstrapper (ensureGuard).
//
// Idempotent discover-or-launch for the single shared local guard at
// ~/.vaibot/guard. Every plugin/adapter calls ensureGuard() through this ONE
// module so the discovery + single-instance logic can't diverge between codex,
// claudecode, and openclaw.
//
// Algorithm:
//   1. Read the lock file (~/.vaibot/guard/guard.json) and /health-probe it.
//      Healthy + version-compatible → reuse (no launch).
//   2. Otherwise acquire a single-flight lock, re-check, then launch:
//      walk candidate ports; the guard binds one (port-as-mutex). On
//      EADDRINUSE, probe /health — if it's OUR compatible guard, reuse it;
//      a foreign squatter or incompatible version → try the next port.
//      A guard that is still starting holds the same lock (role 'daemon'),
//      so a launcher that finds it held by a live guard adopts it rather
//      than launching a second one: one guard per machine.
//   3. On success, write the lock atomically (file 0600 / dir 0700) — unless
//      the guard already registered itself, and never over another guard's
//      token.
//
// The orchestration takes injectable deps so it is fully unit-testable without
// real sockets/processes. Real defaults: httpHealth (GET /health), fs lock I/O.
// The `launch` dep (spawning the guard process) is supplied by the integration
// layer in a later L step. Plain ESM so the guard + vendored hooks can use it
// without importing a workspace package at runtime.

import { readFileSync, writeFileSync, mkdirSync, chmodSync, renameSync, openSync, closeSync, unlinkSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { randomBytes } from 'node:crypto'

export const GUARD_DIR = join(homedir(), '.vaibot', 'guard')
export const LOCK_FILE = join(GUARD_DIR, 'guard.json')
export const LAUNCH_LOCK_FILE = join(GUARD_DIR, 'launch.lock')
// Containment state lives HERE, machine-wide, rather than in a workspace log
// dir — so every breaker on the machine reads one file, with no daemon, no
// network and no credentials. That is the point: the paths where a breaker
// degrades (daemon unreachable, no key, breaker tripped, fail-open) are exactly
// the paths that must still observe it, and all of them can read a file.
export const CONTAINMENT_FILE = join(GUARD_DIR, 'containment.json')
export const DEFAULT_HOST = '127.0.0.1'
export const DEFAULT_PORT = 39111
export const PORT_SCAN_COUNT = 10

export function defaultCandidatePorts(base = DEFAULT_PORT, count = PORT_SCAN_COUNT) {
  return Array.from({ length: count }, (_, i) => base + i)
}

export function readLock(path = LOCK_FILE) {
  try {
    return JSON.parse(readFileSync(path, 'utf-8'))
  } catch {
    return null
  }
}

export function writeLock(lock, path = LOCK_FILE, dir = GUARD_DIR) {
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  try {
    chmodSync(dir, 0o700)
  } catch {
    /* best-effort */
  }
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString('hex')}`
  writeFileSync(tmp, JSON.stringify({ ...lock, updatedAt: Date.now() }) + '\n', { mode: 0o600 })
  renameSync(tmp, path)
  return lock
}

export function genToken() {
  return randomBytes(32).toString('hex')
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

/** True if a process with this pid exists (signal 0 checks without signalling). */
export function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (e) {
    return !!e && e.code === 'EPERM' // exists, owned by someone else
  }
}

/** Who holds the launch lock: `{ pid, at, role }`, or null if nobody (or unreadable). */
export function launchLockHolder(path = LAUNCH_LOCK_FILE) {
  try {
    return JSON.parse(readFileSync(path, 'utf-8'))
  } catch {
    return null
  }
}

/**
 * Cross-process single-flight mutex via an O_EXCL lock file so two concurrent
 * hooks/plugins cannot both spawn a guard (the OS port-bind is only a backstop,
 * and that's a check-then-act window). A guard holds it too while it starts
 * (`role: 'daemon'`), until it has bound and registered.
 *
 * Steals a lock whose holder is gone so we never deadlock: a dead pid at once,
 * or a launcher's lock older than staleMs. A starting guard's lock is never
 * stolen while that guard is alive — its first policy fetch can outlast
 * staleMs, and stealing it is exactly how a second guard got launched.
 * Returns true iff WE now hold it.
 */
export function acquireFileLock(path = LAUNCH_LOCK_FILE, opts = {}) {
  const { staleMs = 10_000, now = () => Date.now(), role = 'launcher', alive = pidAlive } = opts
  try {
    mkdirSync(GUARD_DIR, { recursive: true, mode: 0o700 })
  } catch {
    /* best-effort */
  }
  try {
    const fd = openSync(path, 'wx') // O_CREAT | O_EXCL — fails EEXIST if held
    try {
      writeFileSync(fd, JSON.stringify({ pid: process.pid, at: now(), role }))
    } finally {
      closeSync(fd)
    }
    return true
  } catch (e) {
    if (!e || e.code !== 'EEXIST') return false
    try {
      const held = JSON.parse(readFileSync(path, 'utf-8'))
      const holderGone = held && Number.isInteger(held.pid) && !alive(held.pid)
      const launcherStale =
        held && held.role !== 'daemon' && typeof held.at === 'number' && now() - held.at > staleMs
      if (holderGone || launcherStale) {
        // Atomic steal: only ONE racer's rename of the stale lock wins; the
        // loser gets ENOENT and stays unlocked, so two processes can't both
        // believe they hold it (unlink+recreate would let both win).
        const stealing = `${path}.steal-${process.pid}-${randomBytes(4).toString('hex')}`
        try {
          renameSync(path, stealing)
        } catch {
          return false // another racer already stole/recreated it
        }
        try {
          unlinkSync(stealing)
        } catch {
          /* best-effort */
        }
        return acquireFileLock(path, opts) // recreate our own with O_EXCL
      }
    } catch {
      /* unreadable — treat as actively held */
    }
    return false
  }
}

export function releaseFileLock(path = LAUNCH_LOCK_FILE) {
  try {
    unlinkSync(path)
  } catch {
    /* already released */
  }
}

/** Release the launch lock only if this process holds it (it may have been stolen). */
export function releaseFileLockIfOurs(path = LAUNCH_LOCK_FILE) {
  const held = launchLockHolder(path)
  if (held && held.pid === process.pid) releaseFileLock(path)
}

/**
 * Blocking acquire: spin up to timeoutMs for the launch lock. `false` means we
 * gave up waiting and the caller proceeds best-effort (port-as-mutex backstop);
 * `true` means WE hold it and the caller must releaseFileLock() in finally.
 */
export async function defaultAcquireLock(opts = {}) {
  // 3s cap (not 8s): this blocks a per-call PreToolUse hook, and the host fails
  // the hook OPEN if it exceeds its timeout. Bounded so worst-case cold start
  // (stale-probe + acquire + recheck + launch) stays well under the hook budget;
  // port-as-mutex is the correctness backstop if we give up waiting and launch.
  const { timeoutMs = 3000, pollMs = 100, now = () => Date.now() } = opts
  const deadline = now() + timeoutMs
  for (;;) {
    if (acquireFileLock()) return true
    if (now() >= deadline) return false
    await sleep(pollMs)
  }
}

/** Dotted-numeric version compare: is `running` >= `required`? */
export function isCompatible(running, required) {
  if (!required) return true
  if (!running) return false
  const r = String(running).split('.').map((n) => parseInt(n, 10) || 0)
  const m = String(required).split('.').map((n) => parseInt(n, 10) || 0)
  const len = Math.max(r.length, m.length)
  for (let i = 0; i < len; i++) {
    const a = r[i] ?? 0
    const b = m[i] ?? 0
    if (a > b) return true
    if (a < b) return false
  }
  return true
}

/**
 * Real HTTP /health probe. Returns the guard's identity on success, else null.
 * Requires an explicit `ok === true` so a foreign server on the port is not
 * mistaken for our guard.
 */
export async function httpHealth(host, port, token, opts = {}) {
  const { timeoutMs = 1500, fetchImpl = fetch } = opts
  try {
    const res = await fetchImpl(`http://${host}:${port}/health`, {
      headers: token ? { authorization: `Bearer ${token}` } : {},
      signal: AbortSignal.timeout(timeoutMs),
    })
    if (!res.ok) return null
    const body = await res.json().catch(() => ({}))
    if (body && body.ok === true) {
      return {
        ok: true,
        service: body.service ?? null,
        version: body.version ?? null,
        instanceId: body.instanceId ?? null,
        // Whether the guard accepts the token we sent: true/false from a guard
        // that reports it, null from one that predates the field.
        authorized: typeof body.authorized === 'boolean' ? body.authorized : null,
      }
    }
    return null
  } catch {
    return null
  }
}

async function tryReuse(d, host, requiredVersion) {
  const lock = d.readLock()
  if (!lock || !lock.port) return null
  const h = await d.health(host, lock.port, lock.token)
  if (h && h.ok && isCompatible(h.version, requiredVersion)) {
    return { ...lock, version: h.version ?? lock.version ?? null, ok: true }
  }
  return null
}

// A guard names itself on /health without a token. One answering on any
// candidate port is the machine's guard, whatever its version and whether or
// not guard.json describes it, so nothing is launched beside it.
async function findGuard(d, host, ports) {
  for (const port of ports) {
    const h = await d.health(host, port)
    if (h && h.ok && h.service === 'vaibot-guard') return { port, health: h }
  }
  return null
}

function standDown(found, requiredVersion) {
  const { port, health } = found
  if (!isCompatible(health.version, requiredVersion)) {
    return {
      ok: false,
      status: 'incompatible',
      port,
      version: health.version ?? null,
      reason: `the running guard on port ${port} is ${health.version ?? 'an unknown version'}, below the required ${requiredVersion}; restart it to upgrade — not launching another`,
    }
  }
  return {
    ok: false,
    status: 'unregistered',
    port,
    version: health.version ?? null,
    reason: `a guard is running on port ${port} but guard.json does not describe it; restart it to re-register — not launching another`,
  }
}

/**
 * Idempotent discover-or-launch. Pure orchestration; inject deps to test.
 *
 * @param {{host?:string, requiredVersion?:string|null, candidatePorts?:number[], lockPath?:string}} opts
 * @param {{readLock?, writeLock?, health?, launch?, acquireLock?, releaseLock?, lockHolder?, alive?, genToken?, now?}} deps
 *   launch(host,port,token,{lockHeld}) resolves:
 *     { outcome:'launched', health:{ok,version}, pid? } | { outcome:'in-use' } | { outcome:'failed', error? }
 */
export async function ensureGuard(opts = {}, deps = {}) {
  const host = opts.host ?? DEFAULT_HOST
  const requiredVersion = opts.requiredVersion ?? null
  const candidatePorts = opts.candidatePorts ?? defaultCandidatePorts()
  const lockPath = opts.lockPath ?? LOCK_FILE

  const d = {
    readLock: deps.readLock ?? (() => readLock(lockPath)),
    writeLock: deps.writeLock ?? ((lock) => writeLock(lock, lockPath)),
    health: deps.health ?? ((h, p, t) => httpHealth(h, p, t)),
    launch: deps.launch,
    acquireLock: deps.acquireLock ?? (() => defaultAcquireLock()),
    releaseLock: deps.releaseLock ?? (async () => releaseFileLock()),
    lockHolder: deps.lockHolder ?? (() => launchLockHolder()),
    alive: deps.alive ?? pidAlive,
    genToken: deps.genToken ?? genToken,
    now: deps.now ?? (() => Date.now()),
  }

  // 1. Reuse an existing healthy guard.
  const existing = await tryReuse(d, host, requiredVersion)
  if (existing) return { ...existing, status: 'reused' }

  // 2. Single-flight launch.
  const acquired = await d.acquireLock()
  try {
    const recheck = await tryReuse(d, host, requiredVersion)
    if (recheck) return { ...recheck, status: 'reused' }

    // A guard that is still starting holds the launch lock. Adopt it: never
    // launch a second guard beside it, even if it has not bound a port yet.
    if (!acquired) {
      const holder = d.lockHolder()
      if (holder && holder.role === 'daemon' && d.alive(holder.pid)) {
        return {
          ok: false,
          status: 'starting',
          pid: holder.pid,
          reason: `a guard is starting (pid ${holder.pid}); not launching another`,
        }
      }
    }

    const running = await findGuard(d, host, candidatePorts)
    if (running) return standDown(running, requiredVersion)

    if (typeof d.launch !== 'function') {
      return { ok: false, status: 'no-launcher', reason: 'no guard running and no launcher provided' }
    }

    const token = d.genToken()
    for (const port of candidatePorts) {
      const res = await d.launch(host, port, token, { lockHeld: !!acquired })
      if (res && res.outcome === 'launched' && res.health && res.health.ok) {
        const lock = {
          version: res.health.version ?? null,
          host,
          port,
          token,
          pid: res.pid ?? null,
          startedAt: d.now(),
        }
        // The guard registers itself once it has bound, so the lock usually
        // already carries this token: leave it (the guard's own record is
        // richer). Never write over a live guard's record with another token —
        // that left every client holding a token the running guard never issued.
        const current = d.readLock()
        if (current && current.token !== token) {
          const other = await tryReuse(d, host, requiredVersion)
          if (other) return { ...other, status: 'reused' }
        }
        if (!current || current.token !== token) d.writeLock(lock)
        return { ...lock, ok: true, status: 'launched' }
      }
      if (res && res.outcome === 'in-use') {
        // Port-as-mutex: something is already bound. Is it OUR guard?
        const existingLock = d.readLock()
        const probeToken = existingLock && existingLock.port === port ? existingLock.token : undefined
        const h = await d.health(host, port, probeToken)
        if (h && h.ok && isCompatible(h.version, requiredVersion) && existingLock && existingLock.port === port) {
          return { ...existingLock, version: h.version ?? existingLock.version ?? null, ok: true, status: 'reused' }
        }
        // A guard bound it after the scan above: it wins.
        if (h && h.ok && h.service === 'vaibot-guard') return standDown({ port, health: h }, requiredVersion)
        // Not a guard — try the next candidate port.
        continue
      }
      // outcome 'failed' — try the next port.
    }
    return { ok: false, status: 'launch-failed', reason: 'no candidate port yielded a healthy guard' }
  } finally {
    if (acquired) await d.releaseLock()
  }
}

/**
 * Read machine-wide containment state. Absent or unreadable => not engaged, so
 * a machine that has never been contained behaves normally.
 *
 * @returns {{contained: boolean, at: string|null, reason: string|null}}
 */
export function readContainment(file = CONTAINMENT_FILE) {
  try {
    const raw = JSON.parse(readFileSync(file, 'utf-8'))
    return {
      contained: raw?.contained === true,
      at: typeof raw?.at === 'string' ? raw.at : null,
      reason: typeof raw?.reason === 'string' ? raw.reason : null,
    }
  } catch {
    return { contained: false, at: null, reason: null }
  }
}

/**
 * Record containment state for every breaker on this machine. Atomic, 0600.
 * Best-effort: the in-process flag is what gates the daemon's own decisions,
 * and a breaker that cannot read the file falls back to asking the daemon.
 */
export function writeContainment(contained, reason = null, file = CONTAINMENT_FILE) {
  try {
    // The directory of the file we were GIVEN — not the default one. They
    // coincide in production and diverge in tests, which is how this was found.
    mkdirSync(dirname(file), { recursive: true })
    const tmp = file + '.tmp'
    writeFileSync(tmp, JSON.stringify({ contained: !!contained, reason: reason ?? null, at: new Date().toISOString() }), { mode: 0o600 })
    renameSync(tmp, file)
    try { chmodSync(file, 0o600) } catch { /* best effort */ }
    return true
  } catch {
    return false
  }
}
