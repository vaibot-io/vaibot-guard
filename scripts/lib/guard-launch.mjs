// @vaibot/shared — real launch dep + default wiring for ensureGuard.
//
// Provides the process-spawning half of the guard bootstrapper: a TCP probe to
// detect an occupied port (port-as-mutex) and a launcher that spawns the guard
// service detached, waits for /health, and reports launched|in-use|failed in
// the shape ensureGuard() expects. ensureGuardDefault() wires it together with
// the real httpHealth + fs lock I/O from guard-bootstrap.
//
// Plain ESM so the guard + vendored hook copies can use it at runtime.

import { spawn } from 'node:child_process'
import net from 'node:net'
import { openSync, mkdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { ensureGuard, httpHealth, defaultCandidatePorts } from './guard-bootstrap.mjs'
import { readGuardEndpoint, writeGuardEndpoint } from './creds.mjs'

// Where the daemon's own boot stdout/stderr is tee'd, so a spawn that never turns
// healthy leaves a diagnosable trail instead of failing silently.
export const LAUNCH_LOG = join(homedir(), '.vaibot', 'guard', 'launch.log')

function openLaunchLog() {
  try {
    mkdirSync(join(homedir(), '.vaibot', 'guard'), { recursive: true, mode: 0o700 })
    return openSync(LAUNCH_LOG, 'a', 0o600)
  } catch {
    return null // best-effort — never block a spawn on logging
  }
}

/** Resolve true if something is already listening on host:port. */
export function tcpProbe(host, port, opts = {}) {
  const { timeoutMs = 600 } = opts
  return new Promise((resolve) => {
    let done = false
    const finish = (v) => {
      if (done) return
      done = true
      try {
        sock.destroy()
      } catch {
        /* ignore */
      }
      resolve(v)
    }
    const sock = net.createConnection({ host, port })
    sock.setTimeout(timeoutMs)
    sock.once('connect', () => finish(true))
    sock.once('timeout', () => finish(false))
    sock.once('error', () => finish(false))
  })
}

/**
 * Build a launch(host, port, token) for ensureGuard that spawns the guard
 * service script detached and waits for /health from THAT guard.
 *   - port already occupied → { outcome: 'in-use' } (ensureGuard identity-checks)
 *   - became healthy        → { outcome: 'launched', health, pid }
 *   - never healthy / error  → { outcome: 'failed', error }
 *
 * "That guard" is checked, not assumed: /health must accept the token we gave
 * the child. Another guard that bound the port first (one already starting
 * when we probed) answers /health too, but with its own token, and our child
 * exits on EADDRINUSE. Taking that answer as success is how a launcher once
 * wrote its unused token into the lock beside a running guard.
 */
export function makeLauncher(cfg = {}) {
  // 10s default cold-start budget (was 4s): a fresh machine's first spawn pays
  // module load + policy-bundle fetch + bind; 4s races that and reports a false
  // "failed". Override via cfg.healthTimeoutMs.
  const { guardScript, baseEnv = {}, healthTimeoutMs = 10000, pollMs = 150 } = cfg
  return async function launch(host, port, token, ctx = {}) {
    if (await tcpProbe(host, port)) return { outcome: 'in-use' }

    // Tee the daemon's own stdout/stderr to ~/.vaibot/guard/launch.log so a boot
    // that never turns healthy is diagnosable instead of silently swallowed.
    const logFd = openLaunchLog()
    const childStdio = logFd == null ? 'ignore' : ['ignore', logFd, logFd]

    let child
    try {
      child = spawn(process.execPath, [guardScript], {
        env: {
          ...process.env,
          ...baseEnv,
          VAIBOT_GUARD_HOST: host,
          VAIBOT_GUARD_PORT: String(port),
          VAIBOT_GUARD_TOKEN: token,
          // We hold the launch lock on the child's behalf; it must not wait on it.
          ...(ctx.lockHeld ? { VAIBOT_GUARD_LAUNCH_LOCK_HELD: '1' } : {}),
        },
        detached: true,
        stdio: childStdio,
      })
      child.unref()
    } catch (error) {
      return { outcome: 'failed', error }
    }
    let exited = false
    child.once('exit', () => {
      exited = true
    })

    const deadline = Date.now() + healthTimeoutMs
    while (Date.now() < deadline) {
      const h = await httpHealth(host, port, token, { timeoutMs: 800 })
      if (h && h.ok && h.authorized === true) return { outcome: 'launched', health: h, pid: child.pid }
      // Someone else's guard is on the port: ours lost the bind (or soon will).
      if ((h && h.ok && h.authorized === false) || exited) {
        try {
          if (!exited && child.pid) process.kill(child.pid)
        } catch {
          /* ignore */
        }
        return (await tcpProbe(host, port))
          ? { outcome: 'in-use' }
          : { outcome: 'failed', error: new Error(`guard exited before becoming healthy — see ${LAUNCH_LOG}`) }
      }
      await new Promise((r) => setTimeout(r, pollMs))
    }
    try {
      if (child.pid) process.kill(child.pid)
    } catch {
      /* ignore */
    }
    return {
      outcome: 'failed',
      error: new Error(`guard did not become healthy within ${healthTimeoutMs}ms — see ${LAUNCH_LOG}`),
    }
  }
}

/**
 * ensureGuard with real defaults: httpHealth + fs lock I/O (from
 * guard-bootstrap) + a spawning launcher. `opts.guardScript` is the path to
 * vaibot-guard-service.mjs; `opts.guardEnv` supplies the guard's runtime env
 * (workspace, log dir, policy path, API creds, etc.).
 */
export async function ensureGuardDefault(opts = {}) {
  const launch = makeLauncher({
    guardScript: opts.guardScript,
    baseEnv: opts.guardEnv,
    healthTimeoutMs: opts.healthTimeoutMs,
    pollMs: opts.pollMs,
  })
  // Port-as-data: prefer the persisted (assigned) port so a restart reuses it,
  // then fall back to the default scan — best-effort, no hardcoded contract.
  let assigned = null
  try { assigned = readGuardEndpoint() } catch { /* best-effort */ }
  let candidatePorts = opts.candidatePorts
  if (assigned && Number.isInteger(assigned.port)) {
    const base = candidatePorts ?? defaultCandidatePorts()
    candidatePorts = [assigned.port, ...base.filter((p) => p !== assigned.port)]
  }

  const r = await ensureGuard({ ...opts, candidatePorts }, { launch })

  // Persist the resolved endpoint (only when it changed) so the port is remembered
  // + discoverable via credentials.json — never a hardcoded default.
  if (r && r.ok && Number.isInteger(r.port) && (r.port !== assigned?.port || r.token !== assigned?.token)) {
    try { writeGuardEndpoint({ host: r.host, port: r.port, token: r.token }) } catch { /* best-effort */ }
  }
  return r
}
