// Type declarations for guard-bootstrap.mjs — idempotent discover-or-launch
// of the shared local guard daemon. Hand-written to pair with the ESM source.

export const GUARD_DIR: string
export const LOCK_FILE: string
export const LAUNCH_LOCK_FILE: string
export const CONTAINMENT_FILE: string
export const DEFAULT_HOST: '127.0.0.1'
export const DEFAULT_PORT: 39111
export const PORT_SCAN_COUNT: 10

export interface GuardLock {
  version: string | null
  host: string
  port: number
  token: string
  pid?: number | null
  startedAt?: number
  updatedAt?: number
}

export interface GuardHealth {
  ok: boolean
  /** `"vaibot-guard"` from a guard; how a launcher recognises one without its token. */
  service?: string | null
  version: string | null
  instanceId?: string | null
  /** Whether the guard accepts the token sent; null from a guard that predates the field. */
  authorized?: boolean | null
}

/** Who holds the launch lock. A starting guard holds it as `daemon`. */
export interface LaunchLockHolder {
  pid: number
  at: number
  role?: 'launcher' | 'daemon'
}

export type LaunchResult =
  | { outcome: 'launched'; health: GuardHealth; pid?: number | null }
  | { outcome: 'in-use' }
  | { outcome: 'failed'; error?: unknown }

export interface EnsureGuardOpts {
  host?: string
  requiredVersion?: string | null
  candidatePorts?: number[]
  lockPath?: string
}

export interface EnsureGuardDeps {
  readLock?: () => GuardLock | null
  writeLock?: (lock: GuardLock) => GuardLock
  health?: (host: string, port: number, token?: string) => Promise<GuardHealth | null>
  launch?: (host: string, port: number, token: string, ctx?: { lockHeld: boolean }) => Promise<LaunchResult>
  acquireLock?: () => Promise<boolean>
  releaseLock?: () => Promise<void>
  lockHolder?: () => LaunchLockHolder | null
  alive?: (pid: number) => boolean
  genToken?: () => string
  now?: () => number
}

export type EnsureGuardResult =
  | (GuardLock & { ok: true; status: 'reused' | 'launched' })
  | { ok: false; status: 'no-launcher' | 'launch-failed'; reason: string }
  /** A guard is starting and holds the launch lock: adopt it, launch nothing. */
  | { ok: false; status: 'starting'; pid: number; reason: string }
  /**
   * A guard is running on a candidate port but guard.json does not describe
   * it, or it is older than required. It wins: nothing is launched beside it.
   */
  | { ok: false; status: 'unregistered' | 'incompatible'; port: number; version: string | null; reason: string }

/** Machine-wide containment state, as the guard writes it. */
export interface Containment {
  /** True only for a literal `true` in the record; anything else is not engaged. */
  contained: boolean
  /** ISO-8601, when it was engaged. */
  at: string | null
  /** Why it was engaged, when the control plane sent a reason. */
  reason: string | null
}

export function defaultCandidatePorts(base?: number, count?: number): number[]
export function readLock(path?: string): GuardLock | null
export function writeLock(lock: GuardLock, path?: string, dir?: string): GuardLock
export function genToken(): string

/**
 * Read machine-wide containment. Absent or unreadable means NOT engaged, so this
 * never raises and never fails into containment.
 */
export function readContainment(file?: string): Containment
/** Record containment for every breaker on the machine. Atomic, 0600, best-effort. */
export function writeContainment(contained: boolean, reason?: string | null, file?: string): boolean

/** True if a process with this pid exists. */
export function pidAlive(pid: number): boolean
/** Who holds the launch lock, or null. */
export function launchLockHolder(path?: string): LaunchLockHolder | null
/**
 * Cross-process single-flight mutex via an O_EXCL lock file. True iff WE hold it.
 * A live guard's (`daemon`) lock is never stolen; a dead holder's always is.
 */
export function acquireFileLock(
  path?: string,
  opts?: { staleMs?: number; now?: () => number; role?: 'launcher' | 'daemon'; alive?: (pid: number) => boolean },
): boolean
export function releaseFileLock(path?: string): void
/** Release the launch lock only if this process holds it. */
export function releaseFileLockIfOurs(path?: string): void
/** Blocking acquire; false means we gave up waiting and the caller proceeds best-effort. */
export function defaultAcquireLock(
  opts?: { timeoutMs?: number; pollMs?: number; now?: () => number },
): Promise<boolean>
export function isCompatible(running: string | null | undefined, required: string | null | undefined): boolean
export function httpHealth(
  host: string,
  port: number,
  token?: string,
  opts?: { timeoutMs?: number; fetchImpl?: typeof fetch },
): Promise<GuardHealth | null>
export function ensureGuard(opts?: EnsureGuardOpts, deps?: EnsureGuardDeps): Promise<EnsureGuardResult>
