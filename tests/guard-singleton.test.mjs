import test, { after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { reservePort } from "./lib/free-port.mjs";

// One guard per machine. A guard that finds another one registered and
// answering adopts it and exits 0 without touching guard.json; a guard that is
// still starting holds the launch lock, so a plugin launcher waits for it
// instead of launching a second; and a launcher only believes /health from the
// guard it started (the one that accepts its token).
//
// Hermetic: this process and every guard it starts use a temp HOME, so nothing
// here can reach the developer's live rendezvous lock.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_PATH = path.resolve(__dirname, "..", "scripts", "vaibot-guard-service.mjs");
const POLICY_PATH = path.resolve(__dirname, "..", "references", "policy.default.json");

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "vaibot-guard-singleton-"));
process.env.HOME = path.join(tmpRoot, "self-home");
fs.mkdirSync(process.env.HOME, { recursive: true });

const bootstrap = await import("../scripts/lib/guard-bootstrap.mjs");
const { makeLauncher } = await import("../scripts/lib/guard-launch.mjs");
const { ensureGuard, acquireFileLock, launchLockHolder } = bootstrap;

/* ───────────── ensureGuard (injected deps) ───────────── */

function deps(over = {}) {
  const calls = { launch: 0, writes: [] };
  return {
    calls,
    d: {
      readLock: () => null,
      writeLock: (l) => (calls.writes.push(l), l),
      health: async () => null,
      acquireLock: async () => true,
      releaseLock: async () => {},
      lockHolder: () => null,
      alive: () => true,
      genToken: () => "tok-new",
      launch: async () => {
        calls.launch++;
        return { outcome: "launched", health: { ok: true, version: "2.4.0", authorized: true }, pid: 4242 };
      },
      ...over,
    },
  };
}

test("a guard still starting is adopted: nothing is launched", async () => {
  const { calls, d } = deps({
    acquireLock: async () => false,
    lockHolder: () => ({ pid: 777, at: 0, role: "daemon" }),
  });
  const r = await ensureGuard({ candidatePorts: [1] }, d);
  assert.equal(r.status, "starting");
  assert.equal(r.pid, 777);
  assert.equal(calls.launch, 0);
  assert.equal(calls.writes.length, 0);
});

test("a dead starting guard does not block a launch", async () => {
  const { calls, d } = deps({
    acquireLock: async () => false,
    lockHolder: () => ({ pid: 777, at: 0, role: "daemon" }),
    alive: () => false,
  });
  const r = await ensureGuard({ candidatePorts: [1] }, d);
  assert.equal(r.status, "launched");
  assert.equal(calls.launch, 1);
});

test("after a launch, the guard's own registration is left alone", async () => {
  const own = { host: "127.0.0.1", port: 1, token: "tok-new", pid: 4242, instanceId: "x", effective_mode: "enforce" };
  const { calls, d } = deps({ readLock: (() => { let n = 0; return () => (n++ === 0 ? null : own); })() });
  const r = await ensureGuard({ candidatePorts: [1] }, d);
  assert.equal(r.status, "launched");
  assert.equal(calls.writes.length, 0, "the guard registered itself; a poorer copy must not replace it");
});

test("a launch never writes over a running guard's token", async () => {
  const other = { host: "127.0.0.1", port: 1, token: "tok-running", pid: 99, version: "2.4.0" };
  const { calls, d } = deps({
    readLock: (() => { let n = 0; return () => (n++ < 2 ? null : other); })(),
    health: async (_h, _p, t) => (t === "tok-running" ? { ok: true, version: "2.4.0" } : null),
  });
  const r = await ensureGuard({ candidatePorts: [1] }, d);
  assert.equal(r.status, "reused");
  assert.equal(r.token, "tok-running");
  assert.equal(calls.writes.length, 0);
});

test("a launch with no registration yet writes one", async () => {
  const { calls, d } = deps();
  await ensureGuard({ candidatePorts: [1] }, d);
  assert.equal(calls.writes.length, 1);
  assert.equal(calls.writes[0].token, "tok-new");
});

/* ───────────── the launch lock ───────────── */

test("a live starting guard's lock is never stolen; a dead one's always is", () => {
  const p = path.join(tmpRoot, "launch-a.lock");
  fs.writeFileSync(p, JSON.stringify({ pid: 123, at: 0, role: "daemon" }));
  assert.equal(acquireFileLock(p, { alive: () => true }), false, "old but alive: still starting");
  assert.equal(acquireFileLock(p, { alive: () => false }), true, "holder gone");
  assert.equal(launchLockHolder(p).pid, process.pid);
  assert.equal(launchLockHolder(p).role, "launcher");
});

test("a launcher's stale lock is stolen even if its pid is alive", () => {
  const p = path.join(tmpRoot, "launch-b.lock");
  fs.writeFileSync(p, JSON.stringify({ pid: 123, at: 0, role: "launcher" }));
  assert.equal(acquireFileLock(p, { alive: () => true, now: () => 60_000 }), true);
});

/* ───────────── real guards ───────────── */

function guardEnv(home, port, token, extra = {}) {
  const logDir = fs.mkdtempSync(path.join(tmpRoot, "log-"));
  return {
    ...process.env,
    HOME: home,
    VAIBOT_GUARD_HOST: "127.0.0.1",
    VAIBOT_GUARD_PORT: String(port),
    VAIBOT_GUARD_TOKEN: token,
    VAIBOT_POLICY_PATH: POLICY_PATH,
    VAIBOT_WORKSPACE: tmpRoot,
    VAIBOT_GUARD_LOG_DIR: logDir,
    VAIBOT_PROVE_MODE: "off",
    VAIBOT_POLICY_URL: "off",
    ...extra,
  };
}

function start(env) {
  const child = spawn(process.execPath, [SERVICE_PATH], { env, stdio: ["ignore", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (b) => (stderr += b));
  const exited = new Promise((resolve) => child.once("exit", (code) => resolve(code)));
  // The exit code, or "running" — then it is shut down, so a regression that
  // lets a second guard run fails here instead of hanging the file.
  const exitCode = async (ms = 8000) => {
    const code = await Promise.race([exited, delay(ms).then(() => "running")]);
    if (code === "running") child.kill("SIGTERM");
    return code;
  };
  return { child, exited, exitCode, stderr: () => stderr };
}

async function healthy(port) {
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/health`);
      if (res.ok) return true;
    } catch {
      /* not yet */
    }
    await delay(100);
  }
  return false;
}

const homeA = fs.mkdtempSync(path.join(tmpRoot, "home-"));
const portA = await reservePort();
const guardA = start(guardEnv(homeA, portA, "token-A"));
const lockFile = path.join(homeA, ".vaibot", "guard", "guard.json");
after(() => guardA.child.kill("SIGTERM"));
assert.equal(await healthy(portA), true, "guard A should start");

test("/health says whether the caller's token is this guard's", async () => {
  const get = async (auth) =>
    (await fetch(`http://127.0.0.1:${portA}/health`, auth ? { headers: { authorization: `Bearer ${auth}` } } : {})).json();
  assert.equal((await get("token-A")).authorized, true);
  assert.equal((await get("token-B")).authorized, false);
  assert.equal("authorized" in (await get()), false);
});

test("a second guard adopts the running one and leaves its registration alone", async () => {
  const before = fs.readFileSync(lockFile, "utf8");
  const b = start(guardEnv(homeA, await reservePort(), "token-B"));
  assert.equal(await b.exitCode(), 0);
  assert.match(b.stderr(), /adopting it — not starting a second guard/);
  assert.equal(fs.readFileSync(lockFile, "utf8"), before);
  assert.equal(JSON.parse(before).token, "token-A");
});

test("a guard that loses the bind to a running guard adopts it without registering", async () => {
  const before = fs.readFileSync(lockFile, "utf8");
  fs.rmSync(lockFile); // as if A had not registered yet
  try {
    const c = start(guardEnv(homeA, portA, "token-C", { VAIBOT_GUARD_LAUNCH_LOCK_HELD: "1" }));
    assert.equal(await c.exitCode(), 0);
    assert.match(c.stderr(), /adopting it/);
    assert.equal(fs.existsSync(lockFile), false, "the losing guard must not register itself");
  } finally {
    fs.writeFileSync(lockFile, before);
  }
});

test("a guard still starting makes another one adopt it", async () => {
  const home = fs.mkdtempSync(path.join(tmpRoot, "home-"));
  fs.mkdirSync(path.join(home, ".vaibot", "guard"), { recursive: true });
  // Guard A's pid stands in for a live guard that has not bound yet.
  fs.writeFileSync(
    path.join(home, ".vaibot", "guard", "launch.lock"),
    JSON.stringify({ pid: guardA.child.pid, at: Date.now(), role: "daemon" }),
  );
  const d = start(guardEnv(home, await reservePort(), "token-D"));
  assert.equal(await d.exitCode(), 0);
  assert.match(d.stderr(), /another guard is starting/);
});

/* ───────────── the launcher believes only its own guard ───────────── */

function stub(name, body) {
  const p = path.join(tmpRoot, name);
  fs.writeFileSync(p, body);
  return p;
}

test("a guard answering /health that refuses our token is not taken as ours", async () => {
  // The child is a server that answers like a guard holding another token.
  const script = stub(
    "other-guard.mjs",
    `import http from "node:http";
     http.createServer((q, s) => { s.setHeader("content-type", "application/json");
       s.end(JSON.stringify({ ok: true, service: "vaibot-guard", version: "2.4.0", authorized: false })); })
       .listen(Number(process.env.VAIBOT_GUARD_PORT), "127.0.0.1");`,
  );
  const port = await reservePort();
  const r = await makeLauncher({ guardScript: script, healthTimeoutMs: 5000 })("127.0.0.1", port, "tok");
  assert.equal(r.outcome, "in-use");
});

test("a child that exits is reported at once, not after the health timeout", async () => {
  const script = stub("exits.mjs", "process.exitCode = 1;");
  const port = await reservePort();
  const t0 = Date.now();
  const r = await makeLauncher({ guardScript: script, healthTimeoutMs: 8000 })("127.0.0.1", port, "tok");
  assert.equal(r.outcome, "failed");
  assert.ok(Date.now() - t0 < 4000, "should not wait out the timeout");
});

test("the guard it started is accepted", async () => {
  const port = await reservePort();
  const home = fs.mkdtempSync(path.join(tmpRoot, "home-"));
  const env = guardEnv(home, port, "unused");
  delete env.VAIBOT_GUARD_TOKEN;
  delete env.VAIBOT_GUARD_PORT;
  const r = await makeLauncher({ guardScript: SERVICE_PATH, baseEnv: env, healthTimeoutMs: 8000 })("127.0.0.1", port, "tok-own");
  try {
    assert.equal(r.outcome, "launched");
    assert.equal(r.health.authorized, true);
  } finally {
    if (r.pid) process.kill(r.pid, "SIGTERM");
  }
});

