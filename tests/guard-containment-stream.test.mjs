import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { reservePort } from "./lib/free-port.mjs";

// Containment reaches the guard by being PUSHED. The /me poll is a five-minute
// reconciliation floor, not the latency path — an arm that takes five minutes
// to arrive is not a panic switch.
//
// These tests stand up a fake control plane that speaks the real SSE shape and
// assert on what the guard actually enforces afterwards.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_PATH = path.resolve(__dirname, "..", "scripts", "vaibot-guard-service.mjs");
const POLICY_PATH = path.resolve(__dirname, "..", "references", "policy.default.json");

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "vaibot-contain-"));
const servers = [];
const guards = [];

/** A control plane that serves /v2/accounts/me and the containment stream. */
function startControlPlane() {
  const clients = new Set();
  const receipts = [];
  let contained = false;

  const server = createServer((req, res) => {
    if (req.url.startsWith("/v2/accounts/me")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, admin: false, enforcement: { effective_mode: "enforce", contained } }));
      return;
    }
    if (req.url === "/v2/receipts" && req.method === "POST") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        try { receipts.push(JSON.parse(body)); } catch { /* ignore */ }
        res.writeHead(201, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
      });
      return;
    }
    if (req.url.startsWith("/v2/enforcement/stream")) {
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
      // Current state on connect: a reconnect is its own resync.
      res.write(`event: containment\ndata: ${JSON.stringify({ contained, snapshot: true })}\n\n`);
      clients.add(res);
      req.on("close", () => clients.delete(res));
      return;
    }
    res.writeHead(404);
    res.end("{}");
  });

  servers.push(server);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () =>
      resolve({
        base: `http://127.0.0.1:${server.address().port}`,
        push(next) {
          contained = next;
          for (const res of clients) res.write(`event: containment\ndata: ${JSON.stringify({ contained: next, snapshot: false })}\n\n`);
        },
        get clientCount() { return clients.size; },
        get receipts() { return receipts; },
        dropAll() { for (const res of clients) { try { res.end(); } catch { /* ignore */ } } clients.clear(); },
      }),
    );
  });
}

// The containment stream talks to the CANONICAL governance base, never an
// overridable one — the same anti-spoofing rule the mode poll follows, so a
// VAIBOT_GOVERNANCE_URL override cannot point a guard at a control plane that
// simply never sends an arm. Redirecting it therefore means writing real
// credentials (v3 store), not setting an env var.
function writeCreds(home, base) {
  const dir = path.join(home, ".vaibot");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, "credentials.json"),
    JSON.stringify({
      version: 3,
      active_env: "staging",
      environments: {
        staging: { api_key: "vbk_test_key", governance: { url: base }, provenance: { url: null } },
      },
    }),
  );
}

async function startGuard({ base, logDir, label, home: sharedHome }) {
  const port = await reservePort();
  fs.mkdirSync(logDir, { recursive: true });
  // A shared HOME models one machine: containment now lives in
  // ~/.vaibot/guard/containment.json, read by every breaker on the box.
  const home = sharedHome ?? fs.mkdtempSync(path.join(tmpRoot, `home-${label}-`));
  writeCreds(home, base);
  const proc = spawn(process.execPath, [SERVICE_PATH], {
    env: {
      ...process.env,
      HOME: home, // never touch the developer's live rendezvous lock
      VAIBOT_GUARD_HOST: "127.0.0.1",
      VAIBOT_GUARD_PORT: String(port),
      VAIBOT_GUARD_TOKEN: `tok-${label}`,
      VAIBOT_POLICY_PATH: POLICY_PATH,
      VAIBOT_WORKSPACE: tmpRoot,
      VAIBOT_GUARD_LOG_DIR: logDir,
      VAIBOT_PROVE_MODE: "off",
      VAIBOT_POLICY_URL: "off",
      VAIBOT_ENV: "staging",
      VAIBOT_API_KEY: "vbk_test_key",
      VAIBOT_GOVERNANCE_URL: base,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  guards.push(proc);

  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/health`);
      if (r.ok) return { port, proc, home };
    } catch { /* not up yet */ }
    await delay(100);
  }
  throw new Error("guard did not become healthy");
}

const decide = (port, label) =>
  fetch(`http://127.0.0.1:${port}/v1/decide/tool`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer tok-${label}` },
    body: JSON.stringify({ sessionId: "s1", toolName: "Read", params: {}, workspaceDir: tmpRoot }),
  }).then((r) => r.json());

async function waitUntil(fn, { timeoutMs = 5000, intervalMs = 50 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await fn()) return true;
    await delay(intervalMs);
  }
  return false;
}

test("an arm pushed over the stream denies the very next action", async () => {
  const cp = await startControlPlane();
  const { port } = await startGuard({ base: cp.base, logDir: path.join(tmpRoot, "push"), label: "push" });

  // Whatever policy says about a benign read, it is not a containment deny.
  const before = await decide(port, "push");
  assert.ok(!/containment/i.test(before.decision.reason || ""), "not contained to begin with");
  assert.equal(before.contained, false);

  assert.equal(await waitUntil(() => cp.clientCount > 0), true, "guard should connect to the stream");
  cp.push(true);

  const denied = await waitUntil(async () => /containment/i.test((await decide(port, "push")).decision.reason || ""));
  assert.equal(denied, true, "containment should arrive over the stream, not at the next poll");

  const d = await decide(port, "push");
  assert.equal(d.decision.decision, "deny");
  assert.match(d.decision.reason, /containment/i);
  assert.equal(d.contained, true);
});

test("a release pushed over the stream restores normal decisions", async () => {
  const cp = await startControlPlane();
  const { port } = await startGuard({ base: cp.base, logDir: path.join(tmpRoot, "release"), label: "release" });
  assert.equal(await waitUntil(() => cp.clientCount > 0), true);

  cp.push(true);
  assert.equal(await waitUntil(async () => (await decide(port, "release")).contained === true), true);

  cp.push(false);
  assert.equal(await waitUntil(async () => (await decide(port, "release")).contained === false), true);
  const after = await decide(port, "release");
  assert.ok(!/containment/i.test(after.decision.reason || ""), "normal decisions resume");
});

test("containment survives a restart — a contained machine does not come back permissive", async () => {
  const cp = await startControlPlane();
  const logDir = path.join(tmpRoot, "restart");
  const first = await startGuard({ base: cp.base, logDir, label: "restart" });
  assert.equal(await waitUntil(() => cp.clientCount > 0), true);

  cp.push(true);
  assert.equal(await waitUntil(async () => (await decide(first.port, "restart")).contained === true), true);

  // The process goes away with containment in force.
  first.proc.kill("SIGTERM");
  await delay(300);

  // It comes back with the control plane UNREACHABLE, so only the local marker
  // can tell it what was true — same machine, same HOME.
  const offline = await startGuard({ base: "http://127.0.0.1:1", logDir, label: "restart2", home: first.home });
  const d = await decide(offline.port, "restart2");
  assert.equal(d.decision.decision, "deny", "a restart must not clear containment");
  assert.equal(d.contained, true);
});

test("losing the stream never lifts containment", async () => {
  const cp = await startControlPlane();
  const { port } = await startGuard({ base: cp.base, logDir: path.join(tmpRoot, "drop"), label: "drop" });
  assert.equal(await waitUntil(() => cp.clientCount > 0), true);

  cp.push(true);
  assert.equal(await waitUntil(async () => (await decide(port, "drop")).contained === true), true);

  // The stream goes away under the guard.
  cp.dropAll();
  await delay(600);

  assert.equal((await decide(port, "drop")).decision.decision, "deny", "fail-static: a dropped stream keeps the last known state");
});

test("a contained action is RECORDED — an incident must not be invisible", async () => {
  const cp = await startControlPlane();
  const { port } = await startGuard({ base: cp.base, logDir: path.join(tmpRoot, "receipt"), label: "receipt" });
  assert.equal(await waitUntil(() => cp.clientCount > 0), true);

  cp.push(true);
  assert.equal(await waitUntil(async () => (await decide(port, "receipt")).contained === true), true);

  const before = cp.receipts.length;
  await decide(port, "receipt"); // denied by containment — the tool never runs, so no finalize ever fires

  const got = await waitUntil(() => cp.receipts.length > before);
  assert.equal(got, true, "a containment deny must reach the control plane on its own");

  const r = cp.receipts[cp.receipts.length - 1];
  assert.equal(r.policy.decision, "deny");
  assert.match(r.policy.reason, /containment/i);
  assert.equal(r.result.outcome, "blocked");
  assert.equal(r.approval.status, "not_required");
});

test.after(async () => {
  for (const g of guards) if (!g.killed) g.kill("SIGTERM");
  for (const s of servers) { try { s.close(); } catch { /* best effort */ } }
  await delay(150);
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch { /* best effort */ }
});
