import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { reservePort } from "./lib/free-port.mjs";

// Phase 0 — Tier-0 containment switch. Armed ONLY by the guard adopting
// `enforcement.contained` from its /v2/accounts/me poll — there is deliberately NO local
// env/file lever (that would be an escape hatch an adversarial agent could reach). This spec
// drives arming through a MOCK control plane, and asserts a stray VAIBOT_CONTAIN env is ignored.
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_PATH = path.resolve(__dirname, "..", "scripts", "vaibot-guard-service.mjs");
const POLICY_PATH = path.resolve(__dirname, "..", "references", "policy.default.json");
const HOST = "127.0.0.1";

// Mock control plane — the single source of the containment flag.
let contained = false;
const mock = http.createServer((req, res) => {
  if (req.url === "/v2/accounts/me") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ admin: false, enforcement: { effective_mode: "enforce", contained } }));
    return;
  }
  res.writeHead(404, { "content-type": "application/json" });
  res.end('{"ok":false}');
});
const MOCK_PORT = await new Promise((r) => mock.listen(0, HOST, () => r(mock.address().port)));
mock.unref();

const servers = [];
process.on("exit", () => {
  for (const s of servers) { try { s.kill("SIGKILL"); } catch { /* gone */ } }
  try { mock.close(); } catch { /* closed */ }
});

async function startGuard(extraEnv = {}) {
  const port = await reservePort();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "vaibot-guard-contain-"));
  const home = path.join(root, "home");
  const credsDir = path.join(root, "creds");
  const logDir = path.join(root, ".vaibot-guard");
  for (const d of [home, credsDir, logDir]) fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(root, "notes.txt"), "hi\n");
  // Seed creds so the guard's canonical governance base points at the mock control plane.
  fs.writeFileSync(path.join(credsDir, "credentials.json"), JSON.stringify({
    version: 3, active_env: "staging",
    environments: { staging: { api_key: "vb_stg_test", wallet_address: "0x0", governance: { url: `http://${HOST}:${MOCK_PORT}` }, provenance: { url: null } } },
  }));
  const env = {
    PATH: process.env.PATH, HOME: home,
    VAIBOT_ENV: "staging", VAIBOT_CREDS_DIR: credsDir,
    VAIBOT_GUARD_HOST: HOST, VAIBOT_GUARD_PORT: String(port),
    VAIBOT_WORKSPACE: root, VAIBOT_GUARD_LOG_DIR: logDir,
    VAIBOT_POLICY_URL: "off", VAIBOT_PROVE_MODE: "off",
    VAIBOT_POLICY_PATH: POLICY_PATH,
    VAIBOT_POLICY_BUNDLE_PATH: path.join(root, "no.bundle.json"),
    VAIBOT_MODE_REFRESH_MS: "60000",
    ...extraEnv,
  };
  const srv = spawn(process.execPath, [SERVICE_PATH], { env, stdio: ["ignore", "ignore", "ignore"] });
  srv.unref(); // don't keep node:test's loop alive
  servers.push(srv);
  for (let i = 0; i < 60; i++) {
    try { const r = await fetch(`http://${HOST}:${port}/health`); if (r.ok) break; } catch { /* not up */ }
    await delay(100);
  }
  const post = async (p, body) => (await fetch(`http://${HOST}:${port}${p}`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body || {}),
  })).json().catch(() => ({}));
  const health = async () => (await fetch(`http://${HOST}:${port}/health`)).json();
  const forceRefresh = () => post("/v1/mode/refresh", {}); // deterministic re-poll of the mock
  return { port, root, post, health, forceRefresh };
}

const main = await startGuard();
assert.equal((await main.health()).ok, true, "guard service should start");

const matrix = (ws) => [
  { label: "read in-ws", p: "/v1/decide/tool", body: { sessionId: "c", toolName: "Read", params: { file_path: path.join(ws, "notes.txt") } } },
  { label: "safe exec", p: "/v1/decide/exec", body: { sessionId: "c", cmd: "echo", args: ["hi"], intent: { tool: "exec", action: "run", command: "echo hi", cwd: ws } } },
  { label: "write in-ws", p: "/v1/decide/tool", body: { sessionId: "c", toolName: "Write", params: { file_path: path.join(ws, "out.txt") }, workspaceDir: ws } },
  { label: "unknown tool", p: "/v1/decide/tool", body: { sessionId: "c", toolName: "mcp__acme__deploy", params: {} } },
];
const decide = async (g, act) => (await g.post(act.p, act.body)).decision;

test("DISARMED (control plane contained:false): benign work is allowed", async () => {
  contained = false;
  await main.forceRefresh();
  assert.equal((await main.health()).contained, false, "/health reports contained:false");
  const read = await decide(main, matrix(main.root)[0]);
  assert.equal(read.decision, "allow");
  assert.notEqual(read.floor, true);
});

test("ARMED (control plane flips enforcement.contained:true): every action floor-denies", async () => {
  contained = true;
  await main.forceRefresh();
  assert.equal((await main.health()).contained, true, "/health reports contained:true after control-plane arm");
  for (const act of matrix(main.root)) {
    const d = await decide(main, act);
    assert.equal(d.decision, "deny", `${act.label} must deny when contained`);
    assert.equal(d.floor, true, `${act.label} must be floor:true (survives observe) when contained`);
  }
});

test("CLEARED (control plane contained:false again): containment lifts", async () => {
  contained = false;
  await main.forceRefresh();
  assert.equal((await main.health()).contained, false);
  const read = await decide(main, matrix(main.root)[0]);
  assert.equal(read.decision, "allow", "containment must lift only via the control plane");
});

test("NO local lever: a stray VAIBOT_CONTAIN=1 env does NOT arm containment", async () => {
  contained = false; // control plane says not contained
  const rogue = await startGuard({ VAIBOT_CONTAIN: "1" }); // adversary-style local env — must be ignored
  await rogue.forceRefresh();
  assert.equal((await rogue.health()).contained, false, "env var must be ignored — only the control plane arms containment");
});
