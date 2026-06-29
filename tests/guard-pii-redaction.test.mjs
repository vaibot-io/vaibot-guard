import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Regression test for the home-dir PII collapse (collapseHome): the OS username,
// which leaks via absolute home paths ($HOME/...), must never reach the persisted
// audit leaves — not in workspaceDir, cwd, or paths inside commands.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_PATH = path.resolve(__dirname, "..", "scripts", "vaibot-guard-service.mjs");
const POLICY_PATH = path.resolve(__dirname, "..", "references", "policy.default.json");

const PORT = 39400 + Math.floor(Math.random() * 1500);
const TOKEN = "test-guard-token";

// A fake HOME whose final segment stands in for the (PII) username.
const fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), "vaibot-pii-home-"));
const SECRET_USER = path.basename(fakeHome);
const logDir = fs.mkdtempSync(path.join(os.tmpdir(), "vaibot-pii-log-"));

const env = {
  ...process.env,
  HOME: fakeHome,
  VAIBOT_GUARD_HOST: "127.0.0.1",
  VAIBOT_GUARD_PORT: String(PORT),
  VAIBOT_GUARD_TOKEN: TOKEN,
  VAIBOT_POLICY_PATH: POLICY_PATH,
  VAIBOT_GUARD_LOG_DIR: logDir,
  VAIBOT_PROVE_MODE: "off",
  VAIBOT_POLICY_URL: "off", // hermetic: no control-plane policy fetch
};

const server = spawn(process.execPath, [SERVICE_PATH], { env, stdio: "ignore" });
server.unref(); // don't let the long-lived child keep node --test alive after the tests

async function waitForHealth() {
  for (let i = 0; i < 40; i++) {
    try { const r = await fetch(`http://127.0.0.1:${PORT}/health`); if (r.ok) return true; } catch { /* retry */ }
    await delay(100);
  }
  return false;
}
async function postJson(p, body) {
  const res = await fetch(`http://127.0.0.1:${PORT}${p}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${TOKEN}` },
    body: JSON.stringify(body),
  });
  return { status: res.status, data: await res.json().catch(() => ({})) };
}
function readLog(sessionId) {
  const p = path.join(logDir, `${sessionId}.jsonl`);
  return fs.existsSync(p) ? fs.readFileSync(p, "utf8") : "";
}

assert.equal(await waitForHealth(), true, "guard service should start");
process.on("exit", () => { if (!server.killed) server.kill("SIGTERM"); });

test("tool leaf: home-dir workspaceDir is collapsed to ~ (no username leak)", async () => {
  const sessionId = "pii-tool";
  const ws = path.join(fakeHome, "clients", "acme-corp");
  const { status } = await postJson("/v1/decide/tool", {
    sessionId, toolName: "read", params: { path: "README.md" }, workspaceDir: ws,
  });
  assert.equal(status, 200);
  await delay(60);
  const log = readLog(sessionId);
  assert.ok(log.length > 0, "audit log should be written");
  assert.ok(!log.includes(fakeHome), `leaf must not contain the raw home path: ${fakeHome}`);
  assert.ok(!log.includes(SECRET_USER), "leaf must not contain the username segment");
  assert.ok(log.includes("~/clients/acme-corp"), "workspaceDir should be collapsed to ~");
});

test("exec leaf: home paths in cmd AND cwd are collapsed (no username leak)", async () => {
  const sessionId = "pii-exec";
  const secretPath = path.join(fakeHome, ".ssh", "id_rsa");
  const cwd = path.join(fakeHome, "work");
  const { status } = await postJson("/v1/decide/exec", {
    sessionId,
    cmd: `cat ${secretPath}`,
    args: [secretPath],
    intent: { tool: "exec", action: "read", command: `cat ${secretPath}`, cwd },
  });
  assert.equal(status, 200);
  await delay(60);
  const log = readLog(sessionId);
  assert.ok(log.length > 0, "audit log should be written");
  assert.ok(!log.includes(fakeHome), `exec leaf must not contain the raw home path: ${fakeHome}`);
  assert.ok(!log.includes(SECRET_USER), "exec leaf must not contain the username segment");
  assert.ok(log.includes("~/.ssh/id_rsa"), "the home path inside the command should be collapsed to ~");
});
