import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Exercises Phase D's ephemeral-approval invariants through the live guard:
//  - D-140: approvals are held in memory and NEVER written to disk,
//  - D-140: approvals are session-scoped (one session can't redeem another's),
//  - D-141 / I-177: an approved approval does not survive a daemon restart
//    (no permanent/durable grant is minted locally).

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_PATH = path.resolve(__dirname, "..", "scripts", "vaibot-guard-service.mjs");
const POLICY_PATH = path.resolve(__dirname, "..", "references", "policy.default.json");

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "vaibot-guard-ephemeral-"));
const servers = [];

async function startGuard({ logDir }) {
  const port = 43200 + Math.floor(Math.random() * 2000);
  const token = "ephemeral-approval-token";
  fs.mkdirSync(logDir, { recursive: true });
  const env = {
    ...process.env,
    VAIBOT_GUARD_HOST: "127.0.0.1",
    VAIBOT_GUARD_PORT: String(port),
    VAIBOT_GUARD_TOKEN: token,
    VAIBOT_POLICY_PATH: POLICY_PATH,
    VAIBOT_WORKSPACE: tmpRoot,
    VAIBOT_GUARD_LOG_DIR: logDir,
    VAIBOT_PROVE_MODE: "off",
  };
  const server = spawn(process.execPath, [SERVICE_PATH], { env, stdio: ["ignore", "pipe", "pipe"] });
  servers.push(server);

  let healthy = false;
  for (let i = 0; i < 40; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/health`);
      if (res.ok) {
        healthy = true;
        break;
      }
    } catch {
      // not up yet
    }
    await delay(100);
  }
  assert.equal(healthy, true, "guard should become healthy");

  async function post(pathname, body) {
    const res = await fetch(`http://127.0.0.1:${port}${pathname}`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    return { status: res.status, data };
  }

  async function stop() {
    if (server.killed) return;
    server.kill("SIGTERM");
    for (let i = 0; i < 40; i++) {
      if (server.exitCode !== null || server.signalCode !== null) return;
      await delay(50);
    }
  }

  return { post, server, port, stop };
}

test("approvals are never written to disk through a full approve -> redeem cycle", async () => {
  const logDir = path.join(tmpRoot, "no-disk");
  const g = await startGuard({ logDir });

  const payload = { sessionId: "s1", toolName: "message.send", params: { text: "hi" }, workspaceDir: tmpRoot };
  const decided = await g.post("/v1/decide/tool", payload);
  assert.equal(decided.data.decision.decision, "approve");
  const approvalId = decided.data.decision.approvalId;
  assert.ok(approvalId);

  const resolved = await g.post("/v1/approvals/resolve", { approvalId, action: "approve" });
  assert.equal(resolved.data.status, "approved");

  const redeemed = await g.post("/v1/decide/tool", { ...payload, approval: { approvalId } });
  assert.equal(redeemed.data.decision.decision, "allow");

  // The dedicated approvals store directory must never be created on disk.
  assert.equal(fs.existsSync(path.join(logDir, "approvals")), false, "approvals/ dir must not exist");
});

test("approvals are session-scoped: another session cannot redeem them", async () => {
  const logDir = path.join(tmpRoot, "session-scope");
  const g = await startGuard({ logDir });

  const payload = { sessionId: "owner", toolName: "message.send", params: { text: "scoped" }, workspaceDir: tmpRoot };
  const decided = await g.post("/v1/decide/tool", payload);
  const approvalId = decided.data.decision.approvalId;
  assert.ok(approvalId);
  await g.post("/v1/approvals/resolve", { approvalId, action: "approve" });

  // A different session presenting the same approvalId + same params is denied.
  const intruder = await g.post("/v1/decide/tool", { ...payload, sessionId: "intruder", approval: { approvalId } });
  assert.equal(intruder.data.decision.decision, "deny");
  assert.match(intruder.data.decision.reason, /session mismatch/i);

  // The owning session can still redeem it.
  const owner = await g.post("/v1/decide/tool", { ...payload, approval: { approvalId } });
  assert.equal(owner.data.decision.decision, "allow");
});

test("an approved approval does not survive a daemon restart (no permanent grant)", async () => {
  const logDir = path.join(tmpRoot, "restart");
  const first = await startGuard({ logDir });

  const payload = { sessionId: "s1", toolName: "message.send", params: { text: "later" }, workspaceDir: tmpRoot };
  const decided = await first.post("/v1/decide/tool", payload);
  const approvalId = decided.data.decision.approvalId;
  assert.ok(approvalId);
  const resolved = await first.post("/v1/approvals/resolve", { approvalId, action: "approve" });
  assert.equal(resolved.data.status, "approved");

  // Restart the daemon (same LOG_DIR). A persisted grant would survive; an
  // ephemeral one is gone.
  await first.stop();
  const second = await startGuard({ logDir });

  const redeemed = await second.post("/v1/decide/tool", { ...payload, approval: { approvalId } });
  assert.equal(redeemed.data.decision.decision, "deny");
  assert.match(redeemed.data.decision.reason, /not found/i);
});

test.after(async () => {
  for (const s of servers) if (!s.killed) s.kill("SIGTERM");
  await delay(100);
  try {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  } catch {
    // best effort
  }
});
