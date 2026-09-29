import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { reservePort } from "./lib/free-port.mjs";

// Regression: an approval that is still `pending` must not decide anything.
//
// The redemption path used to treat every status other than `approved` as a
// rejection, which swept `pending` in with denied/used/expired. Re-presenting a
// call before the human had answered returned a hard DENY, so the host showed an
// error instead of a prompt — the question never reached anyone, and the record
// stayed pending forever. That is the mechanism behind the dashboard's orphaned
// approvals: nothing was ever able to resolve them.
//
// `pending` now re-issues the escalation with the same approvalId. These tests
// pin that, and pin that the genuinely terminal states still deny — the fix must
// not become a way to replay a used approval or ignore a denial.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_PATH = path.resolve(__dirname, "..", "scripts", "vaibot-guard-service.mjs");
const POLICY_PATH = path.resolve(__dirname, "..", "references", "policy.default.json");

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "vaibot-guard-apprpend-"));
const servers = [];

async function startGuard(label) {
  const port = await reservePort();
  const token = "approval-pending-token";
  const logDir = path.join(tmpRoot, `logs-${label}`);
  const home = path.join(tmpRoot, `home-${label}`);
  fs.mkdirSync(logDir, { recursive: true });
  fs.mkdirSync(home, { recursive: true });
  const server = spawn(process.execPath, [SERVICE_PATH], {
    env: {
      ...process.env,
      HOME: home, // never touch the live rendezvous lock
      VAIBOT_GUARD_HOST: "127.0.0.1",
      VAIBOT_GUARD_PORT: String(port),
      VAIBOT_GUARD_TOKEN: token,
      VAIBOT_POLICY_PATH: POLICY_PATH,
      VAIBOT_WORKSPACE: tmpRoot,
      VAIBOT_GUARD_LOG_DIR: logDir,
      VAIBOT_PROVE_MODE: "off",
      VAIBOT_POLICY_URL: "off",
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  servers.push(server);

  for (let i = 0; i < 60; i++) {
    try {
      if ((await fetch(`http://127.0.0.1:${port}/health`)).ok) break;
    } catch { /* not up yet */ }
    await delay(100);
  }

  async function post(pathname, body) {
    const res = await fetch(`http://127.0.0.1:${port}${pathname}`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    return { status: res.status, data: await res.json().catch(() => ({})) };
  }
  return { post };
}

// message.send lands in the ask lane under the default policy.
const call = (extra = {}) => ({
  sessionId: "appr-pending",
  toolName: "message.send",
  params: { text: "hi" },
  workspaceDir: tmpRoot,
  ...extra,
});

test.after(() => {
  for (const s of servers) if (!s.killed) s.kill("SIGTERM");
});

test("a pending approval re-asks instead of denying", async () => {
  const g = await startGuard("pending");

  const first = await g.post("/v1/decide/tool", call());
  assert.equal(first.data.decision.decision, "approve", "first call should escalate");
  const approvalId = first.data.decision.approvalId;
  assert.ok(approvalId, "an escalation mints an approvalId");

  // Re-present it WITHOUT resolving — exactly what happens when the host retries
  // before the human has answered.
  const second = await g.post("/v1/decide/tool", call({ approval: { approvalId } }));
  const d = second.data.decision;

  assert.notEqual(d.decision, "deny", "a pending approval must never decide deny");
  assert.equal(d.decision, "approve", "it should re-issue the escalation");
  assert.equal(d.approvalId, approvalId, "and carry the SAME id so the record can still be resolved");
  assert.doesNotMatch(
    String(d.reason ?? ""),
    /not approved/i,
    "the old 'Approval not approved (status=pending)' message must be gone"
  );
});

test("the re-asked approval is still resolvable — no orphan left behind", async () => {
  const g = await startGuard("resolvable");

  const first = await g.post("/v1/decide/tool", call());
  const approvalId = first.data.decision.approvalId;

  // Bounce off the pending path, then answer.
  await g.post("/v1/decide/tool", call({ approval: { approvalId } }));
  const resolved = await g.post("/v1/approvals/resolve", { approvalId, action: "approve" });
  assert.equal(resolved.data.status, "approved", "the record survived the re-ask and can still be answered");

  const redeemed = await g.post("/v1/decide/tool", call({ approval: { approvalId } }));
  assert.equal(redeemed.data.decision.decision, "allow");
});

test("a denied approval still denies", async () => {
  const g = await startGuard("denied");

  const first = await g.post("/v1/decide/tool", call());
  const approvalId = first.data.decision.approvalId;
  await g.post("/v1/approvals/resolve", { approvalId, action: "deny" });

  const after = await g.post("/v1/decide/tool", call({ approval: { approvalId } }));
  assert.equal(after.data.decision.decision, "deny", "a human 'no' is terminal");
  assert.match(String(after.data.decision.reason), /denied/i);
});

test("an approval cannot be replayed once used", async () => {
  const g = await startGuard("replay");

  const first = await g.post("/v1/decide/tool", call());
  const approvalId = first.data.decision.approvalId;
  await g.post("/v1/approvals/resolve", { approvalId, action: "approve" });

  const once = await g.post("/v1/decide/tool", call({ approval: { approvalId } }));
  assert.equal(once.data.decision.decision, "allow");

  const twice = await g.post("/v1/decide/tool", call({ approval: { approvalId } }));
  assert.equal(twice.data.decision.decision, "deny", "single use — the pending fix must not open a replay");
  assert.match(String(twice.data.decision.reason), /used/i);
});

test("re-asking re-evaluates policy: a floor call is denied, not re-escalated", async () => {
  const g = await startGuard("floor");

  const first = await g.post("/v1/decide/tool", call());
  const approvalId = first.data.decision.approvalId;

  // Present the still-pending id against a call the floor denies. The re-ask
  // path must run policy again rather than blanket-approving whatever arrives.
  const floored = await g.post("/v1/decide/tool", {
    sessionId: "appr-pending",
    toolName: "Bash",
    params: { command: "rm -rf /nonexistent-appr-probe" },
    workspaceDir: tmpRoot,
    approval: { approvalId },
  });
  assert.equal(floored.data.decision.decision, "deny");
  assert.equal(floored.data.decision.floor, true, "the catastrophic floor still wins over a pending id");
});
