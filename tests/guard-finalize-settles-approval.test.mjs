import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { reservePort } from "./lib/free-port.mjs";

// The host reports the human's answer to a gated run at finalize, and the run's
// approval record must be settled to match:
//   approval: "denied"   → burned, so a retry cannot redeem a refusal.
//   approval: "approved" → spent (`used`). The user said "Yes" in the host's own
//                          dialog and the call ran. Left `pending`, the record sat
//                          on the dashboard as an open question until its TTL,
//                          and could still be approved there and redeemed.
// Tool route only: exec decide never mints an approval record (its approvalId
// is decideExec's throwaway uuid), so an exec run has nothing to settle.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_PATH = path.resolve(__dirname, "..", "scripts", "vaibot-guard-service.mjs");
const POLICY_PATH = path.resolve(__dirname, "..", "references", "policy.default.json");

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "vaibot-guard-settle-"));
const servers = [];

async function startGuard(label) {
  const port = await reservePort();
  const token = "settle-token";
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
  const pendingIds = async () => (await post("/v1/approvals/list", {})).data.approvals.map((a) => a.approvalId);
  return { post, pendingIds, healthUrl: `http://127.0.0.1:${port}/health` };
}

// message.send lands in the ask lane under the default policy.
const call = (extra = {}) => ({
  sessionId: "settle",
  toolName: "message.send",
  params: { text: "hi" },
  workspaceDir: tmpRoot,
  ...extra,
});

async function gatedToolRun(g) {
  const d = await g.post("/v1/decide/tool", call());
  assert.equal(d.data.decision.decision, "approve", "precondition: the call is gated");
  return { runId: d.data.runId, approvalId: d.data.decision.approvalId };
}

test.after(() => {
  for (const s of servers) if (!s.killed) s.kill("SIGTERM");
});

test('tool: a native "Yes" spends the approval — off the pending list, not redeemable', async () => {
  const g = await startGuard("yes");
  const { runId, approvalId } = await gatedToolRun(g);
  assert.ok((await g.pendingIds()).includes(approvalId), "precondition: pending while the dialog is up");

  const fin = await g.post("/v1/finalize/tool", { sessionId: "settle", runId, result: { outcome: "allowed", approval: "approved" } });
  assert.equal(fin.status, 200);

  assert.ok(!(await g.pendingIds()).includes(approvalId), "no longer an open question on the dashboard");
  const late = await g.post("/v1/approvals/resolve", { approvalId, action: "approve" });
  assert.match(String(late.data.error), /status 'used'/, "cannot be approved after the fact");
  const redeem = await g.post("/v1/decide/tool", call({ approval: { approvalId } }));
  assert.equal(redeem.data.decision.decision, "deny");
  assert.match(String(redeem.data.decision.reason), /status=used/, "single use: the run already spent it");
});

test('tool: an approval approved out-of-band and then run through the native "Yes" is spent too', async () => {
  const g = await startGuard("approved-then-yes");
  const { runId, approvalId } = await gatedToolRun(g);
  await g.post("/v1/approvals/resolve", { approvalId, action: "approve" });

  await g.post("/v1/finalize/tool", { sessionId: "settle", runId, result: { outcome: "allowed", approval: "approved" } });
  const redeem = await g.post("/v1/decide/tool", call({ approval: { approvalId } }));
  assert.match(String(redeem.data.decision.reason), /status=used/, "the approval that let the run through cannot run a second call");
});

test('tool: a "No" still burns the approval', async () => {
  const g = await startGuard("no");
  const { runId, approvalId } = await gatedToolRun(g);

  await g.post("/v1/finalize/tool", { sessionId: "settle", runId, result: { outcome: "denied_by_reviewer", approval: "denied" } });
  assert.ok(!(await g.pendingIds()).includes(approvalId));
  const redeem = await g.post("/v1/decide/tool", call({ approval: { approvalId } }));
  assert.match(String(redeem.data.decision.reason), /status=denied/);
});

test('tool: "approved" at finalize never upgrades a denied record', async () => {
  const g = await startGuard("no-upgrade");
  const { runId, approvalId } = await gatedToolRun(g);
  await g.post("/v1/approvals/resolve", { approvalId, action: "deny" });

  await g.post("/v1/finalize/tool", { sessionId: "settle", runId, result: { outcome: "allowed", approval: "approved" } });
  const redeem = await g.post("/v1/decide/tool", call({ approval: { approvalId } }));
  assert.match(String(redeem.data.decision.reason), /status=denied/, "a human 'no' stays a 'no'");
});

test("tool: a finalize with no approval claim leaves the record pending", async () => {
  const g = await startGuard("no-claim");
  const { runId, approvalId } = await gatedToolRun(g);

  await g.post("/v1/finalize/tool", { sessionId: "settle", runId, result: { outcome: "allowed" } });
  assert.ok((await g.pendingIds()).includes(approvalId), "only an explicit answer settles it");
});

test("tool: settling touches only the run's OWN approval", async () => {
  const g = await startGuard("own-only");
  const a = await gatedToolRun(g);
  const b = await gatedToolRun(g);

  await g.post("/v1/finalize/tool", { sessionId: "settle", runId: a.runId, result: { outcome: "allowed", approval: "approved" } });
  const pending = await g.pendingIds();
  assert.ok(!pending.includes(a.approvalId));
  assert.ok(pending.includes(b.approvalId), "another run's approval is untouched");
});

test("tool: a host's refusal burns the approval, like a user's", async () => {
  const g = await startGuard("host-denied");
  const { runId, approvalId } = await gatedToolRun(g);

  await g.post("/v1/finalize/tool", { sessionId: "settle", runId, result: { ok: false, approval: "host_denied", host: "cursor" } });
  assert.ok(!(await g.pendingIds()).includes(approvalId));
  const redeem = await g.post("/v1/decide/tool", call({ approval: { approvalId } }));
  assert.match(String(redeem.data.decision.reason), /status=denied/);
});

test("tool: an expired answer marks the record expired at once — off the queue, not approvable", async () => {
  const g = await startGuard("expired");
  const { runId, approvalId } = await gatedToolRun(g);

  await g.post("/v1/finalize/tool", { sessionId: "settle", runId, result: { ok: false, approval: "expired" } });
  assert.ok(!(await g.pendingIds()).includes(approvalId), "no longer an open question on the dashboard");
  const status = await g.post("/v1/approvals/status", { approvalIds: [approvalId] });
  assert.equal(status.data.approvals?.[0]?.status ?? status.data.statuses?.[0]?.status, "expired");
  const late = await g.post("/v1/approvals/resolve", { approvalId, action: "approve" });
  assert.match(String(late.data.error), /status 'expired'/);
});

test("/health advertises approval-resolutions, so a breaker sends host_denied/expired only to a guard that understands them", async () => {
  // An older guard reads any gated finalize without approval:"denied" as
  // "Approved — action ran", so a breaker must check before it sends these.
  const g = await startGuard("caps");
  const health = await (await fetch(g.healthUrl)).json();
  assert.ok(health.capabilities.includes("approval-resolutions"));
});
