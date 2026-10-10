import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { reservePort } from "./lib/free-port.mjs";

// POST /v1/approvals/status — the current status of specific approvals.
//
// /v1/approvals/list returns PENDING only, so an id missing from it may have been
// approved, denied, used or expired. A host that read "missing" as "approved"
// (openclaw's poller) auto-retried refusals. This endpoint is the terminal answer.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_PATH = path.resolve(__dirname, "..", "scripts", "vaibot-guard-service.mjs");
const POLICY_PATH = path.resolve(__dirname, "..", "references", "policy.default.json");

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "vaibot-guard-apprstatus-"));
const servers = [];

async function startGuard(label, extraEnv = {}) {
  const port = await reservePort();
  const token = "status-token";
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
      ...extraEnv,
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  servers.push(server);

  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 60; i++) {
    try {
      if ((await fetch(`${base}/health`)).ok) break;
    } catch { /* not up yet */ }
    await delay(100);
  }

  async function post(pathname, body) {
    const res = await fetch(`${base}${pathname}`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    return { status: res.status, data: await res.json().catch(() => ({})) };
  }
  const pendingIds = async () => (await post("/v1/approvals/list", {})).data.approvals.map((a) => a.approvalId);
  return { base, post, pendingIds };
}

// message.send lands in the ask lane under the default policy.
const call = (extra = {}) => ({ sessionId: "status", toolName: "message.send", params: { text: "hi" }, workspaceDir: tmpRoot, ...extra });

async function escalate(g) {
  const d = await g.post("/v1/decide/tool", call());
  assert.equal(d.data.decision.decision, "approve", "precondition: the call is gated");
  return { runId: d.data.runId, approvalId: d.data.decision.approvalId };
}
const statusOf = async (g, ids) => (await g.post("/v1/approvals/status", { approvalIds: ids })).data.approvals;

test.after(() => {
  for (const s of servers) if (!s.killed) s.kill("SIGTERM");
});

test("status follows an approval through pending → approved → used", async () => {
  const g = await startGuard("lifecycle");
  const { approvalId } = await escalate(g);
  assert.equal((await statusOf(g, [approvalId]))[0].status, "pending");

  await g.post("/v1/approvals/resolve", { approvalId, action: "approve" });
  const approved = (await statusOf(g, [approvalId]))[0];
  assert.equal(approved.status, "approved");
  assert.ok(approved.resolvedAt, "resolvedAt is reported");
  assert.ok(!(await g.pendingIds()).includes(approvalId), "it left the pending list — which is why list alone can't answer");

  await g.post("/v1/decide/tool", call({ approval: { approvalId } }));
  const used = (await statusOf(g, [approvalId]))[0];
  assert.equal(used.status, "used");
  assert.ok(used.usedAt);
});

test("a refusal reads as denied — not as approved", async () => {
  const g = await startGuard("denied");
  const { approvalId } = await escalate(g);
  await g.post("/v1/approvals/resolve", { approvalId, action: "deny" });
  assert.ok(!(await g.pendingIds()).includes(approvalId));
  assert.equal((await statusOf(g, [approvalId]))[0].status, "denied");
});

test('a native "Yes" spent at finalize reads as used', async () => {
  const g = await startGuard("native-yes");
  const { runId, approvalId } = await escalate(g);
  await g.post("/v1/finalize/tool", { sessionId: "status", runId, result: { outcome: "allowed", approval: "approved" } });
  assert.equal((await statusOf(g, [approvalId]))[0].status, "used");
});

test("/health advertises the approval-status capability so a client can detect it", async () => {
  const g = await startGuard("capability");
  const health = await (await fetch(`${g.base}/health`)).json();
  assert.ok(health.capabilities.includes("approval-status"));
});

test("an id this guard never issued reads as unknown", async () => {
  const g = await startGuard("unknown");
  assert.deepEqual(await statusOf(g, ["appr_never_issued"]), [{ approvalId: "appr_never_issued", status: "unknown" }]);
});

test("several ids in one call, duplicates collapsed, each answered on its own", async () => {
  const g = await startGuard("batch");
  const a = await escalate(g);
  const b = await escalate(g);
  await g.post("/v1/approvals/resolve", { approvalId: b.approvalId, action: "deny" });
  const out = await statusOf(g, [a.approvalId, b.approvalId, a.approvalId, "appr_x"]);
  assert.deepEqual(out.map((r) => [r.approvalId, r.status]), [[a.approvalId, "pending"], [b.approvalId, "denied"], ["appr_x", "unknown"]]);
});

test("the endpoint is read-only: asking does not change what a record is", async () => {
  const g = await startGuard("read-only");
  const { approvalId } = await escalate(g);
  await statusOf(g, [approvalId]);
  await statusOf(g, [approvalId]);
  const resolved = await g.post("/v1/approvals/resolve", { approvalId, action: "approve" });
  assert.equal(resolved.data.status, "approved", "still resolvable after being queried");
});

test("bad input is rejected; the guard token is required", async () => {
  const g = await startGuard("validation");
  const bad = [{}, { approvalIds: [] }, { approvalIds: "appr_1" }, { approvalIds: [""] }, { approvalIds: [42] }, { approvalIds: Array.from({ length: 101 }, (_, i) => `appr_${i}`) }];
  for (const body of bad) {
    const r = await g.post("/v1/approvals/status", body);
    assert.equal(r.status, 400, `rejects ${JSON.stringify(body).slice(0, 40)}`);
  }
  const hundred = await g.post("/v1/approvals/status", { approvalIds: Array.from({ length: 100 }, (_, i) => `appr_${i}`) });
  assert.equal(hundred.status, 200, "100 is allowed");
  const anon = await fetch(`${g.base}/v1/approvals/status`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ approvalIds: ["appr_1"] }) });
  assert.equal(anon.status, 401);
});

// The TTL floor is 30 s (VAIBOT_APPROVAL_TTL_MS), so this test waits it out.
test("past its TTL, a pending or an approved-but-unredeemed approval reads as expired", { timeout: 60_000 }, async () => {
  const g = await startGuard("expired", { VAIBOT_APPROVAL_TTL_MS: "30000" });
  const pending = await escalate(g);
  const approved = await escalate(g);
  await g.post("/v1/approvals/resolve", { approvalId: approved.approvalId, action: "approve" });
  await delay(31_000);
  const out = await statusOf(g, [pending.approvalId, approved.approvalId]);
  assert.deepEqual(out.map((r) => r.status), ["expired", "expired"], "a redeem would fail, so neither reads as live");
});
