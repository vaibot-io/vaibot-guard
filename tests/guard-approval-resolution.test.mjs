import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

// A gated action's governance receipt must report the RESOLVED gate, because
// postGovernanceReceipt only ever runs from a finalize handler — by then the
// human has already answered the agent's native approval prompt. Emitting the
// decide-time `pending` there parked every approved action in the dashboard's
// approval queue permanently, and never recorded denials at all.
//
// Observe mode is the carve-out: nothing is enforced, so nobody is asked. Those
// shadow rows stay `pending` but must carry observe_mode=true, which is how the
// server excludes them from the pending queue.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_PATH = path.resolve(__dirname, "..", "scripts", "vaibot-guard-service.mjs");
const POLICY_PATH = path.resolve(__dirname, "..", "references", "policy.default.json");

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "vaibot-guard-appr-"));
const procs = [];
const httpServers = [];

function waitUntil(fn, { timeoutMs = 6000, intervalMs = 50 } = {}) {
  return (async () => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (await fn()) return true;
      await delay(intervalMs);
    }
    return false;
  })();
}

// Boots a guard wired to a capturing V2 sink. `mode` sets VAIBOT_MODE, which
// resolveMode() treats as the global override.
async function startGuard({ mode, label }) {
  const captured = [];
  const sink = createServer((req, res) => {
    if (req.method === "POST" && req.url === "/v2/receipts") {
      let body = "";
      req.on("data", (c) => { body += c; });
      req.on("end", () => {
        try { captured.push(JSON.parse(body)); } catch { /* ignore */ }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, content_hash: "0xtest" }));
      });
      return;
    }
    res.writeHead(404); res.end("{}");
  });
  httpServers.push(sink);
  const sinkPort = await new Promise((r) => sink.listen(0, "127.0.0.1", () => r(sink.address().port)));

  const workspace = path.join(tmpRoot, label);
  const logDir = path.join(workspace, "log");
  fs.mkdirSync(logDir, { recursive: true });

  // Isolate credentials: with the operator's real production creds in scope the
  // guard refuses a governance-URL override (admin-gated, v3 §5) and the receipt
  // would silently go to the canonical host instead of the sink.
  const home = path.join(workspace, "home");
  fs.mkdirSync(path.join(home, ".vaibot"), { recursive: true });
  fs.writeFileSync(
    path.join(home, ".vaibot", "credentials.json"),
    JSON.stringify({
      version: 3,
      active_env: "staging",
      environments: { staging: { api_key: "vb_test_key" } },
    }),
  );

  const port = 49700 + Math.floor(Math.random() * 800);
  const token = `appr-token-${label}`;
  const child = spawn(process.execPath, [SERVICE_PATH], {
    env: {
      ...process.env,
      HOME: home,
      // creds dir resolves via os.homedir()/$VAIBOT_CREDS_DIR (NOT $HOME) — pin it.
      VAIBOT_CREDS_DIR: path.join(home, ".vaibot"),
      // neutralize leaked env-resolution signals so CREDS_ENV comes from the file
      VAIBOT_ENV: "",
      VAIBOT_API_URL: "",
      VAIBOT_GUARD_HOST: "127.0.0.1",
      VAIBOT_GUARD_PORT: String(port),
      VAIBOT_GUARD_TOKEN: token,
      VAIBOT_POLICY_PATH: POLICY_PATH,
      VAIBOT_WORKSPACE: workspace,
      VAIBOT_GUARD_LOG_DIR: logDir,
      VAIBOT_PROVE_MODE: "off",
      VAIBOT_POLICY_URL: "off",
      VAIBOT_MODE: mode,
      VAIBOT_GOVERNANCE_URL: `http://127.0.0.1:${sinkPort}`,
      VAIBOT_API_KEY: "test-key",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  procs.push(child);

  const healthy = await waitUntil(async () => {
    try { return (await fetch(`http://127.0.0.1:${port}/health`)).ok; } catch { return false; }
  });
  assert.equal(healthy, true, `guard (${label}) should become healthy`);

  const post = async (pathname, body) => {
    const res = await fetch(`http://127.0.0.1:${port}${pathname}`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    return res.json().catch(() => ({}));
  };

  // A write landing OUTSIDE the workspace is the canonical gate ("File mutation
  // outside workspace") and earns a tier-2 receipt.
  const gate = async (sessionId) => {
    const decided = await post("/v1/decide/tool", {
      sessionId,
      toolName: "write",
      params: { file_path: path.join(tmpRoot, "outside", `${sessionId}.txt`), content: "x" },
      workspaceDir: workspace,
    });
    assert.equal(decided.decision?.decision, "approve", "the write should be gated for approval");
    return decided;
  };

  return { captured, post, gate };
}

test("an approved gate is recorded approved + allowed, not left pending", async () => {
  const { captured, post, gate } = await startGuard({ mode: "enforce", label: "approved" });
  const decided = await gate("sess-approve");

  // The user picked "Yes": the tool ran, so PostToolUse finalizes normally.
  await post("/v1/finalize/tool", { sessionId: "sess-approve", runId: decided.runId, result: { outcome: "allowed" } });

  assert.equal(await waitUntil(() => captured.length > 0), true, "a governance receipt should be posted");
  const r = captured[0];
  assert.equal(r.policy.decision, "approval_required", "policy still records that it gated");
  assert.equal(r.approval.status, "approved", "the human answered — this must not stay pending");
  assert.equal(r.result.outcome, "allowed");
  assert.equal(r.observe_mode, false);
  assert.match(r.action.summary, /executed after approval/);
});

test("a denied gate is recorded denied + denied_by_reviewer", async () => {
  const { captured, post, gate } = await startGuard({ mode: "enforce", label: "denied" });
  const decided = await gate("sess-deny");

  // The user picked "No": no PostToolUse fires, so a sweep hook finalizes the
  // run and flags the rejection.
  await post("/v1/finalize/tool", {
    sessionId: "sess-deny",
    runId: decided.runId,
    result: { outcome: "denied_by_reviewer", approval: "denied" },
  });

  assert.equal(await waitUntil(() => captured.length > 0), true, "a denial must still produce a receipt");
  const r = captured[0];
  assert.equal(r.approval.status, "denied");
  assert.equal(r.result.outcome, "denied_by_reviewer");
  assert.match(r.action.summary, /denied approval/);
});

test("an approved-but-failed action reports blocked, not allowed", async () => {
  const { captured, post, gate } = await startGuard({ mode: "enforce", label: "failed" });
  const decided = await gate("sess-fail");

  await post("/v1/finalize/tool", { sessionId: "sess-fail", runId: decided.runId, result: { ok: false } });

  assert.equal(await waitUntil(() => captured.length > 0), true);
  const r = captured[0];
  assert.equal(r.approval.status, "approved", "the human still approved it");
  assert.equal(r.result.outcome, "blocked", "but the action itself did not succeed");
});

test("observe-mode shadow rows stay pending AND carry observe_mode=true", async () => {
  const { captured, post, gate } = await startGuard({ mode: "observe", label: "observe" });
  const decided = await gate("sess-observe");

  // Observe mode never prompts — the action just runs and finalizes.
  await post("/v1/finalize/tool", { sessionId: "sess-observe", runId: decided.runId, result: { outcome: "allowed" } });

  assert.equal(await waitUntil(() => captured.length > 0), true);
  const r = captured[0];
  assert.equal(r.observe_mode, true, "without this flag the server cannot filter shadow rows out of the queue");
  assert.equal(r.approval.status, "pending", "uniform shadow shape — observe_mode is what excludes it");
  assert.equal(r.result.outcome, "allowed", "it actually ran; claiming blocked_until_approved was a lie");
});

test.after(async () => {
  for (const c of procs) if (!c.killed) c.kill("SIGTERM");
  for (const s of httpServers) { try { s.close(); } catch { /* best effort */ } }
  await delay(100);
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch { /* best effort */ }
});
