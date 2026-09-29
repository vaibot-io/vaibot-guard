import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { reservePort } from "./lib/free-port.mjs";

// Every blocked or held decision carries `guidance` — the agent-facing "what to
// do next" — kept separate from `reason`, which stays terse and stable because
// it is what lands in the receipt, the audit log and the dashboard.
//
// These tests pin the four properties that make the split worth having:
//  1. a floor deny tells the agent approval cannot help, so it stops asking,
//  2. an ask tells it to wait rather than retry or reroute,
//  3. guidance NEVER names the token that matched — `reason` keeps that for the
//     human reading the receipt; telling the agent which token tripped tells it
//     which token to avoid,
//  4. only a malformed call is told to retry, because only that verdict changes
//     when the call is fixed.
//
// Note: these exercise the decision path only. The guard decides, it never
// executes, so the destructive-looking probe strings below carry no risk.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_PATH = path.resolve(__dirname, "..", "scripts", "vaibot-guard-service.mjs");
const POLICY_PATH = path.resolve(__dirname, "..", "references", "policy.default.json");

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "vaibot-guard-guidance-"));
const servers = [];

async function startGuard() {
  const port = await reservePort();
  const token = "guidance-test-token";
  const logDir = path.join(tmpRoot, `logs-${port}`);
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
    VAIBOT_POLICY_URL: "off", // hermetic: no control-plane policy fetch
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

  return { post };
}

function execPayload(cmd, args) {
  const command = [cmd, ...args].join(" ");
  return {
    sessionId: "guidance-session",
    cmd,
    args,
    intent: { tool: "exec", action: "run", command, cwd: tmpRoot },
  };
}

test.after(() => {
  for (const s of servers) {
    if (!s.killed) s.kill("SIGTERM");
  }
});

test("a floor deny tells the agent approval cannot override it", async () => {
  const g = await startGuard();
  const res = await g.post("/v1/decide/exec", execPayload("rm", ["-rf", "/nonexistent-guidance-probe"]));
  const d = res.data.decision;

  assert.equal(d.decision, "deny");
  assert.equal(d.floor, true, "this probe should hit the catastrophic floor");
  assert.ok(d.guidance, "a floor deny must carry guidance");
  assert.match(d.guidance, /permanent safety rule/i);
  assert.match(d.guidance, /cannot override/i, "the agent must be told approval will not help");
  assert.match(d.guidance, /do not retry/i);
});

test("an ask tells the agent to wait rather than retry or reroute", async () => {
  const g = await startGuard();
  const res = await g.post("/v1/decide/tool", {
    sessionId: "guidance-session",
    toolName: "message.send",
    params: { text: "hi" },
    workspaceDir: tmpRoot,
  });
  const d = res.data.decision;

  assert.equal(d.decision, "approve");
  assert.ok(d.guidance, "an ask must carry guidance");
  assert.match(d.guidance, /human must approve/i);
  assert.match(d.guidance, /do not retry/i);
  assert.match(d.guidance, /another route/i, "rerouting to the same effect must be ruled out too");
});

test("guidance never names the token that matched, but reason still does", async () => {
  const g = await startGuard();
  // `curl` is an approveToken in the default policy, so this lands in the ask
  // lane via `Approval required for token: curl`.
  const res = await g.post("/v1/decide/exec", execPayload("curl", ["https://example.com"]));
  const d = res.data.decision;

  assert.equal(d.decision, "approve");
  assert.match(d.reason, /curl/, "the receipt's reason keeps the token for the human");
  assert.ok(d.guidance, "an ask must carry guidance");
  assert.doesNotMatch(
    d.guidance,
    /curl/i,
    "guidance must not name the matched token — that teaches the agent what to avoid"
  );
});

test("an allowed action carries no guidance", async () => {
  const g = await startGuard();
  const res = await g.post("/v1/decide/exec", execPayload("ls", ["-la"]));
  const d = res.data.decision;

  assert.equal(d.decision, "allow");
  assert.equal(d.guidance, undefined, "there is nothing to steer on an allow");
});

test("a malformed call is the only lane told to retry", async () => {
  const g = await startGuard();
  // An incomplete intent (no `action`) is the malformed lane that is actually
  // reachable over HTTP. The tool route rejects an empty toolName with a 400
  // before decideTool runs, so its "Missing tool name" branch is defence in
  // depth for direct callers rather than a wire-reachable path.
  const res = await g.post("/v1/decide/exec", {
    sessionId: "guidance-session",
    cmd: "ls",
    args: ["-la"],
    intent: { tool: "exec", command: "ls -la", cwd: tmpRoot },
  });
  const d = res.data.decision;

  assert.equal(d.decision, "deny");
  assert.equal(d.ruleId, "intent-invalid");
  assert.ok(d.guidance, "a malformed call must carry guidance");
  assert.match(d.guidance, /reissue/i, "fixing and reissuing is correct here");
  assert.doesNotMatch(d.guidance, /do not retry/i, "this is the one lane where retrying is right");
});

test("deny guidance and ask guidance are distinguishable", async () => {
  const g = await startGuard();
  const denied = await g.post("/v1/decide/exec", execPayload("rm", ["-rf", "/nonexistent-guidance-probe"]));
  const asked = await g.post("/v1/decide/tool", {
    sessionId: "guidance-session",
    toolName: "message.send",
    params: { text: "hi" },
    workspaceDir: tmpRoot,
  });

  assert.notEqual(
    denied.data.decision.guidance,
    asked.data.decision.guidance,
    "an agent must be able to tell a dead end from a wait"
  );
});
