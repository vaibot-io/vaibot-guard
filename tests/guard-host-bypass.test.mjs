import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPair, signBundle, POLICY_BUNDLE_SCHEMA } from "../scripts/policy-bundle.mjs";

// hostBypassAction, rule ids, and how an approval was granted — end to end
// through a live guard, down to the governance receipt it posts.
//
// While an agent host bypasses its own approvals (Hermes --yolo, Claude Code
// bypassPermissions), any escalation is granted before a human sees it. The
// policy decides: 'deny' (default) blocks the escalation, 'approve' honours the
// bypass and the receipt says so. Neither touches the catastrophic floor.
//
// Hermetic: HOME is a temp dir (the guard writes its rendezvous lock under
// $HOME), the policy is a locally signed bundle, and receipts go to a sink.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_PATH = path.resolve(__dirname, "..", "scripts", "vaibot-guard-service.mjs");
const DEFAULT_POLICY = JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", "references", "policy.default.json"), "utf-8"));

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "vaibot-guard-bypass-"));
const { publicKey, privateKey } = generateKeyPair();
const procs = [];
const sinks = [];

const BYPASS = { active: true, mechanism: "hermes:yolo" };
// Assembled from fragments so no literal destructive command sits in this file.
const DESTRUCTIVE = ["rm", " -rf", " /"].join("");

async function waitUntil(fn, timeoutMs = 6000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await fn()) return true;
    await delay(50);
  }
  return false;
}

async function startGuard({ label, signedPolicy = null, localPolicy = {}, mode = "enforce" }) {
  const captured = [];
  const sink = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      if (req.method === "POST" && req.url === "/v2/receipts") {
        try { captured.push(JSON.parse(body)); } catch { /* ignore */ }
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
    });
  });
  sinks.push(sink);
  const sinkPort = await new Promise((r) => sink.listen(0, "127.0.0.1", () => r(sink.address().port)));

  const dir = path.join(tmpRoot, label);
  const home = path.join(dir, "home");
  const workspace = path.join(dir, "workspace");
  fs.mkdirSync(path.join(home, ".vaibot"), { recursive: true });
  fs.mkdirSync(workspace, { recursive: true });
  fs.writeFileSync(
    path.join(home, ".vaibot", "credentials.json"),
    JSON.stringify({ version: 3, active_env: "staging", environments: { staging: { api_key: "vb_stg_test" } } }),
  );
  const policyPath = path.join(dir, "policy.json");
  fs.writeFileSync(policyPath, JSON.stringify({ ...DEFAULT_POLICY, ...localPolicy }));

  const env = {
    PATH: process.env.PATH,
    HOME: home,
    VAIBOT_CREDS_DIR: path.join(home, ".vaibot"),
    VAIBOT_GUARD_HOST: "127.0.0.1",
    VAIBOT_GUARD_PORT: String(43200 + Math.floor(Math.random() * 2000)),
    VAIBOT_GUARD_TOKEN: "bypass-token",
    VAIBOT_POLICY_PATH: policyPath,
    VAIBOT_WORKSPACE: workspace,
    VAIBOT_GUARD_LOG_DIR: path.join(dir, "log"),
    VAIBOT_PROVE_MODE: "off",
    VAIBOT_POLICY_URL: "off",
    VAIBOT_MODE: mode,
    VAIBOT_GOVERNANCE_URL: `http://127.0.0.1:${sinkPort}`,
    VAIBOT_API_KEY: "vb_stg_test",
  };
  if (signedPolicy) {
    const bundlePath = path.join(dir, "bundle.json");
    const bundle = signBundle(
      {
        schema: POLICY_BUNDLE_SCHEMA,
        version: `test-${label}`,
        issuer: "vaibot",
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
        policy: signedPolicy,
      },
      privateKey,
    );
    fs.writeFileSync(bundlePath, JSON.stringify(bundle));
    Object.assign(env, { VAIBOT_POLICY_BUNDLE_PATH: bundlePath, VAIBOT_POLICY_PUBKEY: publicKey });
  }

  const port = env.VAIBOT_GUARD_PORT;
  const child = spawn(process.execPath, [SERVICE_PATH], { env, stdio: ["ignore", "pipe", "pipe"] });
  procs.push(child);
  const healthy = await waitUntil(async () => {
    try { return (await fetch(`http://127.0.0.1:${port}/health`)).ok; } catch { return false; }
  });
  assert.equal(healthy, true, `guard (${label}) should start`);

  const base = `http://127.0.0.1:${port}`;
  const post = async (pathname, body) => {
    const res = await fetch(`${base}${pathname}`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer bypass-token" },
      body: JSON.stringify(body),
    });
    return res.json();
  };
  const get = async (pathname) => (await fetch(`${base}${pathname}`)).json();
  // A write outside the workspace: the canonical escalation, and receipt-tier.
  const escalation = (sessionId, extra = {}) =>
    post("/v1/decide/tool", {
      sessionId,
      toolName: "write",
      params: { file_path: path.join(dir, "outside", "x.txt"), content: "x" },
      workspaceDir: workspace,
      ...extra,
    });
  let stderr = "";
  child.stderr.on("data", (c) => (stderr += c));
  let lastFinalize = null;
  const finalize = async (runId, result) => {
    lastFinalize = await post("/v1/finalize/tool", { sessionId: "s", runId, result });
    return lastFinalize;
  };
  const receipt = async () => {
    const arrived = await waitUntil(() => captured.length > 0);
    assert.equal(arrived, true,
      `a governance receipt should be posted — finalize said ${JSON.stringify(lastFinalize)?.slice(0, 300)}; guard stderr: ${stderr.slice(-400)}`);
    return captured.shift();
  };
  return { post, get, escalation, finalize, receipt, dir, workspace };
}

test("default policy: an escalation under an active bypass is blocked, and says why", async () => {
  const g = await startGuard({ label: "default" });
  const plain = await g.escalation("s1");
  assert.equal(plain.decision.decision, "approve", "without a bypass it is an ordinary escalation");

  const d = await g.escalation("s2", { hostBypass: BYPASS });
  assert.equal(d.decision.decision, "deny");
  assert.equal(d.decision.bypassBlocked, true, JSON.stringify(d.decision));
  assert.match(d.decision.reason, /Approval bypass is active \(hermes:yolo\)/);
  assert.match(d.decision.reason, /File mutation outside workspace/);
  assert.equal(d.decision.ruleId, plain.decision.ruleId, "the rule that fired is kept");
  assert.equal(d.decision.floor, undefined, "a policy block is not the catastrophic floor");
  assert.equal(d.host_bypass_action, "deny");

  // No approval record is minted for an escalation the policy blocked.
  const listed = await g.post("/v1/approvals/list", { sessionId: "s2" });
  assert.equal(listed.approvals.length, 0);

  await g.finalize(d.runId, { outcome: "blocked" });
  const r = await g.receipt();
  assert.equal(r.policy.decision, "deny", JSON.stringify(r));
  assert.equal(r.host_bypass_active, true, JSON.stringify(r));
  assert.equal(r.bypass_override, false);
  assert.equal(r.host_bypass_mechanism, "hermes:yolo");
  assert.equal(r.policy.rule_id, plain.decision.ruleId);
  assert.equal(r.action.tool, "write", "the run context survived to finalize");

  // Every tamper-evident audit line must stay parseable. A decision carrying an
  // undefined value once serialised as literal `undefined`, which broke both the
  // audit line and the run context the receipt is built from.
  const logDir = path.join(g.dir, "log");
  for (const f of fs.readdirSync(logDir).filter((n) => n.endsWith(".jsonl"))) {
    for (const line of fs.readFileSync(path.join(logDir, f), "utf-8").split("\n").filter(Boolean)) {
      assert.doesNotThrow(() => JSON.parse(line), `${f}: ${line.slice(0, 160)}`);
    }
  }
});

test("signed 'approve': the bypass is honoured and the receipt says bypassed, not approved", async () => {
  const g = await startGuard({ label: "honour", signedPolicy: { hostBypassAction: "approve" } });
  assert.equal((await g.get("/v1/policy")).hostBypassAction, "approve");

  const d = await g.escalation("s1", { hostBypass: BYPASS });
  assert.equal(d.decision.decision, "approve");
  assert.equal(d.decision.bypassOverride, true);
  assert.equal(d.host_bypass_action, "approve");

  await g.finalize(d.runId, { outcome: "allowed" });
  const r = await g.receipt();
  assert.equal(r.approval.status, "bypassed", "no human decided — never report approved");
  assert.equal(r.bypass_override, true);
  assert.equal(r.host_bypass_active, true);
  assert.equal(r.result.outcome, "allowed");
  assert.match(r.action.summary, /under an approval bypass/);
});

test("a local policy file can only tighten: local deny beats signed approve", async () => {
  const g = await startGuard({ label: "tighten", signedPolicy: { hostBypassAction: "approve" }, localPolicy: { hostBypassAction: "deny" } });
  assert.equal((await g.get("/v1/policy")).hostBypassAction, "deny");
  assert.equal((await g.escalation("s1", { hostBypass: BYPASS })).decision.decision, "deny");
});

test("a local policy file cannot loosen: local approve without a signed approve stays deny", async () => {
  const g = await startGuard({ label: "no-loosen", localPolicy: { hostBypassAction: "approve" } });
  assert.equal((await g.escalation("s1", { hostBypass: BYPASS })).decision.decision, "deny");
});

test("the catastrophic floor and plain allows are untouched by any bypass posture", async () => {
  for (const signedPolicy of [null, { hostBypassAction: "approve" }]) {
    const g = await startGuard({ label: `floor-${signedPolicy ? "honour" : "default"}`, signedPolicy });
    const floor = await g.post("/v1/decide/tool", { sessionId: "s", toolName: "terminal", params: { command: DESTRUCTIVE }, hostBypass: BYPASS });
    assert.equal(floor.decision.decision, "deny");
    assert.equal(floor.decision.floor, true);
    assert.equal(floor.decision.bypassBlocked, undefined);
    assert.equal(floor.decision.bypassOverride, undefined);

    const allow = await g.post("/v1/decide/tool", { sessionId: "s", toolName: "terminal", params: { command: "ls -la" }, hostBypass: BYPASS });
    assert.equal(allow.decision.decision, "allow");
    assert.equal(allow.decision.bypassOverride, undefined);
  }
});

test("only a literal active:true counts, and the mechanism is sanitised", async () => {
  const g = await startGuard({ label: "parse" });
  for (const hostBypass of [{ active: "true" }, { active: 1 }, { enabled: true }, "yolo", null]) {
    assert.equal((await g.escalation("s", { hostBypass })).decision.decision, "approve", JSON.stringify(hostBypass));
  }
  const d = await g.escalation("s", { hostBypass: { active: true, mechanism: "bad mechanism; rm" } });
  assert.equal(d.decision.decision, "deny");
  assert.doesNotMatch(d.decision.reason, /bad mechanism/);
});

test("rule ids name the rule and its subject", async () => {
  const g = await startGuard({ label: "rules" });
  const write = (p) => g.post("/v1/decide/tool", { sessionId: "s", toolName: "write", params: { file_path: p, content: "x" } });
  const a = await write(path.join(g.dir, "outside", "a.txt"));
  const b = await write(path.join(g.dir, "outside", "b.txt"));
  const c = await write(path.join(g.dir, "elsewhere", "c.txt"));
  assert.match(a.decision.ruleId, /^file-outside-workspace:/);
  assert.equal(a.decision.ruleId, b.decision.ruleId, "same directory, same rule");
  assert.notEqual(a.decision.ruleId, c.decision.ruleId, "approving one directory must not approve another");

  const web = await g.post("/v1/decide/tool", { sessionId: "s", toolName: "web_fetch", params: { url: "https://example.invalid/a?b=c" } });
  assert.equal(web.decision.ruleId, "network:example.invalid");

  const token = await g.post("/v1/decide/tool", { sessionId: "s", toolName: "terminal", params: { command: "curl https://example.invalid" } });
  assert.equal(token.decision.decision, "approve");
  assert.equal(token.decision.ruleId, "token-approve:curl");

  const unknown = await g.post("/v1/decide/tool", { sessionId: "s", toolName: "execute_code", params: { code: "print(1)" } });
  assert.match(unknown.decision.ruleId, /^classifier:medium-unknown-tool-execute_code$/);

  const denied = await write("/etc/hosts");
  assert.equal(denied.decision.decision, "deny");
  assert.equal(denied.decision.ruleId, "file-denied-path:/etc");

  const floor = await g.post("/v1/decide/tool", { sessionId: "s", toolName: "terminal", params: { command: DESTRUCTIVE } });
  assert.match(floor.decision.ruleId, /^floor:/);

  for (const d of [a, web, token, unknown, denied, floor]) {
    assert.match(d.decision.ruleId, /^[a-z-]+(:[a-z0-9._~/-]+)?$/, d.decision.ruleId);
    assert.ok(d.decision.ruleId.length <= 120);
  }
});

test("receipts record how an approval was granted, and the host's own prompt", async () => {
  const g = await startGuard({ label: "scope" });
  const d = await g.escalation("s1");
  await g.finalize(d.runId, { outcome: "allowed", approvalScope: "session-grant", approvalChoice: "session", hostApproval: { choice: "once", surface: "cli" } });
  const r = await g.receipt();
  assert.equal(r.approval.status, "approved");
  assert.equal(r.approval.scope, "session-grant");
  assert.equal(r.approval.choice, "session");
  assert.deepEqual(r.host_approval, { choice: "once", surface: "cli" });
  assert.equal(r.host_bypass_active, false);
  assert.equal(r.bypass_override, false);
  assert.equal(r.host_bypass_mechanism, undefined);

  // Values outside the vocabulary are dropped, not written to a receipt.
  const e = await g.escalation("s2");
  await g.finalize(e.runId, { outcome: "allowed", approvalScope: "forever", approvalChoice: "yes please", hostApproval: { choice: "sure" } });
  const r2 = await g.receipt();
  assert.equal(r2.approval.scope, undefined);
  assert.equal(r2.approval.choice, undefined);
  assert.equal(r2.host_approval, undefined);
});

test("observe enforces nothing, so a receipt never claims an override", async () => {
  const g = await startGuard({ label: "observe", signedPolicy: { hostBypassAction: "approve" }, mode: "observe" });
  const d = await g.escalation("s1", { hostBypass: BYPASS });
  await g.finalize(d.runId, { outcome: "allowed" });
  const r = await g.receipt();
  assert.equal(r.observe_mode, true);
  // Nothing was gated, so no human was asked and none is waiting.
  assert.equal(r.approval.status, "not_required");
  assert.equal(r.bypass_override, false);
  assert.equal(r.host_bypass_active, true, "posture is still recorded");
});

test("/health advertises host-bypass and rule-id", async () => {
  const g = await startGuard({ label: "health" });
  const h = await g.get("/health");
  for (const cap of ["host-vocab:hermes", "host-bypass", "rule-id"]) assert.ok(h.capabilities.includes(cap), cap);
});

test.after(async () => {
  for (const c of procs) if (!c.killed) c.kill("SIGTERM");
  for (const s of sinks) { try { s.close(); } catch { /* best effort */ } }
  await delay(100);
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch { /* best effort */ }
});
