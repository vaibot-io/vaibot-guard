import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { reservePort } from "./lib/free-port.mjs";

// Batch approvals: "yes to exactly THESE N things."
//
// The opposite shape to a lease. A lease is time-boxed and pattern-scoped, and may
// never cover an irreversible action — one answer would then license actions nobody
// enumerated, which is precisely how 41 branch deletions followed a single approval.
// A batch is content-bound and count-bounded, so it IS allowed to cover floorAsk:
// floorAsk means "never silent", and a batch is not silence — it is disclosure of the
// whole list before anything runs. It removes the repetition, not the visibility.
//
// The two properties that carry all the weight:
//   * approving `git branch -D feat/a` must NOT approve `feat/b`
//   * creating one requires the OPERATOR token, never the guard token the breakers
//     hold — otherwise an agent could approve its own batch

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_PATH = path.resolve(__dirname, "..", "scripts", "vaibot-guard-service.mjs");
const POLICY_PATH = path.resolve(__dirname, "..", "references", "policy.default.json");

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "vaibot-guard-batch-"));
const servers = [];
const GUARD_TOKEN = "batch-test-guard-token";
const OPERATOR_TOKEN = "batch-test-operator-token-0123456789";

async function startGuard({ operatorToken = OPERATOR_TOKEN } = {}) {
  const port = await reservePort();
  const root = fs.mkdtempSync(path.join(tmpRoot, "g-"));
  const logDir = path.join(root, "logs");
  fs.mkdirSync(logDir, { recursive: true });
  const env = {
    ...process.env,
    HOME: path.join(root, "home"),
    VAIBOT_GUARD_HOST: "127.0.0.1",
    VAIBOT_GUARD_PORT: String(port),
    VAIBOT_GUARD_TOKEN: GUARD_TOKEN,
    VAIBOT_POLICY_PATH: POLICY_PATH,
    VAIBOT_WORKSPACE: root,
    VAIBOT_GUARD_LOG_DIR: logDir,
    VAIBOT_PROVE_MODE: "off",
    VAIBOT_POLICY_URL: "off",
    VAIBOT_MODE: "enforce",
  };
  if (operatorToken) env.VAIBOT_OPERATOR_TOKEN = operatorToken;
  else delete env.VAIBOT_OPERATOR_TOKEN;
  fs.mkdirSync(env.HOME, { recursive: true });

  const server = spawn(process.execPath, [SERVICE_PATH], { env, stdio: ["ignore", "ignore", "ignore"] });
  server.unref();
  servers.push(server);
  for (let i = 0; i < 60; i++) {
    try { if ((await fetch(`http://127.0.0.1:${port}/health`)).ok) break; } catch { /* not up */ }
    await delay(100);
  }

  const call = async (pathname, body, headers = {}) => {
    const res = await fetch(`http://127.0.0.1:${port}${pathname}`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${GUARD_TOKEN}`, ...headers },
      body: JSON.stringify(body || {}),
    });
    return { status: res.status, data: await res.json().catch(() => ({})) };
  };
  const asOperator = (pathname, body) => call(pathname, body, { "x-vaibot-operator-token": OPERATOR_TOKEN });
  const stop = async () => { try { server.kill("SIGTERM"); } catch { /* gone */ } };
  return { call, asOperator, port, stop, root };
}

test.after(() => {
  for (const s of servers) { try { s.kill("SIGKILL"); } catch { /* ignore */ } }
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch { /* ignore */ }
});

const del = (branch) => ({ kind: "exec", cmd: "git", args: ["branch", "-D", branch] });

/** validateIntent() requires tool/action/command/cwd; anything less is denied as malformed. */
const execIntent = (cmd, args) => ({ tool: "exec", action: "run", command: [cmd, ...args].join(" "), cwd: "/tmp" });

const decideExec = (g, sessionId, cmd, args) =>
  g.call("/v1/decide/exec", { sessionId, cmd, args, intent: execIntent(cmd, args) });

const decideDel = (g, branch) => decideExec(g, "s1", "git", ["branch", "-D", branch]);

test("a batch covers floorAsk — that is what it is for", async () => {
  const g = await startGuard();
  try {
    // Branch deletion is floorAsk: it asks on every preset, and no lease can cover it.
    const before = await decideDel(g, "feat/a");
    assert.notEqual(before.data.decision.decision, "allow", "setup: floorAsk asks by default");

    const made = await g.asOperator("/v1/batches/create", { sessionId: "s1", items: [del("feat/a"), del("feat/b")], reason: "cleanup" });
    assert.equal(made.status, 200, JSON.stringify(made.data));
    assert.equal(made.data.items.length, 2);
    assert.match(made.data.items[0].label, /git branch -D feat\/a/, "the list is legible to whoever approves it");

    const a = await decideDel(g, "feat/a");
    assert.equal(a.data.decision.decision, "allow", "an enumerated floorAsk action is allowed");
    assert.equal(a.data.decision.batchId, made.data.batchId);
    assert.match(a.data.decision.reason, /would otherwise ask/, "the receipt records what was suppressed");
  } finally { await g.stop(); }
});

test("content-bound: approving one branch does not approve another", async () => {
  const g = await startGuard();
  try {
    await g.asOperator("/v1/batches/create", { sessionId: "s1", items: [del("feat/a")] });
    assert.equal((await decideDel(g, "feat/a")).data.decision.decision, "allow");
    // The whole point. A pattern would have covered this; a list does not.
    assert.notEqual((await decideDel(g, "feat/b")).data.decision.decision, "allow",
      "a branch nobody enumerated must still ask");
  } finally { await g.stop(); }
});

test("count-bounded: each item is consumed exactly once", async () => {
  const g = await startGuard();
  try {
    await g.asOperator("/v1/batches/create", { sessionId: "s1", items: [del("feat/a")] });
    assert.equal((await decideDel(g, "feat/a")).data.decision.decision, "allow", "first use");
    assert.notEqual((await decideDel(g, "feat/a")).data.decision.decision, "allow",
      "the same call a second time is not covered — there is no rate, only a list");
  } finally { await g.stop(); }
});

test("creating a batch requires the OPERATOR token — the guard token is not enough", async () => {
  const g = await startGuard();
  try {
    // The guard token is what every breaker holds, so it must not be sufficient.
    const withGuardToken = await g.call("/v1/batches/create", { sessionId: "s1", items: [del("feat/a")] });
    assert.equal(withGuardToken.status, 401, "an agent holding the guard token cannot approve its own batch");

    const wrong = await g.call("/v1/batches/create", { sessionId: "s1", items: [del("feat/a")] },
      { "x-vaibot-operator-token": "wrong-token-but-long-enough-here" });
    assert.equal(wrong.status, 401);

    assert.notEqual((await decideDel(g, "feat/a")).data.decision.decision, "allow", "nothing was approved");
  } finally { await g.stop(); }
});

test("with no operator token configured, batch creation fails closed", async () => {
  const g = await startGuard({ operatorToken: null });
  try {
    const r = await g.asOperator("/v1/batches/create", { sessionId: "s1", items: [del("feat/a")] });
    assert.equal(r.status, 501, "absent configuration must never mean 'allowed'");
    assert.match(r.data.error, /not configured/);
  } finally { await g.stop(); }
});

test("a batch never turns a deny into an allow", async () => {
  const g = await startGuard();
  try {
    const made = await g.asOperator("/v1/batches/create", {
      sessionId: "s1",
      items: [{ kind: "exec", cmd: "rm", args: ["-rf", "/"] }],
    });
    assert.equal(made.status, 200, "the operator may enumerate anything; it changes nothing");
    const r = await decideExec(g, "s1", "rm", ["-rf", "/"]);
    assert.equal(r.data.decision.decision, "deny", "the catastrophic floor is not approvable");
    // Prove it was the FLOOR, not a malformed intent: the floor flag is set and the
    // reason names the pattern. Without this the test passed for the wrong reason.
    assert.equal(r.data.decision.floor, true, "denied by the catastrophic floor specifically");
  } finally { await g.stop(); }
});

test("session-scoped when asked, and revocable", async () => {
  const g = await startGuard();
  try {
    await g.asOperator("/v1/batches/create", { sessionId: "s1", items: [del("feat/a")] });
    const other = await decideExec(g, "s2", "git", ["branch", "-D", "feat/a"]);
    assert.notEqual(other.data.decision.decision, "allow", "another session is not covered by a scoped batch");

    const listed = await g.call("/v1/batches/list", {});
    assert.equal(listed.data.batches.length, 1);
    assert.equal(listed.data.batches[0].remaining, 1, "the list says how much is unused");

    const revoked = await g.call("/v1/batches/revoke", { batchId: listed.data.batches[0].batchId });
    assert.equal(revoked.status, 200);
    assert.equal(revoked.data.unused, 1, "revocation reports what it took back");
    assert.notEqual((await decideDel(g, "feat/a")).data.decision.decision, "allow", "a revoked batch covers nothing");
  } finally { await g.stop(); }
});

test("duplicates collapse — approving the same call twice grants one use", async () => {
  const g = await startGuard();
  try {
    const made = await g.asOperator("/v1/batches/create", { sessionId: "s1", items: [del("feat/a"), del("feat/a")] });
    assert.equal(made.data.items.length, 1, "a duplicated line must not double the grant");
  } finally { await g.stop(); }
});

test("an over-long list is refused — a list nobody can read is not disclosure", async () => {
  const g = await startGuard();
  try {
    const items = Array.from({ length: 501 }, (_, i) => del(`feat/${i}`));
    const r = await g.asOperator("/v1/batches/create", { sessionId: "s1", items });
    assert.equal(r.status, 400);
    assert.match(r.data.error, /Too many items/);
  } finally { await g.stop(); }
});

test("a batched action is still recorded — the audit is never suppressed", async () => {
  const g = await startGuard();
  try {
    await g.asOperator("/v1/batches/create", { sessionId: "s1", items: [del("feat/a")] });
    const r = await decideDel(g, "feat/a");
    assert.equal(r.data.decision.decision, "allow");
    assert.ok(r.data.audit?.hash, "a batched action still appends to the audit log");
    assert.equal(r.data.receiptTier, "receipt", "and is receipted, not merely ledgered");
  } finally { await g.stop(); }
});

test("nothing is written to disk, and a batch dies with the process", async () => {
  const g = await startGuard();
  try {
    await g.asOperator("/v1/batches/create", { sessionId: "s1", items: [del("feat/a")] });
    const hits = [];
    const walk = (dir) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) { walk(p); continue; }
        if (/batch/i.test(e.name)) hits.push(p);
      }
    };
    walk(g.root);
    assert.deepEqual(hits, [], `no batch file may exist on disk: ${hits.join(", ")}`);
  } finally { await g.stop(); }
});
