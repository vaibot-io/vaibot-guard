import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { reservePort } from "./lib/free-port.mjs";

// "Allow for this session" — an approval lease. Every one of these tests pins an
// invariant that keeps a lease from becoming the poisonable grant store the
// classifier's opening comment rules out:
//
//   1. HUMAN-INITIATED  — nothing but a host-reported "session" answer mints one.
//   2. SCOPED           — session x kind x category x subject x path prefix.
//   3. EPHEMERAL        — expires, and does not survive a restart.
//   4. FLOOR-PRESERVING — never covers floorAsk; never turns a deny into an allow.
//   5. DEAD ON A RULE CHANGE — mode change, policy change, containment.
//   6. REVOCABLE        — one lease, or all of them.
//
// The one that matters most is 4. A lease that could cover an irreversible action
// would erase floorAsk, which exists precisely so those actions are never silent.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_PATH = path.resolve(__dirname, "..", "scripts", "vaibot-guard-service.mjs");
const POLICY_PATH = path.resolve(__dirname, "..", "references", "policy.default.json");

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "vaibot-guard-lease-"));
const servers = [];

// Mock control plane — the only thing that can change mode or arm containment. The
// guard polls /v2/accounts/me; /v1/mode/refresh forces a deterministic re-poll.
const cp = { mode: "enforce", contained: false };
const mock = http.createServer((req, res) => {
  if (req.url === "/v2/accounts/me") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ admin: false, enforcement: { effective_mode: cp.mode, contained: cp.contained } }));
    return;
  }
  res.writeHead(404, { "content-type": "application/json" });
  res.end('{"ok":false}');
});
const MOCK_PORT = await new Promise((r) => mock.listen(0, "127.0.0.1", () => r(mock.address().port)));
mock.unref();

/** A guard wired to the mock control plane, so mode/containment are drivable. */
async function startGuardWithControlPlane() {
  const root = fs.mkdtempSync(path.join(tmpRoot, "cp-"));
  const credsDir = path.join(root, "creds");
  fs.mkdirSync(credsDir, { recursive: true });
  fs.writeFileSync(path.join(credsDir, "credentials.json"), JSON.stringify({
    version: 3, active_env: "staging",
    environments: { staging: { api_key: "vb_stg_test", governance: { url: `http://127.0.0.1:${MOCK_PORT}` }, provenance: { url: null } } },
  }));
  return startGuard({ extraEnv: { VAIBOT_CREDS_DIR: credsDir, VAIBOT_ENV: "staging", VAIBOT_MODE_REFRESH_MS: "60000" } });
}

async function startGuard({ logDir, mode = "enforce", home, extraEnv = {} } = {}) {
  const port = await reservePort();
  const token = "lease-test-token";
  const dir = logDir || fs.mkdtempSync(path.join(tmpRoot, "logs-"));
  fs.mkdirSync(dir, { recursive: true });
  const env = {
    ...process.env,
    HOME: home || fs.mkdtempSync(path.join(tmpRoot, "home-")),
    VAIBOT_GUARD_HOST: "127.0.0.1",
    VAIBOT_GUARD_PORT: String(port),
    VAIBOT_GUARD_TOKEN: token,
    VAIBOT_POLICY_PATH: POLICY_PATH,
    VAIBOT_WORKSPACE: tmpRoot,
    VAIBOT_GUARD_LOG_DIR: dir,
    VAIBOT_PROVE_MODE: "off",
    VAIBOT_POLICY_URL: "off",
    VAIBOT_MODE: mode,
    ...extraEnv,
  };
  const server = spawn(process.execPath, [SERVICE_PATH], { env, stdio: ["ignore", "pipe", "pipe"] });
  servers.push(server);

  let healthy = false;
  for (let i = 0; i < 40; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/health`);
      if (res.ok) { healthy = true; break; }
    } catch { /* not up yet */ }
    await delay(100);
  }
  assert.equal(healthy, true, "guard should become healthy");

  async function post(pathname, body) {
    const res = await fetch(`http://127.0.0.1:${port}${pathname}`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    return { status: res.status, data: await res.json().catch(() => ({})) };
  }

  async function stop() {
    if (server.killed) return;
    server.kill("SIGTERM");
    for (let i = 0; i < 40; i++) {
      if (server.exitCode !== null || server.signalCode !== null) return;
      await delay(50);
    }
  }

  return { post, server, port, stop, env };
}

test.after(async () => {
  try { mock.close(); } catch { /* closed */ }
  for (const s of servers) { try { s.kill("SIGKILL"); } catch { /* ignore */ } }
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch { /* ignore */ }
});

/** A file-mutation tool outside the workspace: reliably escalates, and is not floorAsk. */
function writeCall(sessionId, filePath) {
  return { sessionId, toolName: "Write", params: { file_path: filePath, content: "x" }, workspaceDir: "/tmp" };
}

/** Ask, then answer "session" the way a host reports it, minting a lease. */
async function leaseVia(post, call) {
  const decided = await post("/v1/decide/tool", call);
  assert.equal(decided.data?.decision?.decision, "approve", "setup: the call should escalate");
  const finalized = await post("/v1/finalize/tool", {
    sessionId: call.sessionId,
    runId: decided.data.runId,
    result: { code: 0, hostApproval: { choice: "session", surface: "tui" } },
  });
  assert.equal(finalized.status, 200);
  return decided.data.runId;
}

test("invariant 1: no lease without a host-reported 'session' answer", async () => {
  const g = await startGuard({});
  try {
    const call = writeCall("s1", "/tmp/lease-a/one.txt");
    const decided = await g.post("/v1/decide/tool", call);
    // answered "once" — the human said yes to THIS call only
    await g.post("/v1/finalize/tool", {
      sessionId: "s1", runId: decided.data.runId,
      result: { code: 0, hostApproval: { choice: "once", surface: "tui" } },
    });
    const leases = await g.post("/v1/leases/list", {});
    assert.equal(leases.data.leases.length, 0, "'once' must not mint a lease");

    const again = await g.post("/v1/decide/tool", writeCall("s1", "/tmp/lease-a/two.txt"));
    assert.equal(again.data.decision.decision, "approve", "still asks");
  } finally { await g.stop(); }
});

test("invariant 2: a lease suppresses the prompt for a matching call, and says so", async () => {
  const g = await startGuard({});
  try {
    await leaseVia(g.post, writeCall("s1", "/tmp/lease-b/one.txt"));

    const leases = await g.post("/v1/leases/list", {});
    assert.equal(leases.data.leases.length, 1, "a session answer mints exactly one lease");
    const lease = leases.data.leases[0];
    assert.equal(lease.grantedBy, "host-prompt", "the receipt names the host, not a verified human");
    assert.equal(lease.pathPrefix, "/tmp/lease-b", "scoped to the directory, not the file");

    const next = await g.post("/v1/decide/tool", writeCall("s1", "/tmp/lease-b/two.txt"));
    assert.equal(next.data.decision.decision, "allow", "a sibling file in the leased dir is covered");
    assert.equal(next.data.decision.leaseId, lease.leaseId);
    assert.equal(next.data.decision.approvalScope, "session-grant");
    assert.match(next.data.decision.reason, /would otherwise ask/, "the receipt records what was suppressed");
  } finally { await g.stop(); }
});

test("invariant 2: scope holds — other session, other subject, other path are NOT covered", async () => {
  const g = await startGuard({});
  try {
    await leaseVia(g.post, writeCall("s1", "/tmp/lease-c/one.txt"));

    // a different host session (Briant's call: leases are per host sessionId)
    const other = await g.post("/v1/decide/tool", writeCall("s2", "/tmp/lease-c/two.txt"));
    assert.equal(other.data.decision.decision, "approve", "another session must not inherit the lease");

    // a different path prefix
    const elsewhere = await g.post("/v1/decide/tool", writeCall("s1", "/tmp/lease-elsewhere/x.txt"));
    assert.equal(elsewhere.data.decision.decision, "approve", "outside the leased directory it still asks");

    // a `..` escape resolving outside the prefix
    const escape = await g.post("/v1/decide/tool", writeCall("s1", "/tmp/lease-c/../lease-escape/x.txt"));
    assert.equal(escape.data.decision.decision, "approve", "a .. segment cannot escape the prefix");
  } finally { await g.stop(); }
});

test("invariant 4: floorAsk is NEVER leasable — an irreversible action asks every time", async () => {
  const g = await startGuard({});
  try {
    // Lease a benign exec family first, to prove a lease exists and still does not help.
    await leaseVia(g.post, writeCall("s1", "/tmp/lease-d/one.txt"));

    // Branch deletion is floorAsk. It must ask no matter what leases exist.
    for (const cmd of ["git", "npm", "cargo"]) {
      const args = cmd === "git" ? ["branch", "-D", "feat/x"] : cmd === "npm" ? ["publish"] : ["publish"];
      const r = await g.post("/v1/decide/exec", { sessionId: "s1", cmd, args, intent: { kind: "exec" } });
      assert.notEqual(r.data.decision.decision, "allow", `${cmd} ${args.join(" ")} must not be leasable`);
      assert.equal(r.data.decision.leaseId, undefined, "no lease may be attached to a floorAsk action");
    }
  } finally { await g.stop(); }
});

test("invariant 4: a lease never turns a deny into an allow", async () => {
  const g = await startGuard({});
  try {
    await leaseVia(g.post, writeCall("s1", "/tmp/lease-e/one.txt"));
    // The catastrophic floor.
    const r = await g.post("/v1/decide/exec", {
      sessionId: "s1", cmd: "rm", args: ["-rf", "/"], intent: { kind: "exec" },
    });
    assert.equal(r.data.decision.decision, "deny", "the floor is untouched by any lease");
  } finally { await g.stop(); }
});

test("invariant 5: a mode change invalidates every lease", async () => {
  cp.mode = "enforce";
  cp.contained = false;
  const g = await startGuardWithControlPlane();
  try {
    await g.post("/v1/mode/refresh", {});
    await leaseVia(g.post, writeCall("s1", "/tmp/lease-f/one.txt"));
    assert.equal((await g.post("/v1/leases/list", {})).data.leases.length, 1, "setup: one lease");

    // Really flip it, through the only thing that can.
    cp.mode = "observe";
    await g.post("/v1/mode/refresh", {});
    const health = await (await fetch(`http://127.0.0.1:${g.port}/health`)).json();
    assert.equal(health.effective_mode, "observe", "setup: the mode must actually have changed");

    const after = await g.post("/v1/leases/list", {});
    assert.equal(after.data.leases.length, 0, "a lease must not survive a mode change");
  } finally { cp.mode = "enforce"; await g.stop(); }
});

test("invariant 5: containment invalidates every lease, and nothing is leasable while armed", async () => {
  cp.mode = "enforce";
  cp.contained = false;
  const g = await startGuardWithControlPlane();
  try {
    await g.post("/v1/mode/refresh", {});
    await leaseVia(g.post, writeCall("s1", "/tmp/lease-g/one.txt"));
    assert.equal((await g.post("/v1/leases/list", {})).data.leases.length, 1, "setup: one lease");

    cp.contained = true;
    await g.post("/v1/mode/refresh", {});
    const health = await (await fetch(`http://127.0.0.1:${g.port}/health`)).json();
    assert.equal(health.contained, true, "setup: containment must actually be armed");

    assert.equal((await g.post("/v1/leases/list", {})).data.leases.length, 0,
      "containment is rung 0 — no lease survives it");
    const call = await g.post("/v1/decide/tool", writeCall("s1", "/tmp/lease-g/two.txt"));
    assert.equal(call.data.decision.decision, "deny", "and while armed, everything blocks");
    assert.equal(call.data.decision.floor, true, "with the floor flag, so observe cannot lift it");
  } finally { cp.contained = false; await g.stop(); }
});

test("invariant 3: a lease does not survive a restart — nothing durable is minted", async () => {
  const home = fs.mkdtempSync(path.join(tmpRoot, "home-persist-"));
  const logDir = fs.mkdtempSync(path.join(tmpRoot, "logs-persist-"));
  const g1 = await startGuard({ home, logDir });
  try {
    await leaseVia(g1.post, writeCall("s1", "/tmp/lease-h/one.txt"));
    assert.equal((await g1.post("/v1/leases/list", {})).data.leases.length, 1);
  } finally { await g1.stop(); }

  // Same HOME and log dir: anything persisted would come back.
  const g2 = await startGuard({ home, logDir });
  try {
    const after = await g2.post("/v1/leases/list", {});
    assert.equal(after.data.leases.length, 0, "a lease must die with the process");
    const call = await g2.post("/v1/decide/tool", writeCall("s1", "/tmp/lease-h/two.txt"));
    assert.equal(call.data.decision.decision, "approve", "after a restart it asks again");
  } finally { await g2.stop(); }
});

test("invariant 3: no lease is ever written to disk", async () => {
  const home = fs.mkdtempSync(path.join(tmpRoot, "home-disk-"));
  const logDir = fs.mkdtempSync(path.join(tmpRoot, "logs-disk-"));
  const g = await startGuard({ home, logDir });
  try {
    const runId = await leaseVia(g.post, writeCall("s1", "/tmp/lease-i/one.txt"));
    const leases = await g.post("/v1/leases/list", {});
    const leaseId = leases.data.leases[0].leaseId;

    // The leaseId may legitimately appear in the AUDIT (that is the point — suppress
    // the prompt, never the audit). What must not exist is a lease STORE.
    const hits = [];
    const walk = (dir) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) { walk(p); continue; }
        if (/lease/i.test(e.name)) hits.push(p);
      }
    };
    walk(home);
    assert.deepEqual(hits, [], `no lease file may exist on disk: ${hits.join(", ")}`);
    assert.ok(runId, "sanity");
  } finally { await g.stop(); }
});

test("invariant 6: a lease is revocable, individually and all at once", async () => {
  const g = await startGuard({});
  try {
    await leaseVia(g.post, writeCall("s1", "/tmp/lease-j/one.txt"));
    const leaseId = (await g.post("/v1/leases/list", {})).data.leases[0].leaseId;

    const revoked = await g.post("/v1/leases/revoke", { leaseId });
    assert.equal(revoked.status, 200);
    const call = await g.post("/v1/decide/tool", writeCall("s1", "/tmp/lease-j/two.txt"));
    assert.equal(call.data.decision.decision, "approve", "a revoked lease covers nothing");

    // revoking twice is an error, not a silent success
    assert.equal((await g.post("/v1/leases/revoke", { leaseId })).status, 400);

    // and the panic path
    await leaseVia(g.post, writeCall("s2", "/tmp/lease-k/one.txt"));
    const all = await g.post("/v1/leases/revoke", { all: true });
    assert.equal(all.status, 200);
    assert.ok(all.data.revoked >= 1, "revoke-all reports how many it dropped");
    assert.equal((await g.post("/v1/leases/list", {})).data.leases.length, 0);
  } finally { await g.stop(); }
});

test("a host running with approvals bypassed cannot mint a lease — there was no human", async () => {
  const g = await startGuard({});
  try {
    const call = { ...writeCall("s1", "/tmp/lease-l/one.txt"), hostBypass: { active: true, mechanism: "yolo" } };
    const decided = await g.post("/v1/decide/tool", call);
    await g.post("/v1/finalize/tool", {
      sessionId: "s1", runId: decided.data.runId,
      result: { code: 0, hostApproval: { choice: "session", surface: "tui" } },
    });
    const leases = await g.post("/v1/leases/list", {});
    assert.equal(leases.data.leases.length, 0, "a bypassed host asserts a human that does not exist");
  } finally { await g.stop(); }
});

test("a leased action is still recorded — suppress the prompt, never the audit", async () => {
  const g = await startGuard({});
  try {
    await leaseVia(g.post, writeCall("s1", "/tmp/lease-m/one.txt"));
    const next = await g.post("/v1/decide/tool", writeCall("s1", "/tmp/lease-m/two.txt"));
    assert.equal(next.data.decision.decision, "allow");
    // A receipt tier and an audit entry are still produced for the leased call.
    assert.ok(next.data.audit?.hash, "a leased action still appends to the audit log");
    assert.equal(next.data.receiptTier, "receipt", "and is still receipted, not merely ledgered");
  } finally { await g.stop(); }
});
