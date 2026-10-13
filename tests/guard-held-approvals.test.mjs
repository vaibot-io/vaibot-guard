import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import { createPrivateKey, sign as edSign } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { reservePort } from "./lib/free-port.mjs";
import { canonicalPayload, generateKeyPair, verifyBundle } from "../scripts/policy-bundle.mjs";
import {
  verifyApprovalResolution,
  heldApprovalTransition,
  APPROVAL_RESOLUTION_SCHEMA,
} from "../scripts/lib/approval-resolution-signed.mjs";

// A held call is put in front of the person (phone, dashboard, email) and their
// answer comes back down the enforcement stream, signed. These tests run the
// real guard against a fake control plane and assert on what the guard reports
// and enforces afterwards.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_PATH = path.resolve(__dirname, "..", "scripts", "vaibot-guard-service.mjs");
const POLICY_PATH = path.resolve(__dirname, "..", "references", "policy.default.json");

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "vaibot-held-"));
const servers = [];
const guards = [];
const { privateKey: serverKey, publicKey: serverPub } = generateKeyPair();
const { privateKey: otherKey } = generateKeyPair();

function signAnswer({ runId, contentHash, status, source = "authenticator", key = serverKey, ttlMs = 600_000 }) {
  const now = Date.now();
  const body = {
    schema: APPROVAL_RESOLUTION_SCHEMA,
    run_id: runId,
    content_hash: contentHash,
    status,
    source,
    resolved_at: new Date(now).toISOString(),
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + ttlMs).toISOString(),
  };
  const signature = edSign(null, Buffer.from(canonicalPayload(body)), createPrivateKey(key)).toString("base64");
  return { ...body, signature };
}

function startControlPlane() {
  const clients = new Set();
  const receipts = [];
  const server = createServer((req, res) => {
    if (req.url.startsWith("/v2/accounts/me")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, admin: false, enforcement: { effective_mode: "enforce", contained: false } }));
      return;
    }
    if (req.url === "/v2/receipts" && req.method === "POST") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        let parsed = null;
        try { parsed = JSON.parse(body); } catch { /* ignore */ }
        receipts.push(parsed);
        res.writeHead(201, { "content-type": "application/json" });
        res.end(JSON.stringify({
          ok: true,
          content_hash: `0xhash_${parsed?.run_id}`,
          approval_channels: { authenticator: true, email: true, dashboard: true },
        }));
      });
      return;
    }
    if (req.url.startsWith("/v2/enforcement/stream")) {
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
      res.write(`event: containment\ndata: ${JSON.stringify({ contained: false, snapshot: true })}\n\n`);
      clients.add(res);
      req.on("close", () => clients.delete(res));
      return;
    }
    res.writeHead(404);
    res.end("{}");
  });
  servers.push(server);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () =>
      resolve({
        base: `http://127.0.0.1:${server.address().port}`,
        answer(doc) {
          for (const res of clients) res.write(`event: approval\ndata: ${JSON.stringify({ resolution: doc, snapshot: false })}\n\n`);
        },
        get clientCount() { return clients.size; },
        receipts,
      }),
    );
  });
}

function writeCreds(home, base) {
  const dir = path.join(home, ".vaibot");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, "credentials.json"),
    JSON.stringify({
      version: 3,
      active_env: "staging",
      environments: { staging: { api_key: "vbk_test_key", governance: { url: base }, provenance: { url: null } } },
    }),
  );
}

async function startGuard(cp, label) {
  const port = await reservePort();
  const home = fs.mkdtempSync(path.join(tmpRoot, `home-${label}-`));
  const logDir = path.join(tmpRoot, `log-${label}`);
  fs.mkdirSync(logDir, { recursive: true });
  writeCreds(home, cp.base);
  const proc = spawn(process.execPath, [SERVICE_PATH], {
    env: {
      ...process.env,
      HOME: home, // never touch the developer's live rendezvous lock
      VAIBOT_GUARD_HOST: "127.0.0.1",
      VAIBOT_GUARD_PORT: String(port),
      VAIBOT_GUARD_TOKEN: `tok-${label}`,
      VAIBOT_POLICY_PATH: POLICY_PATH,
      VAIBOT_WORKSPACE: tmpRoot,
      VAIBOT_GUARD_LOG_DIR: logDir,
      VAIBOT_PROVE_MODE: "off",
      VAIBOT_POLICY_URL: "off",
      VAIBOT_POLICY_PUBKEY: serverPub,
      VAIBOT_ENV: "staging",
      VAIBOT_API_KEY: "vbk_test_key",
      VAIBOT_GOVERNANCE_URL: cp.base,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  guards.push(proc);
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/health`);
      if (r.ok) break;
    } catch { /* not up yet */ }
    await delay(100);
  }
  // Mode and stream come up on their own timers.
  for (let i = 0; i < 60 && cp.clientCount === 0; i++) await delay(100);
  for (let i = 0; i < 30; i++) {
    const h = await fetch(`http://127.0.0.1:${port}/health`).then((r) => r.json()).catch(() => ({}));
    if (h?.effective_mode === "enforce" || h?.mode === "enforce") break;
    await delay(100);
  }
  const call = (route, body) =>
    fetch(`http://127.0.0.1:${port}${route}`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer tok-${label}` },
      body: JSON.stringify(body),
    }).then(async (r) => ({ status: r.status, body: await r.json() }));
  return { port, call };
}

const statusOf = async (g, approvalId) => (await g.call("/v1/approvals/status", { approvalIds: [approvalId] })).body.approvals[0];

async function waitFor(fn, ms = 3000) {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v || Date.now() > end) return v;
    await delay(50);
  }
}

test.after(() => {
  for (const g of guards) { try { g.kill("SIGKILL"); } catch { /* gone */ } }
  for (const s of servers) { try { s.close(); } catch { /* closed */ } }
});

test("a gated call is held, posted as pending, and a signed phone answer approves it", async () => {
  const cp = await startControlPlane();
  const g = await startGuard(cp, "a");
  const d = await g.call("/v1/decide/tool", {
    sessionId: "s1", toolName: "WebFetch", params: { url: "https://unlisted.example.net/x" }, workspaceDir: tmpRoot,
  });
  assert.equal(d.body.decision.decision, "approve");

  const h = await g.call("/v1/hold", { runId: d.body.runId, sessionId: "s1" });
  assert.equal(h.status, 200);
  assert.equal(h.body.held, true);
  assert.equal(h.body.approvalId, d.body.decision.approvalId);
  assert.deepEqual(h.body.channels, { authenticator: true, email: true, dashboard: true });

  const posted = cp.receipts.find((r) => r?.run_id === d.body.runId);
  assert.ok(posted, "the hold is posted to the control plane");
  assert.equal(posted.approval.status, "pending");
  assert.equal(posted.idempotency_key, `${d.body.runId}:hold`);
  assert.match(posted.result.summary, /^Held for approval — the action has not run\./);

  cp.answer(signAnswer({ runId: d.body.runId, contentHash: h.body.contentHash, status: "approved" }));
  const st = await waitFor(async () => { const s = await statusOf(g, h.body.approvalId); return s.status === "approved" ? s : null; });
  assert.ok(st, "approved after the signed answer");
  assert.equal(st.resolutionSource, "authenticator");
});

test("an answer signed with another key, or for another receipt, changes nothing", async () => {
  const cp = await startControlPlane();
  const g = await startGuard(cp, "b");
  const d = await g.call("/v1/decide/tool", {
    sessionId: "s1", toolName: "WebFetch", params: { url: "https://unlisted.example.net/y" }, workspaceDir: tmpRoot,
  });
  const h = await g.call("/v1/hold", { runId: d.body.runId, sessionId: "s1" });
  cp.answer(signAnswer({ runId: d.body.runId, contentHash: h.body.contentHash, status: "approved", key: otherKey }));
  cp.answer(signAnswer({ runId: d.body.runId, contentHash: "0xsomething_else", status: "approved" }));
  await delay(400);
  assert.equal((await statusOf(g, h.body.approvalId)).status, "pending");

  // The real answer still lands afterwards.
  cp.answer(signAnswer({ runId: d.body.runId, contentHash: h.body.contentHash, status: "denied", source: "email" }));
  const st = await waitFor(async () => { const s = await statusOf(g, h.body.approvalId); return s.status === "denied" ? s : null; });
  assert.ok(st);
  assert.equal(st.resolutionSource, "email");
});

test("a held call can be refused locally but never approved locally", async () => {
  const cp = await startControlPlane();
  const g = await startGuard(cp, "c");
  const d = await g.call("/v1/decide/tool", {
    sessionId: "s1", toolName: "WebFetch", params: { url: "https://unlisted.example.net/z" }, workspaceDir: tmpRoot,
  });
  const h = await g.call("/v1/hold", { runId: d.body.runId, sessionId: "s1" });
  const approve = await g.call("/v1/approvals/resolve", { approvalId: h.body.approvalId, action: "approve" });
  assert.equal(approve.status, 403);
  assert.equal(approve.body.error, "held_approval");
  assert.equal((await statusOf(g, h.body.approvalId)).status, "pending");
  const deny = await g.call("/v1/approvals/resolve", { approvalId: h.body.approvalId, action: "deny" });
  assert.equal(deny.status, 200);
  assert.equal((await statusOf(g, h.body.approvalId)).status, "denied");
});

test("a call the guard allowed is still held when the host asks the person", async () => {
  const cp = await startControlPlane();
  const g = await startGuard(cp, "d");
  const file = path.join(tmpRoot, "route-supervisor.tsx");
  const d = await g.call("/v1/decide/tool", {
    sessionId: "s1", toolName: "Write", params: { file_path: file, content: "x" }, workspaceDir: tmpRoot,
  });
  assert.equal(d.body.decision.decision, "allow");
  const h = await g.call("/v1/hold", { runId: d.body.runId, sessionId: "s1" });
  assert.equal(h.body.held, true);
  assert.ok(h.body.approvalId);
  const posted = cp.receipts.find((r) => r?.run_id === d.body.runId);
  assert.equal(posted.policy.decision, "approval_required");
  assert.equal(posted.approval.status, "pending");

  // Its finalize is posted even though a workspace write is a ledger-tier call.
  const before = cp.receipts.length;
  await g.call("/v1/finalize/tool", {
    runId: d.body.runId, sessionId: "s1",
    result: { ok: true, approval: "approved" },
  });
  await waitFor(async () => cp.receipts.length > before);
  const fin = cp.receipts.filter((r) => r?.run_id === d.body.runId);
  assert.equal(fin.length, 2);
  assert.equal(fin[1].idempotency_key, `${d.body.runId}:finalize`);
});

test("hold refuses a run from another session, and an unknown run", async () => {
  const cp = await startControlPlane();
  const g = await startGuard(cp, "e");
  const d = await g.call("/v1/decide/tool", {
    sessionId: "s1", toolName: "WebFetch", params: { url: "https://unlisted.example.net/w" }, workspaceDir: tmpRoot,
  });
  assert.equal((await g.call("/v1/hold", { runId: d.body.runId, sessionId: "other" })).status, 403);
  assert.equal((await g.call("/v1/hold", { runId: "run_nope", sessionId: "s1" })).status, 404);
});

test("signed answers: verification and the held-record transition are fail-closed", () => {
  const doc = signAnswer({ runId: "run_1", contentHash: "0xh", status: "approved" });
  assert.equal(verifyApprovalResolution(doc, serverPub).ok, true);
  assert.equal(verifyApprovalResolution({ ...doc, status: "denied" }, serverPub).reason, "bad-signature");
  assert.equal(verifyApprovalResolution(signAnswer({ runId: "run_1", contentHash: "0xh", status: "approved", ttlMs: -1 }), serverPub).reason, "expired");
  assert.equal(verifyApprovalResolution({ ...doc, status: "granted" }, serverPub).reason, "bad-status");
  // Neither document passes as the other.
  assert.equal(verifyBundle(doc, serverPub).ok, false);

  const answer = verifyApprovalResolution(doc, serverPub).answer;
  const pending = { held: true, runId: "run_1", serverContentHash: "0xh", status: "pending", expiresAt: new Date(Date.now() + 60_000).toISOString() };
  assert.equal(heldApprovalTransition(pending, answer).status, "approved");
  for (const rec of [
    { ...pending, held: false },
    { ...pending, runId: "run_2" },
    { ...pending, serverContentHash: "0xother" },
    { ...pending, status: "denied" },
    { ...pending, status: "used" },
    { ...pending, expiresAt: new Date(Date.now() - 1).toISOString() },
  ]) {
    assert.equal(heldApprovalTransition(rec, answer), null);
  }
  // An approval is short-lived once given.
  const next = heldApprovalTransition({ ...pending, expiresAt: new Date(Date.now() + 3_600_000).toISOString() }, answer, { redeemMs: 60_000 });
  assert.ok(Date.parse(next.expiresAt) <= Date.now() + 60_000);
});
