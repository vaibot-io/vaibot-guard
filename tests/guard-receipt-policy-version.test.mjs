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

// #17: a governance receipt the guard emits names the SIGNED policy bundle
// version that governed the decision (so a decision is joinable to its policy,
// and — server-side — to the on-chain anchor). The guard sends policy_version;
// the server resolves policy_hash. Here we capture the outbound receipt POST and
// assert policy_version == the active signed bundle's version.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_PATH = path.resolve(__dirname, "..", "scripts", "vaibot-guard-service.mjs");
const POLICY_PATH = path.resolve(__dirname, "..", "references", "policy.default.json");

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "vaibot-guard-pv-"));
const { publicKey, privateKey } = generateKeyPair();
const BUNDLE_VERSION = "2026.06.05-pvtest";

const servers = [];
const httpServers = [];

function waitUntil(fn, { timeoutMs = 6000, intervalMs = 100 } = {}) {
  return (async () => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (await fn()) return true;
      await delay(intervalMs);
    }
    return false;
  })();
}

test("#17: the guard's governance receipt carries the signed policy_version", async () => {
  // Mock V2 receipts sink — capture POST /api/v2/receipts bodies.
  const captured = [];
  const sink = createServer((req, res) => {
    if (req.method === "POST" && req.url === "/api/v2/receipts") {
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

  // Active signed bundle provided via a local cache file (source = 'bundle').
  const bundle = signBundle(
    {
      schema: POLICY_BUNDLE_SCHEMA,
      version: BUNDLE_VERSION,
      issuer: "vaibot",
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
      policy: { denylist: ["DangerousTool"] },
    },
    privateKey,
  );
  const logDir = path.join(tmpRoot, "pv");
  fs.mkdirSync(logDir, { recursive: true });
  const bundlePath = path.join(logDir, "policy.bundle.json");
  fs.writeFileSync(bundlePath, JSON.stringify(bundle));

  const port = 49200 + Math.floor(Math.random() * 1500);
  const token = "pv-token";
  const guard = spawn(process.execPath, [SERVICE_PATH], {
    env: {
      ...process.env,
      VAIBOT_GUARD_HOST: "127.0.0.1",
      VAIBOT_GUARD_PORT: String(port),
      VAIBOT_GUARD_TOKEN: token,
      VAIBOT_POLICY_PATH: POLICY_PATH,
      VAIBOT_WORKSPACE: tmpRoot,
      VAIBOT_GUARD_LOG_DIR: logDir,
      VAIBOT_PROVE_MODE: "off",
      VAIBOT_POLICY_BUNDLE_PATH: bundlePath,
      VAIBOT_POLICY_PUBKEY: publicKey,
      VAIBOT_API_URL: `http://127.0.0.1:${sinkPort}/api`,
      VAIBOT_API_KEY: "test-key",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  servers.push(guard);

  const healthy = await waitUntil(async () => {
    try { return (await fetch(`http://127.0.0.1:${port}/health`)).ok; } catch { return false; }
  });
  assert.equal(healthy, true, "guard should become healthy");

  async function post(pathname, body) {
    const res = await fetch(`http://127.0.0.1:${port}${pathname}`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    return (await res.json().catch(() => ({})));
  }

  // A write tool earns a tier-2 receipt (egress) → finalize posts the receipt.
  const decided = await post("/v1/decide/tool", {
    sessionId: "pv-sess",
    toolName: "write",
    params: { file_path: path.join(tmpRoot, "out.txt"), content: "x" },
    workspaceDir: tmpRoot,
  });
  assert.equal(decided.receiptTier, "receipt");
  assert.ok(decided.runId);

  await post("/v1/finalize/tool", { sessionId: "pv-sess", runId: decided.runId, result: { ok: true } });

  const got = await waitUntil(() => captured.length > 0);
  assert.equal(got, true, "the guard should POST a governance receipt");
  assert.equal(captured[0].policy.policy_version, BUNDLE_VERSION);
});

test.after(async () => {
  for (const g of servers) if (!g.killed) g.kill("SIGTERM");
  for (const s of httpServers) { try { s.close(); } catch { /* best effort */ } }
  await delay(100);
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch { /* best effort */ }
});
