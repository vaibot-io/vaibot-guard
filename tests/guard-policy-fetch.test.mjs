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

// Distribution wiring: the guard pulls the active signed bundle from the control
// plane (GET /v2/policy) at startup via VAIBOT_POLICY_URL, verifies it against
// the pinned public key, caches it, and enforces it. Fail-closed: an unverified
// (tampered) bundle is never cached — the guard falls back to built-in defaults.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_PATH = path.resolve(__dirname, "..", "scripts", "vaibot-guard-service.mjs");
const POLICY_PATH = path.resolve(__dirname, "..", "references", "policy.default.json");

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "vaibot-guard-fetch-"));
const { publicKey, privateKey } = generateKeyPair();
const httpServers = [];
const guards = [];

function signed(denylist) {
  return signBundle(
    {
      schema: POLICY_BUNDLE_SCHEMA,
      version: "2026.06.03",
      issuer: "vaibot",
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
      policy: { denylist },
    },
    privateKey,
  );
}

function startPolicyServer(makeBody) {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      if (req.url === "/v2/policy") {
        const { status, json } = makeBody();
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(json));
        return;
      }
      res.writeHead(404);
      res.end("{}");
    });
    httpServers.push(server);
    server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${server.address().port}/v2/policy`));
  });
}

async function startGuard({ logDir, policyUrl, pubkey, refreshMs }) {
  const port = 47200 + Math.floor(Math.random() * 2000);
  fs.mkdirSync(logDir, { recursive: true });
  const env = {
    ...process.env,
    VAIBOT_GUARD_HOST: "127.0.0.1",
    VAIBOT_GUARD_PORT: String(port),
    VAIBOT_GUARD_TOKEN: "fetch-token",
    VAIBOT_POLICY_PATH: POLICY_PATH,
    VAIBOT_WORKSPACE: tmpRoot,
    VAIBOT_GUARD_LOG_DIR: logDir,
    VAIBOT_PROVE_MODE: "off",
    VAIBOT_POLICY_URL: policyUrl,
    VAIBOT_POLICY_PUBKEY: pubkey,
    ...(refreshMs ? { VAIBOT_POLICY_REFRESH_MS: String(refreshMs) } : {}),
  };
  const server = spawn(process.execPath, [SERVICE_PATH], { env, stdio: ["ignore", "pipe", "pipe"] });
  guards.push(server);

  let healthy = false;
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/health`);
      if (r.ok) { healthy = true; break; }
    } catch { /* not up yet */ }
    await delay(100);
  }
  assert.equal(healthy, true, "guard should become healthy");
  return { port };
}

test("guard fetches + verifies + enforces the active bundle from GET /v2/policy", async () => {
  const url = await startPolicyServer(() => ({
    status: 200,
    json: { ok: true, version: "2026.06.03", hash: "sha256:x", bundle: signed(["FetchedTool"]) },
  }));
  const { port } = await startGuard({ logDir: path.join(tmpRoot, "ok"), policyUrl: url, pubkey: publicKey });

  const data = await (await fetch(`http://127.0.0.1:${port}/v1/policy`)).json();
  assert.equal(data.source, "bundle");
  assert.equal(data.signature, "ok");
  assert.deepEqual(data.denylist, ["FetchedTool"]);

  // And it's actually enforced: the fetched denylisted tool is denied.
  const decided = await fetch(`http://127.0.0.1:${port}/v1/decide/tool`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer fetch-token" },
    body: JSON.stringify({ sessionId: "s1", toolName: "FetchedTool", params: {}, workspaceDir: tmpRoot }),
  });
  const dj = await decided.json();
  assert.equal(dj.decision.decision, "deny");
});

test("a tampered fetched bundle is NOT cached — guard falls back to built-in (fail-closed)", async () => {
  const url = await startPolicyServer(() => {
    const b = signed(["FetchedTool"]);
    b.policy = { denylist: ["FetchedTool", "Injected"] }; // mutate after signing → bad signature
    return { status: 200, json: { ok: true, bundle: b } };
  });
  const { port } = await startGuard({ logDir: path.join(tmpRoot, "tampered"), policyUrl: url, pubkey: publicKey });

  const data = await (await fetch(`http://127.0.0.1:${port}/v1/policy`)).json();
  assert.equal(data.source, "builtin");
  assert.deepEqual(data.denylist, []);
});

async function waitUntil(fn, { timeoutMs = 8000, intervalMs = 100 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await fn()) return true;
    await delay(intervalMs);
  }
  return false;
}

test("F-157: guard applies policy changes + revocation at runtime (refresh)", async () => {
  let phase = "v1";
  const url = await startPolicyServer(() => {
    if (phase === "v1") return { status: 200, json: { ok: true, bundle: signed(["ToolA"]) } };
    if (phase === "v2") return { status: 200, json: { ok: true, bundle: signed(["ToolB"]) } };
    return { status: 200, json: { ok: true, active: null } }; // revoked
  });
  const { port } = await startGuard({ logDir: path.join(tmpRoot, "refresh"), policyUrl: url, pubkey: publicKey, refreshMs: 1000 });
  const policy = async () => (await (await fetch(`http://127.0.0.1:${port}/v1/policy`)).json());

  // initial: ToolA enforced
  assert.deepEqual((await policy()).denylist, ["ToolA"]);

  // server publishes v2 → after a refresh the guard swaps it in live (ToolA gone)
  phase = "v2";
  const gotV2 = await waitUntil(async () => {
    const d = await policy();
    return d.source === "bundle" && d.denylist.includes("ToolB");
  });
  assert.equal(gotV2, true, "guard should pick up v2 within the refresh window");
  assert.deepEqual((await policy()).denylist, ["ToolB"]);

  // server revokes (no active policy) → guard reverts to built-in on next refresh
  phase = "revoked";
  const reverted = await waitUntil(async () => (await policy()).source === "builtin");
  assert.equal(reverted, true, "guard should honor revocation within the refresh window");
  assert.deepEqual((await policy()).denylist, []);
});

test.after(async () => {
  for (const g of guards) if (!g.killed) g.kill("SIGTERM");
  for (const s of httpServers) {
    try { s.close(); } catch { /* best effort */ }
  }
  await delay(100);
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch { /* best effort */ }
});
