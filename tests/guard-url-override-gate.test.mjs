// §5: the guard's production URL-override admin gate (confirm-then-apply).
//
// A flag-enabled production VAIBOT_GOVERNANCE_URL override must NOT be used to send
// the bearer key until the /me poll (against the CANONICAL host) confirms an admin
// account. We model "canonical" with a STORED governance slot (so a mock server is
// canonical) and the override with VAIBOT_GOVERNANCE_URL pointing at a second mock.
//   - /me returns admin:false  -> override refused, governance receipts go to canonical
//   - /me returns admin:true   -> override applied,  governance receipts go to override
import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_PATH = path.resolve(__dirname, "..", "scripts", "vaibot-guard-service.mjs");
const POLICY_PATH = path.resolve(__dirname, "..", "references", "policy.default.json");

const procs = [];
const httpServers = [];

function waitUntil(fn, { timeoutMs = 8000, intervalMs = 50 } = {}) {
  return (async () => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (await fn()) return true;
      await delay(intervalMs);
    }
    return false;
  })();
}

// A governance mock: counts /me polls and captures POST /v2/receipts. `admin`
// controls the /me admin verdict.
function governanceMock(admin) {
  const state = { mePolls: 0, receipts: 0 };
  const server = createServer((req, res) => {
    if (req.method === "GET" && req.url === "/v2/accounts/me") {
      state.mePolls++;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ user_id: "u", admin, enforcement: { effective_mode: "enforce" } }));
      return;
    }
    if (req.method === "POST" && req.url === "/v2/receipts") {
      state.receipts++;
      let body = "";
      req.on("data", (c) => { body += c; });
      req.on("end", () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, content_hash: "0xtest" }));
      });
      return;
    }
    res.writeHead(404); res.end("{}");
  });
  httpServers.push(server);
  return { state, server };
}

async function listen(server) {
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r(`http://127.0.0.1:${server.address().port}`)));
}

async function startGuardWithOverride({ adminVerdict }) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "vaibot-ovr-home-"));
  const logDir = path.join(home, "logs");
  fs.mkdirSync(logDir, { recursive: true });

  // canonical = a stored governance slot (so it's a mock we control, not api.vaibot.io)
  const canonical = governanceMock(adminVerdict);
  const override = governanceMock(adminVerdict); // override's /me is never consulted
  const canonicalUrl = await listen(canonical.server);
  const overrideUrl = await listen(override.server);

  // prod creds with the canonical mock pinned as the stored governance slot.
  fs.mkdirSync(path.join(home, ".vaibot"), { recursive: true });
  fs.writeFileSync(
    path.join(home, ".vaibot", "credentials.json"),
    JSON.stringify({
      version: 3,
      active_env: "production",
      environments: { production: { api_key: "vb_live_test", governance: { url: canonicalUrl } } },
    }),
  );

  const port = 50_300 + Math.floor(Math.random() * 1200);
  const token = "ovr-token";
  const guard = spawn(process.execPath, [SERVICE_PATH], {
    env: {
      ...process.env,
      HOME: home,
      // creds dir resolves via os.homedir()/$VAIBOT_CREDS_DIR (NOT $HOME) — pin it.
      VAIBOT_CREDS_DIR: path.join(home, ".vaibot"),
      // neutralize any leaked env-resolution signals so CREDS_ENV is decided by the
      // creds file (production) — a leaked VAIBOT_API_URL/VAIBOT_ENV would mis-resolve.
      VAIBOT_ENV: "",
      VAIBOT_API_URL: "",
      VAIBOT_GUARD_HOST: "127.0.0.1",
      VAIBOT_GUARD_PORT: String(port),
      VAIBOT_GUARD_TOKEN: token,
      VAIBOT_POLICY_PATH: POLICY_PATH,
      VAIBOT_WORKSPACE: home,
      VAIBOT_GUARD_LOG_DIR: logDir,
      VAIBOT_PROVE_MODE: "off",
      VAIBOT_POLICY_URL: "off",
      // the deliberate-act flag + a prod override pointing at the OTHER mock
      VAIBOT_ALLOW_URL_OVERRIDE: "1",
      VAIBOT_GOVERNANCE_URL: overrideUrl,
      VAIBOT_MODE_REFRESH_MS: "1000",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  procs.push(guard);

  const healthy = await waitUntil(async () => {
    try { return (await fetch(`http://127.0.0.1:${port}/health`)).ok; } catch { return false; }
  });
  assert.equal(healthy, true, "guard should become healthy");
  return { port, token, canonical, override, home };
}

async function finalizeAWrite(port, token, home) {
  const post = async (p, body) =>
    (await (await fetch(`http://127.0.0.1:${port}${p}`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    })).json().catch(() => ({})));
  const decided = await post("/v1/decide/tool", {
    sessionId: "s", toolName: "write",
    params: { file_path: path.join(home, "out.txt"), content: "x" }, workspaceDir: home,
  });
  await post("/v1/finalize/tool", { sessionId: "s", runId: decided.runId, result: { ok: true } });
}

test("non-admin: a flag-enabled prod override is refused — receipts stay on canonical", async () => {
  const { port, token, canonical, override, home } = await startGuardWithOverride({ adminVerdict: false });
  // wait until the /me poll ran (override decision resolved)
  assert.equal(await waitUntil(() => canonical.state.mePolls >= 1), true, "guard should poll canonical /me");
  await finalizeAWrite(port, token, home);
  assert.equal(await waitUntil(() => canonical.state.receipts >= 1), true, "receipt should land on the canonical host");
  await delay(200);
  assert.equal(override.state.receipts, 0, "a non-admin's override must NEVER receive the bearer key");
  assert.equal(override.state.mePolls, 0, "the admin check must use the canonical host, never the override");
});

test("admin: a flag-enabled prod override is applied — receipts go to the override", async () => {
  const { port, token, canonical, override, home } = await startGuardWithOverride({ adminVerdict: true });
  assert.equal(await waitUntil(() => canonical.state.mePolls >= 1), true, "guard should poll canonical /me");
  // give applyProdOverride() a beat to switch the base after the poll
  assert.equal(await waitUntil(() => override.state.mePolls === 0), true);
  await delay(300);
  await finalizeAWrite(port, token, home);
  assert.equal(await waitUntil(() => override.state.receipts >= 1), true, "an admin's override should receive receipts");
});

test.after(async () => {
  for (const p of procs) if (!p.killed) p.kill("SIGTERM");
  for (const s of httpServers) { try { s.close(); } catch { /* best effort */ } }
  await delay(100);
});
