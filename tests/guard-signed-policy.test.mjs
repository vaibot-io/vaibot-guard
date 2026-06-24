import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPair, signBundle, POLICY_BUNDLE_SCHEMA } from "../scripts/policy-bundle.mjs";

// Exercises D's signed-policy path end-to-end through the live guard:
//  - a denylisted tool is denied by the signed safety floor,
//  - the classifier deny-layer still fires alongside it,
//  - a tampered bundle fails CLOSED (denylist ignored, never relaxes posture).

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVICE_PATH = path.resolve(__dirname, "..", "scripts", "vaibot-guard-service.mjs");
const POLICY_PATH = path.resolve(__dirname, "..", "references", "policy.default.json");

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "vaibot-guard-signed-"));
const { publicKey, privateKey } = generateKeyPair();

function makeUnsigned(overrides = {}) {
  return {
    schema: POLICY_BUNDLE_SCHEMA,
    version: "2026.05.29",
    issuer: "vaibot",
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    policy: { denylist: ["DangerousTool"] },
    ...overrides,
  };
}

const servers = [];

async function startGuard({ bundlePath, publicKeyPem }) {
  const port = 41200 + Math.floor(Math.random() * 2000);
  const token = "signed-policy-token";
  const logDir = path.join(tmpRoot, `.guard-${port}`);
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
    VAIBOT_POLICY_BUNDLE_PATH: bundlePath,
    VAIBOT_POLICY_PUBKEY: publicKeyPem,
  };
  const server = spawn(process.execPath, [SERVICE_PATH], { env, stdio: ["ignore", "pipe", "pipe"] });
  servers.push(server);

  for (let i = 0; i < 40; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/health`);
      if (res.ok) break;
    } catch {
      // not up yet
    }
    await delay(100);
  }

  return async function postJson(pathname, body) {
    const res = await fetch(`http://127.0.0.1:${port}${pathname}`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    return { status: res.status, data };
  };
}

test("signed denylist denies a denylisted tool; classifier coexists; non-listed safe read allowed", async () => {
  const bundlePath = path.join(tmpRoot, "valid.bundle.json");
  fs.writeFileSync(bundlePath, JSON.stringify(signBundle(makeUnsigned(), privateKey)));
  const post = await startGuard({ bundlePath, publicKeyPem: publicKey });

  const denied = await post("/v1/decide/tool", {
    sessionId: "s1",
    toolName: "DangerousTool",
    params: {},
    workspaceDir: tmpRoot,
  });
  assert.equal(denied.status, 200);
  assert.equal(denied.data.decision.decision, "deny");
  assert.match(denied.data.decision.reason, /signed policy denylist/);

  const classifierDeny = await post("/v1/decide/tool", {
    sessionId: "s1",
    toolName: "bash",
    params: { command: "rm -rf /" },
    workspaceDir: tmpRoot,
  });
  assert.equal(classifierDeny.data.decision.decision, "deny");
  assert.match(classifierDeny.data.decision.reason, /Classifier/);

  const allowed = await post("/v1/decide/tool", {
    sessionId: "s1",
    toolName: "read",
    params: { path: "README.md" },
    workspaceDir: tmpRoot,
  });
  assert.equal(allowed.data.decision.decision, "allow");
});

test("a tampered bundle fails closed — signed denylist is ignored, posture not relaxed", async () => {
  // Sign a real bundle, then mutate the policy after signing so the signature
  // no longer matches. The guard must reject it and fall back to built-ins.
  const signed = signBundle(makeUnsigned(), privateKey);
  signed.policy = { denylist: ["DangerousTool", "AnotherTool"] };
  const bundlePath = path.join(tmpRoot, "tampered.bundle.json");
  fs.writeFileSync(bundlePath, JSON.stringify(signed));
  const post = await startGuard({ bundlePath, publicKeyPem: publicKey });

  // DangerousTool is no longer blocked by the (ignored) signed denylist. It is
  // an unknown tool, so it is NOT denied with the signed-policy reason.
  const res = await post("/v1/decide/tool", {
    sessionId: "s2",
    toolName: "DangerousTool",
    params: {},
    workspaceDir: tmpRoot,
  });
  assert.equal(res.status, 200);
  assert.doesNotMatch(res.data.decision.reason || "", /signed policy denylist/);

  // Built-in classifier safety floor still denies destructive commands.
  const stillDenied = await post("/v1/decide/tool", {
    sessionId: "s2",
    toolName: "bash",
    params: { command: "rm -rf /" },
    workspaceDir: tmpRoot,
  });
  assert.equal(stillDenied.data.decision.decision, "deny");
});

test.after(() => {
  for (const s of servers) if (!s.killed) s.kill("SIGTERM");
  try {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  } catch {
    // best effort
  }
});
