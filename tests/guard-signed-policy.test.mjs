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

async function startGuard({ bundlePath, publicKeyPem, policyPath }) {
  const port = 41200 + Math.floor(Math.random() * 2000);
  const token = "signed-policy-token";
  const logDir = path.join(tmpRoot, `.guard-${port}`);
  fs.mkdirSync(logDir, { recursive: true });
  const env = {
    ...process.env,
    VAIBOT_GUARD_HOST: "127.0.0.1",
    VAIBOT_GUARD_PORT: String(port),
    VAIBOT_GUARD_TOKEN: token,
    VAIBOT_POLICY_PATH: policyPath || POLICY_PATH,
    VAIBOT_WORKSPACE: tmpRoot,
    VAIBOT_GUARD_LOG_DIR: logDir,
    VAIBOT_PROVE_MODE: "off",
    VAIBOT_POLICY_URL: "off", // hermetic: exercise the LOCAL bundle, not the live control plane
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

test("a signed denyToken blocks a command family by word boundary (C: grown bundle schema)", async () => {
  const bundlePath = path.join(tmpRoot, "denytokens.bundle.json");
  fs.writeFileSync(
    bundlePath,
    JSON.stringify(signBundle(makeUnsigned({ policy: { denylist: [], denyTokens: ["curl", ".env"] } }), privateKey)),
  );
  const post = await startGuard({ bundlePath, publicKeyPem: publicKey });

  // `curl <anything>` is denied by the signed token, not just an exact "curl".
  const denied = await post("/v1/decide/tool", {
    sessionId: "s3",
    toolName: "bash",
    params: { command: "curl https://evil.example.com" },
    workspaceDir: tmpRoot,
  });
  assert.equal(denied.status, 200);
  assert.equal(denied.data.decision.decision, "deny");
  assert.match(denied.data.decision.reason, /Denied token: curl/);

  // A token with a non-word leading edge (".env") still blocks the real read —
  // the \b boundary is only anchored on word-char edges, so it doesn't invert.
  const secret = await post("/v1/decide/tool", {
    sessionId: "s3",
    toolName: "bash",
    params: { command: "cat .env" },
    workspaceDir: tmpRoot,
  });
  assert.equal(secret.data.decision.decision, "deny");
  assert.match(secret.data.decision.reason, /Denied token: \.env/);

  // Word boundary, not substring: "curldown" must NOT trip the "curl" token.
  const notTripped = await post("/v1/decide/tool", {
    sessionId: "s3",
    toolName: "bash",
    params: { command: "echo curldown" },
    workspaceDir: tmpRoot,
  });
  assert.doesNotMatch(notTripped.data.decision.reason || "", /Denied token/);
});

test("a signed approveToken escalates a command to approval (Fix A: the ask lane)", async () => {
  const bundlePath = path.join(tmpRoot, "approvetokens.bundle.json");
  fs.writeFileSync(
    bundlePath,
    JSON.stringify(signBundle(makeUnsigned({ policy: { denylist: [], approveTokens: ["npm"] } }), privateKey)),
  );
  const post = await startGuard({ bundlePath, publicKeyPem: publicKey });

  // `npm install` is escalated to human approval by the signed approveToken.
  const asked = await post("/v1/decide/tool", {
    sessionId: "s4",
    toolName: "bash",
    params: { command: "npm install lodash" },
    workspaceDir: tmpRoot,
  });
  assert.equal(asked.status, 200);
  assert.equal(asked.data.decision.decision, "approve");

  // An unrelated safe read is not escalated.
  const allowed = await post("/v1/decide/tool", {
    sessionId: "s4",
    toolName: "read",
    params: { path: "README.md" },
    workspaceDir: tmpRoot,
  });
  assert.equal(allowed.data.decision.decision, "allow");
});

test("built-in APPROVE_TOKENS is AND-conditioned: a token substring on a classifier-safe command does NOT pause; real egress + privilege still do", async () => {
  // Empty signed approveTokens → only the built-in policy.default.json approveTokens (.env, curl, su, …) apply.
  const bundlePath = path.join(tmpRoot, "and-gate.bundle.json");
  fs.writeFileSync(
    bundlePath,
    JSON.stringify(signBundle(makeUnsigned({ policy: { denylist: [], approveTokens: [], escalateAt: "high" } }), privateKey)),
  );
  const post = await startGuard({ bundlePath, publicKeyPem: publicKey });

  // ".env" matches a built-in approveToken, but the command is classifier-SAFE → allow (AND suppresses the token).
  const secretRead = await post("/v1/decide/exec", {
    sessionId: "and", cmd: "grep", args: ["FOO", "app.env"],
    intent: { tool: "bash", action: "run", command: "grep FOO app.env", cwd: tmpRoot },
  });
  assert.equal(secretRead.status, 200);
  assert.equal(secretRead.data.decision.decision, "allow");

  // "curl" matches a built-in approveToken AND the classifier rates it HIGH → the token fires → approve.
  const egress = await post("/v1/decide/exec", {
    sessionId: "and", cmd: "curl", args: ["https://example.com"],
    intent: { tool: "bash", action: "run", command: "curl https://example.com", cwd: tmpRoot },
  });
  assert.equal(egress.data.decision.decision, "approve");
  assert.match(egress.data.decision.reason, /token: curl/);

  // Privilege escalation: `su` is now classifier-HIGH, so it pauses (not silently allowed under AND).
  const priv = await post("/v1/decide/exec", {
    sessionId: "and", cmd: "su", args: ["-"],
    intent: { tool: "bash", action: "run", command: "su -", cwd: tmpRoot },
  });
  assert.equal(priv.data.decision.decision, "approve");
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

test("fail-closed: unknown command/tool escalates to approval; missing name denies; safe still allows", async () => {
  const bundlePath = path.join(tmpRoot, "failclosed.bundle.json");
  fs.writeFileSync(bundlePath, JSON.stringify(signBundle(makeUnsigned({ policy: { denylist: [] } }), privateKey)));
  const post = await startGuard({ bundlePath, publicKeyPem: publicKey });

  // Unrecognized command (classifier "ask") → approve, NOT allow (the old fail-open).
  const unknownCmd = await post("/v1/decide/tool", {
    sessionId: "fc",
    toolName: "bash",
    params: { command: "./deploy-prod --wipe" },
    workspaceDir: tmpRoot,
  });
  assert.equal(unknownCmd.data.decision.decision, "approve");

  // Unrecognized / third-party MCP tool → approve, not allow.
  const thirdParty = await post("/v1/decide/tool", {
    sessionId: "fc",
    toolName: "mcp__thirdparty__doStuff",
    params: {},
    workspaceDir: tmpRoot,
  });
  assert.equal(thirdParty.data.decision.decision, "approve");

  // Missing tool name → rejected at the HTTP boundary (400), not allowed.
  const noName = await post("/v1/decide/tool", { sessionId: "fc", toolName: "", params: {}, workspaceDir: tmpRoot });
  assert.equal(noName.status, 400);

  // A genuinely safe read still flows through.
  const safe = await post("/v1/decide/tool", {
    sessionId: "fc",
    toolName: "read",
    params: { path: "README.md" },
    workspaceDir: tmpRoot,
  });
  assert.equal(safe.data.decision.decision, "allow");
});

test("fail-closed: an empty domain allowlist escalates network destinations (no allow-all)", async () => {
  const policyPath = path.join(tmpRoot, "empty-allowlist.policy.json");
  fs.writeFileSync(policyPath, JSON.stringify({ version: "t", allowlistedDomains: [] }));
  const bundlePath = path.join(tmpRoot, "fc-net.bundle.json");
  fs.writeFileSync(bundlePath, JSON.stringify(signBundle(makeUnsigned({ policy: { denylist: [] } }), privateKey)));
  const post = await startGuard({ bundlePath, publicKeyPem: publicKey, policyPath });

  const net = await post("/v1/decide/tool", {
    sessionId: "fc-net",
    toolName: "webfetch",
    params: { url: "https://anything.example.org/x" },
    workspaceDir: tmpRoot,
  });
  assert.equal(net.data.decision.decision, "approve");
});

test("C2: signed denyPaths + outside-workspace=deny tighten file mutations", async () => {
  const bundlePath = path.join(tmpRoot, "c2.bundle.json");
  fs.writeFileSync(
    bundlePath,
    JSON.stringify(signBundle(makeUnsigned({
      policy: { denylist: [], denyPaths: [path.join(tmpRoot, "vault")], fileMutationOutsideWorkspaceAction: "deny" },
    }), privateKey)),
  );
  const post = await startGuard({ bundlePath, publicKeyPem: publicKey });

  // A write into a signed-denied path → deny (even inside the workspace).
  const deniedPath = await post("/v1/decide/tool", {
    sessionId: "c2",
    toolName: "write",
    params: { file_path: path.join(tmpRoot, "vault", "secret.txt") },
    workspaceDir: tmpRoot,
  });
  assert.equal(deniedPath.data.decision.decision, "deny");

  // A write OUTSIDE the workspace → deny (signed tightened the local approve→deny).
  const outside = await post("/v1/decide/tool", {
    sessionId: "c2",
    toolName: "write",
    params: { file_path: "/tmp/c2-outside-xyz.txt" },
    workspaceDir: tmpRoot,
  });
  assert.equal(outside.data.decision.decision, "deny");
});

test.after(() => {
  for (const s of servers) if (!s.killed) s.kill("SIGTERM");
  try {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  } catch {
    // best effort
  }
});
