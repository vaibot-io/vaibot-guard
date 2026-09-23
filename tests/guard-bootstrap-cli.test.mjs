import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

// `vaibot-guard bootstrap` — one-shot account provisioning for a breaker with no
// API key. Non-Node hosts (the Hermes Python plugin) call it so the shared
// credential store keeps a single writer.
//
// Every test points the CLI at a local fake control plane on the STAGING env with
// a throwaway credentials dir. Nothing here can reach the real API: a slip would
// mint a real account, which is exactly what this command does.

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "scripts", "vaibot-guard.mjs");

const FINGERPRINT = createHash("sha256").update(`${os.userInfo().username}@${os.hostname()}`).digest("hex");

/** A fake /v2/bootstrap that records requests and answers with `reply`. */
async function fakeControlPlane(reply) {
  const requests = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      requests.push({ method: req.method, url: req.url, body: body ? JSON.parse(body) : null });
      const { status, json } = reply;
      res.writeHead(status, { "content-type": "application/json" });
      res.end(typeof json === "string" ? json : JSON.stringify(json));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  return { url: `http://127.0.0.1:${port}`, requests, close: () => new Promise((r) => server.close(r)) };
}

function tmpHome() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "vaibot-bootstrap-cli-"));
  const credsDir = path.join(home, ".vaibot");
  return { home, credsDir, credsFile: path.join(credsDir, "credentials.json") };
}

/** Run the CLI hermetically: no inherited VAIBOT_* env, staging, local control plane. */
function runBootstrap(args, { home, credsDir }, governanceUrl) {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [CLI, "bootstrap", ...args],
      {
        env: {
          PATH: process.env.PATH,
          HOME: home,
          VAIBOT_CREDS_DIR: credsDir,
          VAIBOT_ENV: "staging",
          VAIBOT_GOVERNANCE_URL: governanceUrl,
        },
        timeout: 20_000,
      },
      (err, stdout, stderr) => resolve({ code: err?.code ?? 0, stdout: String(stdout), stderr: String(stderr) }),
    );
  });
}

function seed(credsDir, store) {
  fs.mkdirSync(credsDir, { recursive: true });
  fs.writeFileSync(path.join(credsDir, "credentials.json"), JSON.stringify(store));
}

test("bootstrap: provisions, saves the key to the store, and never prints it", async () => {
  const cp = await fakeControlPlane({
    status: 201,
    json: { ok: true, bootstrapped: true, api_key: "vb_stg_secretvalue123", wallet_address: "0xabc", wallet_network: "base-sepolia" },
  });
  const t = tmpHome();
  try {
    const r = await runBootstrap(["--agent", "hermes"], t, cp.url);
    assert.equal(r.code, 0, r.stderr);
    const out = JSON.parse(r.stdout.trim());
    assert.deepEqual(out, { ok: true, env: "staging", provisioned: true, wallet_address: "0xabc", wallet_network: "base-sepolia" });
    assert.ok(!r.stdout.includes("secretvalue"), "the key must not cross the process boundary");
    assert.ok(!r.stderr.includes("secretvalue"));

    assert.equal(cp.requests.length, 1);
    assert.equal(cp.requests[0].url, "/v2/bootstrap");
    assert.deepEqual(cp.requests[0].body, { fingerprint: FINGERPRINT, agent: "hermes" });

    const store = JSON.parse(fs.readFileSync(t.credsFile, "utf-8"));
    assert.equal(store.active_env, "staging");
    assert.equal(store.environments.staging.api_key, "vb_stg_secretvalue123");
    assert.equal(store.environments.staging.wallet_address, "0xabc");
    assert.equal(fs.statSync(t.credsFile).mode & 0o777, 0o600);
  } finally {
    await cp.close();
  }
});

test("bootstrap: a key that already resolves means no network call at all", async () => {
  const cp = await fakeControlPlane({ status: 201, json: { api_key: "vb_stg_other" } });
  const t = tmpHome();
  seed(t.credsDir, { version: 3, active_env: "staging", environments: { staging: { api_key: "vb_stg_existing" } } });
  try {
    const r = await runBootstrap(["--agent", "hermes"], t, cp.url);
    assert.equal(r.code, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout), { ok: true, env: "staging", provisioned: false, reason: "key-present" });
    assert.equal(cp.requests.length, 0);
    const store = JSON.parse(fs.readFileSync(t.credsFile, "utf-8"));
    assert.equal(store.environments.staging.api_key, "vb_stg_existing");
  } finally {
    await cp.close();
  }
});

test("bootstrap: an existing account with a lost key reports account-exists and writes nothing", async () => {
  const cp = await fakeControlPlane({ status: 200, json: { ok: true, bootstrapped: false, wallet_address: "0xabc" } });
  const t = tmpHome();
  try {
    const r = await runBootstrap(["--agent", "hermes"], t, cp.url);
    assert.equal(r.code, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout), { ok: true, env: "staging", provisioned: false, reason: "account-exists" });
    assert.equal(fs.existsSync(t.credsFile), false);
  } finally {
    await cp.close();
  }
});

test("bootstrap: merges into the store without touching the other environment", async () => {
  const cp = await fakeControlPlane({ status: 201, json: { api_key: "vb_stg_new", wallet_address: "0xdef" } });
  const t = tmpHome();
  seed(t.credsDir, {
    version: 3,
    active_env: "production",
    environments: { production: { api_key: "vb_live_keepme", wallet_address: "0x111" } },
  });
  try {
    const r = await runBootstrap(["--agent", "hermes"], t, cp.url);
    assert.equal(r.code, 0, r.stderr);
    const store = JSON.parse(fs.readFileSync(t.credsFile, "utf-8"));
    assert.equal(store.environments.production.api_key, "vb_live_keepme");
    assert.equal(store.environments.staging.api_key, "vb_stg_new");
  } finally {
    await cp.close();
  }
});

test("bootstrap: refuses to store a key issued for a different environment", async () => {
  const cp = await fakeControlPlane({ status: 201, json: { api_key: "vb_live_wrongenv" } });
  const t = tmpHome();
  try {
    const r = await runBootstrap(["--agent", "hermes"], t, cp.url);
    assert.notEqual(r.code, 0);
    assert.equal(r.stdout, "");
    assert.equal(fs.existsSync(t.credsFile), false);
  } finally {
    await cp.close();
  }
});

// Every failure exits non-zero with nothing on stdout, so a caller can't read a
// broken run as an answer.
for (const [name, reply] of [
  ["a 5xx", { status: 503, json: { error: "down" } }],
  ["a 4xx", { status: 429, json: { error: "rate_limited" } }],
  ["invalid JSON", { status: 201, json: "not json{" }],
  ["an answer with neither key nor account", { status: 201, json: { ok: true } }],
]) {
  test(`bootstrap: ${name} is a failure to answer`, async () => {
    const cp = await fakeControlPlane(reply);
    const t = tmpHome();
    try {
      const r = await runBootstrap(["--agent", "hermes"], t, cp.url);
      assert.notEqual(r.code, 0);
      assert.equal(r.stdout, "");
      assert.equal(fs.existsSync(t.credsFile), false);
    } finally {
      await cp.close();
    }
  });
}

test("bootstrap: an unreachable control plane is a failure to answer", async () => {
  const cp = await fakeControlPlane({ status: 201, json: {} });
  const url = cp.url;
  await cp.close(); // nothing listening on that port now
  const r = await runBootstrap(["--agent", "hermes", "--timeout-ms", "2000"], tmpHome(), url);
  assert.notEqual(r.code, 0);
  assert.equal(r.stdout, "");
});

test("bootstrap: --agent is required and validated before any request", async () => {
  const cp = await fakeControlPlane({ status: 201, json: { api_key: "vb_stg_x" } });
  try {
    for (const args of [[], ["--agent"], ["--agent", "Hermes Agent"], ["--agent", "../x"]]) {
      const r = await runBootstrap(args, tmpHome(), cp.url);
      assert.notEqual(r.code, 0, `args ${JSON.stringify(args)}`);
      assert.equal(r.stdout, "");
    }
    assert.equal(cp.requests.length, 0);
  } finally {
    await cp.close();
  }
});
