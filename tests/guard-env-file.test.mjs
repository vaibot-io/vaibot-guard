import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { parseEnvFile, loadGuardEnvFile, defaultGuardEnvPath } from "../scripts/lib/env-file.mjs";

const PEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAabc=\n-----END PUBLIC KEY-----";

// The exact shape the Rust CLI writes (managed block + quoted multi-line PEM).
const CLI_BLOCK = `# >>> vaibot-managed (vaibot init / doctor --fix rewrites this block; edits here are lost) >>>
VAIBOT_API_KEY=vbk_live_123
VAIBOT_POLICY_URL=https://api.vaibot.io/v2/policy
VAIBOT_POLICY_PUBKEY="${PEM}"
# <<< vaibot-managed <<<
`;

test("parseEnvFile reads bare values and skips comments + blank lines", () => {
  const got = parseEnvFile("# a comment\n\nVAIBOT_API_KEY=vbk_live_123\n; another\nVAIBOT_POLICY_URL=https://api.vaibot.io/v2/policy\n");
  assert.equal(got.VAIBOT_API_KEY, "vbk_live_123");
  assert.equal(got.VAIBOT_POLICY_URL, "https://api.vaibot.io/v2/policy");
  assert.equal(Object.keys(got).length, 2);
});

test("parseEnvFile preserves a double-quoted MULTI-LINE PEM verbatim", () => {
  const got = parseEnvFile(CLI_BLOCK);
  assert.equal(got.VAIBOT_POLICY_PUBKEY, PEM); // newlines intact, markers ignored
  assert.equal(got.VAIBOT_API_KEY, "vbk_live_123");
  assert.equal(got.VAIBOT_POLICY_URL, "https://api.vaibot.io/v2/policy");
  // the managed-block marker comments must not leak in as keys
  assert.ok(!("# >>> vaibot-managed (vaibot init / doctor --fix rewrites this block" in got));
});

test("parseEnvFile handles single-quoted values without escape processing", () => {
  const got = parseEnvFile("X='a b c'\nY=plain\n");
  assert.equal(got.X, "a b c");
  assert.equal(got.Y, "plain");
});

test("parseEnvFile honors a backslash-escaped quote inside double quotes", () => {
  const got = parseEnvFile('X="he said \\"hi\\""\n');
  assert.equal(got.X, 'he said "hi"');
});

test("loadGuardEnvFile fills only UNSET keys — real env always wins", () => {
  const env = { VAIBOT_API_KEY: "launcher_key" }; // already provided by the launcher
  const dir = mkdtempSync(join(tmpdir(), "vaibot-envfile-"));
  const p = join(dir, "vaibot-guard.env");
  writeFileSync(p, CLI_BLOCK);
  try {
    const filled = loadGuardEnvFile({ path: p, env });
    // pre-set key preserved; absent keys filled
    assert.equal(env.VAIBOT_API_KEY, "launcher_key");
    assert.equal(env.VAIBOT_POLICY_URL, "https://api.vaibot.io/v2/policy");
    assert.equal(env.VAIBOT_POLICY_PUBKEY, PEM);
    assert.deepEqual(filled.sort(), ["VAIBOT_POLICY_PUBKEY", "VAIBOT_POLICY_URL"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("loadGuardEnvFile never overrides the launcher's scanned port/token", () => {
  const env = { VAIBOT_GUARD_PORT: "39114", VAIBOT_GUARD_TOKEN: "tok" };
  const dir = mkdtempSync(join(tmpdir(), "vaibot-envfile-"));
  const p = join(dir, "vaibot-guard.env");
  // a stale port in the file must lose to the launcher's process.env value
  writeFileSync(p, "VAIBOT_GUARD_PORT=39111\nVAIBOT_POLICY_URL=https://api.vaibot.io/v2/policy\n");
  try {
    loadGuardEnvFile({ path: p, env });
    assert.equal(env.VAIBOT_GUARD_PORT, "39114"); // launcher wins
    assert.equal(env.VAIBOT_GUARD_TOKEN, "tok");
    assert.equal(env.VAIBOT_POLICY_URL, "https://api.vaibot.io/v2/policy"); // filled
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("loadGuardEnvFile is a silent no-op when the file is missing", () => {
  const env = {};
  const filled = loadGuardEnvFile({ path: join(tmpdir(), "definitely-absent-vaibot.env"), env });
  assert.deepEqual(filled, []);
  assert.deepEqual(env, {});
});

test("defaultGuardEnvPath matches the CLI's literal ~/.config path", () => {
  assert.ok(defaultGuardEnvPath().endsWith(join(".config", "vaibot-guard", "vaibot-guard.env")));
});
