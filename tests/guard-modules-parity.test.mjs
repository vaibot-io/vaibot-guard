import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Guards the vendored copies of the shared decision-engine modules. The guard
// ships as a standalone .skill and can't import @vaibot/shared at runtime, so
// scripts/{classifier,policy-bundle}.mjs are verbatim copies of
// packages/shared/src. These tests fail if a copy drifts from the canonical
// source.

const __dirname = dirname(fileURLToPath(import.meta.url));
const scriptsDir = join(__dirname, "..", "scripts");
const srcDir = join(__dirname, "..", "..", "shared", "src");
const MODULES = ["classifier.mjs", "policy-bundle.mjs"];

for (const m of MODULES) {
  test(`vendored ${m} is byte-identical to @vaibot/shared source`, () => {
    assert.equal(
      readFileSync(join(scriptsDir, m), "utf-8"),
      readFileSync(join(srcDir, m), "utf-8"),
      `scripts/${m} has drifted — re-copy from packages/shared/src/${m}`,
    );
  });
}

test("vendored decision-engine modules expose the expected API", async () => {
  const cls = await import(join(scriptsDir, "classifier.mjs"));
  assert.equal(typeof cls.classify, "function");
  assert.equal(typeof cls.classifyBash, "function");
  const pb = await import(join(scriptsDir, "policy-bundle.mjs"));
  assert.equal(typeof pb.loadPolicyBundle, "function");
  assert.equal(typeof pb.effectivePolicy, "function");
});
