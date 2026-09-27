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

// [path under scripts/, path under shared/src/] — the two differ for anything the
// guard keeps in scripts/lib/.
//
// guard-bootstrap.mjs was absent from this list, and drifted: shared's copy fell
// behind by the whole launch-lock mutex and then by the containment reader, with
// nothing failing. Anything copied between the two belongs here.
const MODULES = [
  ["classifier.mjs", "classifier.mjs"],
  ["policy-bundle.mjs", "policy-bundle.mjs"],
  ["lib/guard-bootstrap.mjs", "guard-bootstrap.mjs"],
];

for (const [scriptPath, srcPath] of MODULES) {
  test(`vendored ${scriptPath} is byte-identical to @vaibot/shared source`, () => {
    assert.equal(
      readFileSync(join(scriptsDir, scriptPath), "utf-8"),
      readFileSync(join(srcDir, srcPath), "utf-8"),
      `scripts/${scriptPath} has drifted — re-copy from packages/shared/src/${srcPath}`,
    );
  });
}

// A declaration file is hand-written beside each copy, so it drifts too — and
// silently, because nothing imports these from TypeScript inside this package.
// openclaw does, and shipped a type error for exactly this reason.
test("guard-bootstrap.d.mts declares every runtime export", async () => {
  const declared = readFileSync(join(scriptsDir, "lib", "guard-bootstrap.d.mts"), "utf-8");
  const mod = await import(join(scriptsDir, "lib", "guard-bootstrap.mjs"));
  const undeclared = Object.keys(mod).filter(
    (name) => !new RegExp(`\\bexport\\s+(declare\\s+)?(function|const|class)\\s+${name}\\b`).test(declared),
  );
  assert.deepEqual(undeclared, [], `undeclared in guard-bootstrap.d.mts: ${undeclared.join(", ")}`);
});

test("vendored decision-engine modules expose the expected API", async () => {
  const cls = await import(join(scriptsDir, "classifier.mjs"));
  assert.equal(typeof cls.classify, "function");
  assert.equal(typeof cls.classifyBash, "function");
  const pb = await import(join(scriptsDir, "policy-bundle.mjs"));
  assert.equal(typeof pb.loadPolicyBundle, "function");
  assert.equal(typeof pb.effectivePolicy, "function");
});
