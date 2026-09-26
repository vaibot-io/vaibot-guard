import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  CONTAINMENT_FILE,
  GUARD_DIR,
  readContainment,
  writeContainment,
} from "../scripts/lib/guard-bootstrap.mjs";

// Containment used to live only inside the daemon, reachable through its HTTP
// API. Every path where a breaker degrades — daemon unreachable, no API key,
// breaker tripped, fail-open, hook timeout — skips that API, and therefore
// skipped containment.
//
// The marker exists so those paths can still observe it: one machine-wide file,
// readable with NO daemon, NO network and NO credentials. These tests pin the
// properties a breaker depends on.

test("the marker lives in the shared rendezvous dir, not a workspace", () => {
  // A workspace-scoped file cannot be found by a breaker running elsewhere on
  // the machine, which is most of them.
  assert.equal(path.dirname(CONTAINMENT_FILE), GUARD_DIR);
  assert.equal(path.basename(CONTAINMENT_FILE), "containment.json");
  assert.ok(GUARD_DIR.includes(path.join(".vaibot", "guard")), GUARD_DIR);
});

test("round-trips state and reason with no daemon involved", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "marker-"));
  const file = path.join(home, ".vaibot", "guard", "containment.json");

  assert.equal(writeContainment(true, "laptop looks compromised", file), true);
  const read = readContainment(file);
  assert.equal(read.contained, true);
  assert.equal(read.reason, "laptop looks compromised");
  assert.ok(read.at, "carries a timestamp so a breaker can say how long");

  assert.equal(writeContainment(false, null, file), true);
  assert.equal(readContainment(file).contained, false);
});

test("absent means not engaged — a machine never contained behaves normally", () => {
  const missing = path.join(os.tmpdir(), `marker-absent-${Date.now()}`, "containment.json");
  assert.deepEqual(readContainment(missing), { contained: false, at: null, reason: null });
});

test("a corrupt marker does not throw, and does not claim containment", () => {
  // A breaker reads this on every single tool call. It must never be the thing
  // that crashes the hook.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "marker-bad-"));
  const file = path.join(home, "containment.json");
  for (const junk of ["", "{", "null", "[]", '{"contained":"yes"}', "\u0000"]) {
    fs.writeFileSync(file, junk);
    assert.equal(readContainment(file).contained, false, JSON.stringify(junk));
  }
});

test("only a literal true engages it", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "marker-truthy-"));
  const file = path.join(home, "containment.json");
  for (const v of [1, "true", "1", {}, [], "yes"]) {
    fs.writeFileSync(file, JSON.stringify({ contained: v }));
    assert.equal(readContainment(file).contained, false, JSON.stringify(v));
  }
  fs.writeFileSync(file, JSON.stringify({ contained: true }));
  assert.equal(readContainment(file).contained, true);
});

test("is written 0600 — it names an account's security posture", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "marker-perm-"));
  const file = path.join(home, "containment.json");
  writeContainment(true, "x", file);
  const mode = fs.statSync(file).mode & 0o777;
  assert.equal(mode, 0o600, `mode was ${mode.toString(8)}`);
});

test("the write is atomic — a reader never sees a half-written marker", () => {
  // renameSync over a temp file, so a breaker reading concurrently sees either
  // the old state or the new one.
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "marker-atomic-"));
  const file = path.join(home, "containment.json");
  writeContainment(true, "first", file);
  writeContainment(true, "second", file);
  assert.equal(readContainment(file).reason, "second");
  assert.equal(fs.existsSync(file + ".tmp"), false, "no temp file left behind");
});

test("an unwritable location fails soft rather than throwing", () => {
  // The daemon's in-process flag is what gates its own decisions; a marker it
  // cannot write must not take the daemon down.
  //
  // The unwritable directory has to already EXIST. Don't reach for a path under
  // /proc to get one: fs.mkdirSync(dir, {recursive: true}) never returns when a
  // missing parent is procfs (Node 22), so such a path hangs the run instead of
  // exercising the failure.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "marker-ro-"));
  fs.chmodSync(dir, 0o500); // r-x: traversable, not writable
  try {
    assert.equal(writeContainment(true, "x", path.join(dir, "containment.json")), false);
  } finally {
    fs.chmodSync(dir, 0o700); // leave it removable
  }
});
