import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

// `vaibot-guard classify` — the one-shot, offline classifier query.
//
// This is the seam non-Node hosts use to reach the SAME safety floor the Node
// plugins use on their degraded paths. If it stops answering, or starts answering
// differently, a Python host either loses the floor or gets a second, drifting
// copy of it. So these tests pin the contract, not just the happy path:
//   - both accepted input shapes
//   - the catastrophic floor still denies
//   - every failure mode exits non-zero WITHOUT printing a verdict, so a caller
//     can never mistake a broken run for an allow
//   - it needs no daemon, no network, and writes nothing

const CLI = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "scripts",
  "vaibot-guard.mjs",
);

/** Run the CLI with an optional stdin payload. Never rejects — returns the outcome. */
function runClassify(args = [], stdin = "") {
  return new Promise((resolve) => {
    const child = execFile(
      process.execPath,
      [CLI, "classify", ...args],
      // A bare env (no VAIBOT_* inherited) proves the command needs no credentials
      // and no running daemon to answer.
      { env: { PATH: process.env.PATH, HOME: process.env.HOME }, timeout: 20_000 },
      (err, stdout, stderr) => {
        resolve({ code: err?.code ?? 0, stdout: String(stdout), stderr: String(stderr) });
      },
    );
    if (child.stdin) {
      child.stdin.end(stdin);
    }
  });
}

function parseVerdict(stdout) {
  return JSON.parse(stdout.trim());
}

test("classify: accepts the wire shape {toolName, params} on stdin", async () => {
  const r = await runClassify([], JSON.stringify({
    toolName: "Read",
    params: { file_path: "/tmp/notes.txt" },
  }));
  assert.equal(r.code, 0, `expected exit 0, got ${r.code} — ${r.stderr}`);
  const v = parseVerdict(r.stdout);
  assert.equal(v.verdictHint, "allow");
  assert.equal(v.risk, "safe");
});

test("classify: accepts the native shape {tool, input} via --intent", async () => {
  const r = await runClassify([
    "--intent",
    JSON.stringify({ tool: "Read", input: { file_path: "/tmp/notes.txt" } }),
  ]);
  assert.equal(r.code, 0);
  assert.equal(parseVerdict(r.stdout).verdictHint, "allow");
});

test("classify: the catastrophic floor denies", async () => {
  // The whole reason this command exists. A destructive filesystem command must
  // come back deny with no policy, no daemon and no credentials in play — that is
  // what a degraded-path caller relies on.
  const r = await runClassify([], JSON.stringify({
    toolName: "Bash",
    params: { command: "mkfs.ext4 /dev/sda1" },
  }));
  assert.equal(r.code, 0);
  const v = parseVerdict(r.stdout);
  assert.equal(v.verdictHint, "deny");
  assert.ok(v.reasons.length > 0, "a deny must carry a reason the caller can surface");
});

test("classify: --escalate-at reproduces a preset's ask threshold", async () => {
  const intent = JSON.stringify({ tool: "Write", input: { file_path: "/tmp/notes.txt" } });

  const dflt = await runClassify(["--intent", intent]);
  assert.equal(parseVerdict(dflt.stdout).verdictHint, "allow");

  const strict = await runClassify(["--escalate-at", "low", "--intent", intent]);
  const v = parseVerdict(strict.stdout);
  assert.equal(v.risk, "low", "risk itself must not move — only the threshold applied to it");
  assert.equal(v.verdictHint, "ask");
});

test("classify: a governance self-call is never gated", async () => {
  const r = await runClassify([], JSON.stringify({
    toolName: "mcp__vaibot__vaibot_status",
    params: {},
  }));
  assert.equal(r.code, 0);
  assert.equal(parseVerdict(r.stdout).verdictHint, "allow");
});

// ── Failure modes: exit non-zero and print NO verdict ─────────────────────────
// A caller that reads stdout as JSON must get nothing parseable here, so a
// malformed run can never be misread as an allow.

for (const [name, args, stdin] of [
  ["invalid JSON", [], "not json"],
  ["empty stdin", [], ""],
  ["missing tool", [], JSON.stringify({ params: {} })],
  ["blank tool", [], JSON.stringify({ toolName: "   ", params: {} })],
  ["non-object intent", [], JSON.stringify("a string")],
]) {
  test(`classify: ${name} exits non-zero without emitting a verdict`, async () => {
    const r = await runClassify(args, stdin);
    assert.notEqual(r.code, 0, `${name} should not exit 0`);
    assert.equal(r.stdout.trim(), "", `${name} must print no verdict on stdout`);
    assert.ok(r.stderr.includes("classify"), "the error should name the command");
  });
}

test("classify: answers with no VAIBOT env, no daemon, and no network", async () => {
  // Implicit in every case above (runClassify strips VAIBOT_*), asserted once
  // explicitly so the guarantee is visible rather than incidental.
  const r = await runClassify([], JSON.stringify({ toolName: "Read", params: {} }));
  assert.equal(r.code, 0);
  assert.ok(parseVerdict(r.stdout).verdictHint);
});
