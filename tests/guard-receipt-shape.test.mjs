import { test } from "node:test";
import assert from "node:assert/strict";

import { receiptOutcome, actionVerbFor } from "../scripts/lib/receipt-shape.mjs";

// The receipt-shape contract. policy.decision keeps the RAW verdict; these
// fields say what HAPPENED and whether anyone is still waiting.
//
// The rule under test: `pending` is CONDITIONAL. It is a claim that a human
// decision is outstanding, and it is the only status the dashboard's approval
// queue holds — so it may be emitted in exactly one case, an approve verdict
// with nothing back yet. Every other case is terminal. Emitting it for a gate
// that was already answered is what parked approved actions in the queue
// forever.

const enforce = (guardDecision, result, bypassOverride = false) =>
  receiptOutcome({ guardDecision, effectiveMode: "enforce", result, bypassOverride });
const observe = (guardDecision, result) =>
  receiptOutcome({ guardDecision, effectiveMode: "observe", result });

const OK = { outcome: "allowed" };
const FAILED = { outcome: "allowed", code: 1 };

// ── the one legitimate pending ───────────────────────────────────────────────

test("approve with nothing back yet is the ONLY pending", () => {
  assert.deepEqual(enforce("approve", null), {
    outcome: "blocked_until_approved",
    approvalStatus: "pending",
    observeMode: false,
    resolved: false,
  });
  assert.deepEqual(enforce("approve", undefined).approvalStatus, "pending");
});

// ── the human answered: terminal, never pending ──────────────────────────────

test("approve + the human allowed it → approved, and it ran", () => {
  assert.deepEqual(enforce("approve", OK), {
    outcome: "allowed",
    approvalStatus: "approved",
    observeMode: false,
    resolved: true,
  });
});

test("approve + the human declined → denied, terminal", () => {
  assert.deepEqual(enforce("approve", { approval: "denied" }), {
    outcome: "denied_by_reviewer",
    approvalStatus: "denied",
    observeMode: false,
    resolved: true,
  });
});

test("a decline reported as an outcome is read the same way", () => {
  const r = enforce("approve", { outcome: "denied_by_reviewer" });
  assert.equal(r.approvalStatus, "denied");
  assert.equal(r.outcome, "denied_by_reviewer");
});

test("approve + the action ran but errored → approved, outcome blocked", () => {
  const r = enforce("approve", FAILED);
  assert.equal(r.approvalStatus, "approved", "the human still approved it");
  assert.equal(r.outcome, "blocked", "the command itself failed");
});

test("a host bypass says bypassed — never approved, and is not a resolved gate", () => {
  const r = enforce("approve", OK, true);
  assert.equal(r.approvalStatus, "bypassed");
  assert.equal(r.outcome, "allowed");
  assert.equal(r.resolved, false, "no human decided anything");
});

test("a decline beats a bypass", () => {
  const r = enforce("approve", { approval: "denied" }, true);
  assert.equal(r.approvalStatus, "denied");
});

// ── nothing was gated ────────────────────────────────────────────────────────

test("observe + approve is not_required — nobody was asked, nobody waits", () => {
  assert.deepEqual(observe("approve", OK), {
    outcome: "allowed",
    approvalStatus: "not_required",
    observeMode: true,
    resolved: false,
  });
});

test("observe + deny → the action ran, so allowed", () => {
  assert.deepEqual(observe("deny", OK), {
    outcome: "allowed",
    approvalStatus: "not_required",
    observeMode: true,
    resolved: false,
  });
});

test("observe reports a command that errored as blocked", () => {
  const r = observe("deny", FAILED);
  assert.equal(r.outcome, "blocked");
  assert.equal(r.observeMode, true);
});

test("observe never emits pending, even with nothing back", () => {
  assert.equal(observe("approve", null).approvalStatus, "not_required");
});

// ── the ungated verdicts ─────────────────────────────────────────────────────

test("enforce + allow → allowed / not_required", () => {
  assert.deepEqual(enforce("allow", OK), {
    outcome: "allowed",
    approvalStatus: "not_required",
    observeMode: false,
    resolved: false,
  });
});

test("allow at precheck (nothing back) is allowed, not blocked", () => {
  assert.equal(enforce("allow", null).outcome, "allowed");
});

test("allow + ok:false → blocked", () => {
  assert.equal(enforce("allow", { ok: false }).outcome, "blocked");
});

test("allow + code:0 → allowed", () => {
  assert.equal(enforce("allow", { code: 0 }).outcome, "allowed");
});

test("enforce + deny → blocked / not_required", () => {
  assert.deepEqual(enforce("deny", null), {
    outcome: "blocked",
    approvalStatus: "not_required",
    observeMode: false,
    resolved: false,
  });
});

test("an unrecognised verdict fails closed to blocked", () => {
  const r = enforce("wat", OK);
  assert.equal(r.outcome, "blocked");
  assert.equal(r.approvalStatus, "not_required");
});

// ── floor denies hold regardless of mode ─────────────────────────────────────

test("a floor deny is blocked in ENFORCE", () => {
  const r = receiptOutcome({ guardDecision: "deny", effectiveMode: "enforce", result: null, floor: true });
  assert.deepEqual(r, { outcome: "blocked", approvalStatus: "not_required", observeMode: false, resolved: false });
});

test("a floor deny is blocked in OBSERVE too — that is what floor means", () => {
  // Without this, the observe branch would report the action as having run,
  // which for Tier-0 containment is a receipt that contradicts the guard.
  const r = receiptOutcome({ guardDecision: "deny", effectiveMode: "observe", result: null, floor: true });
  assert.equal(r.outcome, "blocked");
  assert.equal(r.observeMode, true, "still flagged as observe — the mode is a fact, the block is another");
});

test("floor does not change a non-deny verdict", () => {
  // Only a deny can be a floor deny; an allow carrying the flag must not be
  // rewritten into a block.
  const r = receiptOutcome({ guardDecision: "allow", effectiveMode: "observe", result: { outcome: "allowed" }, floor: true });
  assert.equal(r.outcome, "allowed");
});

// ── the verb follows what happened ───────────────────────────────────────────

test("actionVerbFor reads from the outcome, not the verdict", () => {
  const verb = (approvalStatus, observeMode = false) =>
    actionVerbFor({ mappedDecision: "approval_required", approvalStatus, observeMode });
  assert.equal(verb("approved"), "executed after approval");
  assert.equal(verb("denied"), "was denied approval to run");
  assert.equal(verb("bypassed"), "executed under an approval bypass");
  assert.equal(verb("pending"), "paused pending approval for");
  assert.equal(verb("not_required", true), "would have paused pending approval for");
  assert.equal(actionVerbFor({ mappedDecision: "deny", approvalStatus: "not_required", observeMode: false }), "blocked from executing");
  assert.equal(actionVerbFor({ mappedDecision: "allow", approvalStatus: "not_required", observeMode: false }), "executed");
});
