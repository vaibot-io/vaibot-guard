// Signed approval answers from the control plane.
//
// When a person answers a held call on their phone, the dashboard or an email
// link, the server pushes the answer down GET /v2/enforcement/stream. The API
// key that opens that stream is also held by the agent's host, so an answer is
// only applied after its Ed25519 signature checks out against the pinned
// policy key — the same key, canonical form and rules as a policy bundle.
//
// Domain separation: an answer carries `schema: vaibot/approval-resolution@1`
// and no `policy`, so verifyBundle rejects it, and this rejects a bundle.

import { createPublicKey, verify as edVerify } from "node:crypto";
import { canonicalPayload } from "../policy-bundle.mjs";

export const APPROVAL_RESOLUTION_SCHEMA = "vaibot/approval-resolution@1";

const STATUSES = new Set(["approved", "denied", "expired", "bypassed"]);

/**
 * Verify one answer. Fail-closed: anything unexpected is { ok: false }.
 * @returns {{ ok: true, answer: { runId: string, contentHash: string, status: string, source: string|null, resolvedAt: string|null } } | { ok: false, reason: string }}
 */
export function verifyApprovalResolution(doc, publicKeyPem, opts = {}) {
  const now = typeof opts.now === "number" ? opts.now : Date.now();
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return { ok: false, reason: "malformed" };
  if (doc.schema !== APPROVAL_RESOLUTION_SCHEMA) return { ok: false, reason: "bad-schema" };
  if (typeof doc.signature !== "string" || doc.signature === "") return { ok: false, reason: "no-signature" };
  if (typeof doc.run_id !== "string" || doc.run_id === "") return { ok: false, reason: "malformed" };
  if (typeof doc.content_hash !== "string" || doc.content_hash === "") return { ok: false, reason: "malformed" };
  if (!STATUSES.has(doc.status)) return { ok: false, reason: "bad-status" };
  if (!publicKeyPem) return { ok: false, reason: "no-public-key" };
  const exp = Date.parse(doc.expires_at ?? "");
  if (!Number.isFinite(exp)) return { ok: false, reason: "malformed" };
  if (now > exp) return { ok: false, reason: "expired" };

  let valid = false;
  try {
    valid = edVerify(null, Buffer.from(canonicalPayload(doc)), createPublicKey(publicKeyPem), Buffer.from(doc.signature, "base64"));
  } catch {
    valid = false;
  }
  if (!valid) return { ok: false, reason: "bad-signature" };

  return {
    ok: true,
    answer: {
      runId: doc.run_id,
      contentHash: doc.content_hash,
      status: doc.status,
      source: typeof doc.source === "string" ? doc.source : null,
      resolvedAt: typeof doc.resolved_at === "string" ? doc.resolved_at : null,
    },
  };
}

/**
 * How a verified answer moves a held approval. Pure: returns the new fields, or
 * null when the answer must not touch the record. Only a still-pending record
 * moves, and only to the state the person chose, so a replayed or late answer
 * can never revive, re-approve or overturn a settled call.
 */
export function heldApprovalTransition(rec, answer, opts = {}) {
  const now = typeof opts.now === "number" ? opts.now : Date.now();
  const redeemMs = typeof opts.redeemMs === "number" ? opts.redeemMs : 10 * 60_000;
  if (!rec || rec.held !== true || rec.runId !== answer.runId) return null;
  if (rec.serverContentHash && rec.serverContentHash !== answer.contentHash) return null;
  if (rec.status !== "pending") return null;
  if (rec.expiresAt && now > Date.parse(rec.expiresAt)) return null;
  const at = new Date(now).toISOString();
  switch (answer.status) {
    case "approved":
      // An approval is for this call now, not a standing grant: a short window
      // to use it, never longer than the hold itself.
      return {
        status: "approved",
        resolvedAt: at,
        resolutionSource: answer.source,
        expiresAt: new Date(Math.min(Date.parse(rec.expiresAt || at) || now + redeemMs, now + redeemMs)).toISOString(),
      };
    case "denied":
      return { status: "denied", resolvedAt: at, resolutionSource: answer.source };
    case "expired":
      return { status: "expired", resolvedAt: at, resolutionSource: answer.source };
    default:
      return null; // bypassed is recorded after the fact; nothing to apply
  }
}
