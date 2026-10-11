// approval-resolution — how a gated run was settled, as reported by a breaker
// at finalize.
//
// The wording of the EXISTING answers (approved, a person's denial, a bypass) is
// unchanged, byte for byte: receipts are reported on, and those strings are
// part of what consumers rely on. Only the two additive answers below get new
// wording, which by construction appears on no receipt that existed before.
//
// A breaker reports the answer at finalize as `result.approval`:
//
//   "approved"     the call ran after approval (also what a finalize with no
//                  `approval` field means for a gated run — the call ran)
//   "denied"       a PERSON declined it in the host's own prompt. Only for a
//                  decline the host proves was the user's; never a guess.
//   "host_denied"  the host refused it, and it is not known to be the user's
//                  answer (another hook's deny, the host's own settings, a
//                  prompt the host withdrew). Never attributed to a person.
//   "expired"      nobody answered before the approval lapsed.
//
// and may name itself as `result.host` (a closed vocabulary below) so a
// host-side refusal reads "Declined by Cursor" rather than "by the host".
//
// The server's receipt schema has no status for the last two, so both are
// recorded as approval.status "denied" + outcome "blocked" (it did not run, and
// it was not approved) — the summary is what tells them apart. Neither sets
// `denied_by_reviewer`: that outcome is reserved for a person's "No".
//
// Pure and dependency-free.

export const HOST_LABELS = Object.freeze({
  claudecode: "Claude Code",
  codex: "Codex",
  cursor: "Cursor",
  openclaw: "OpenClaw",
  hermes: "Hermes",
});

/** The display name of a breaker's host, or null for anything unrecognised. */
export function hostLabel(host) {
  return Object.hasOwn(HOST_LABELS, host) ? HOST_LABELS[host] : null;
}

/**
 * How a gated run was settled, from what the host reported at finalize.
 * @returns {"user_declined"|"host_declined"|"expired"|null} null = it ran
 *          (approved, or a bypass — the caller tells those apart)
 */
export function approvalResolution(result) {
  if (result?.approval === "denied" || result?.outcome === "denied_by_reviewer") return "user_declined";
  if (result?.approval === "host_denied") return "host_declined";
  if (result?.approval === "expired") return "expired";
  return null;
}

/** The receipt's result summary for a gated run (followed by the policy reason). */
export function resolutionSummary({ resolution, host, bypassed = false }) {
  const by = hostLabel(host) ?? "the host";
  switch (resolution) {
    case "user_declined":
      return "Denied in the agent session — action did not run.";
    case "host_declined":
      return `Declined by ${by}, not by the user — action did not run.`;
    case "expired":
      return "Approval expired with no answer — action did not run.";
    default:
      return bypassed
        ? "Approval bypass honoured by policy — action ran without a human decision."
        : "Approved in the agent session — action ran.";
  }
}

/**
 * The verb for the receipt's action summary ("Agent <verb>: <command>") for the
 * two additive answers. null for every existing answer, whose verb is unchanged.
 */
export function resolutionVerb({ resolution, host }) {
  const by = hostLabel(host) ?? "the host";
  switch (resolution) {
    case "host_declined":
      return `was declined by ${by} and did not run`;
    case "expired":
      return "got no answer before its approval expired and did not run";
    default:
      return null;
  }
}
