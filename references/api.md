# VAIBot-Guard API (v1)

This document describes the VAIBot-Guard HTTP API endpoints used by:
- the `vaibot-guard` CLI wrapper, and
- the per-host circuit-breaker plugins (Claude Code / Codex / OpenClaw).

> Security model: VAIBot-Guard is intended to run on **localhost** (`127.0.0.1`).
> If `VAIBOT_GUARD_TOKEN` is set, protected endpoints require `Authorization: Bearer <token>`.

## Common response envelope

Most endpoints return a common envelope:

```json
{
  "ok": true,
  "runId": "run_<uuid>",
  "risk": { "risk": "low|high", "reason": "..." },
  "decision": { "decision": "allow|deny|approve", "reason": "...", "approvalId": "appr_<uuid>" },
  "audit": { "eventId": "<uuid>", "hash": "...", "prevHash": "..." },
  "prove": { "ok": true }
}
```

Notes:
- `prove` is best-effort unless `VAIBOT_PROVE_MODE=required`.
- `audit` is an append-only, hash-chained event reference; exact fields may evolve.

## Health

### `GET /health`

Returns:

```json
{ "ok": true, "service": "vaibot-guard", "ts": "<iso8601>" }
```

## Exec flow (shell commands)

### `POST /v1/decide/exec`

Precheck a shell command.

Request body:

```json
{
  "sessionId": "<string>",
  "cmd": "/bin/echo",
  "args": ["hello"],
  "intent": {
    "cwd": ".",
    "files": { "read": [], "write": [], "delete": [] },
    "network": { "destinations": [] },
    "env_keys": []
  }
}
```

Response:
- Common envelope with `decision`.

### `POST /v1/finalize`

Finalize an exec run.

Request body:

```json
{
  "sessionId": "<string>",
  "runId": "run_<uuid>",
  "result": {
    "exitCode": 0,
    "stdout": "...",
    "stderr": "..."
  }
}
```

Response:
- `{ ok: true, audit, prove }` or an error when `VAIBOT_PROVE_MODE=required`.

## Tool flow (agent tool calls)

These endpoints are used by the per-host circuit-breaker plugin that intercepts tool calls.

### Approvals (chat-command UX)

When Guard returns `decision=approve`, the `decision` object also carries an `approvalId` (single-use), an `expiresAt` and a `scope` (`{ paramsHash }`) — inside `decision`, not at the top level of the response:

```json
{ "ok": true, "runId": "run_...", "decision": { "decision": "approve", "reason": "...", "approvalId": "appr_...", "expiresAt": "...", "scope": { "paramsHash": "sha256:..." } } }
```

To support human-in-the-loop approval:

- `POST /v1/approvals/list` — list **pending** approvals (optionally filtered by `sessionId`)
- `POST /v1/approvals/resolve` — approve/deny a specific `approvalId`
- `POST /v1/approvals/status` — the current status of specific `approvalId`s (`list` returns pending only, so an id missing from it is not necessarily approved)
- `POST /v1/hold` — hold a call for an answer on the VAIBot Authenticator, dashboard or email (see below)

After approval, the caller redeems approval by including:

```json
{ "approval": { "approvalId": "appr_..." } }
```

in the next `/v1/decide/tool` request. Successful redemption marks the approval as **used** (single-use).

### `POST /v1/decide/tool`

Precheck a generic tool call.

Request body:

```json
{
  "sessionId": "<string>",
  "agentId": "<optional>",
  "channelId": "<optional>",
  "toolName": "read|write|exec|message.send|...",
  "runId": "<optional host run id>",
  "toolCallId": "<optional provider tool call id>",
  "workspaceDir": "<optional>" ,
  "params": { "...": "..." }
}
```

Response:
- Common envelope with `decision`.

### `POST /v1/finalize/tool`

Finalize a tool call (best-effort audit).

Request body:

```json
{
  "sessionId": "<string>",
  "runId": "run_<uuid>",
  "toolName": "<string>",
  "toolCallId": "<optional>",
  "params": { "...": "..." },
  "result": { "ok": true, "durationMs": 12, "result": "..." }
}
```

Response:
- `{ ok: true, audit, prove }` (or error on required prove failure).

**How a gated run was settled.** A breaker reports the answer in `result.approval` (`scripts/lib/approval-resolution.mjs`). The first two rows are the existing answers, with their existing wording; `host_denied` and `expired` are additive:

| `result.approval` | Meaning | Receipt | Approval record |
|---|---|---|---|
| `"approved"` (or absent) | the call ran after approval | `approved` / `allowed` (or `blocked` if it failed) — "Approved in the agent session — action ran." | `used` |
| `"denied"` | a **person** declined it in the host's prompt — only when the host proves it | `denied` / `denied_by_reviewer` — "Denied in the agent session — action did not run." | `denied` |
| `"host_denied"` | the host refused it, not known to be the user's answer | `denied` / `blocked` — "Declined automatically in the agent session, not by the user — action did not run." | `denied` |
| `"expired"` | nobody answered before the approval lapsed | `denied` / `blocked` — "Approval expired with no answer — action did not run." | `expired` |

The wording never names the agent harness. Only `"denied"` ever produces `denied_by_reviewer`. `/health` advertises this as the `approval-resolutions` capability. A guard without it reads **any** gated finalize that lacks `approval: "denied"` as "approved — ran", so a breaker must check the capability before it sends `host_denied` or `expired`.

### `POST /v1/approvals/list`

Request body:

```json
{ "sessionId": "<optional>" }
```

Response:

```json
{ "ok": true, "approvals": [ { "approvalId": "appr_...", "status": "pending", "expiresAt": "...", "reason": "...", "request": { "toolName": "...", "paramsHash": "sha256:..." } } ] }
```

### `POST /v1/approvals/resolve`

Request body:

```json
{ "approvalId": "appr_...", "action": "approve|deny" }
```

Response:

```json
{ "ok": true, "approvalId": "appr_...", "status": "approved|denied" }
```

### `POST /v1/approvals/status`

The current status of specific approvals. Read-only. Use it when an id leaves the
pending list: `list` returns **pending** approvals only, so a missing id may have been
approved, denied, used or expired.

Request body (1–100 ids):

```json
{ "approvalIds": ["appr_...", "appr_..."] }
```

Response (one entry per distinct id):

```json
{ "ok": true, "approvals": [ { "approvalId": "appr_...", "status": "approved", "expiresAt": "...", "resolvedAt": "...", "usedAt": null } ] }
```

| `status` | Meaning |
|---|---|
| `pending` | not answered yet |
| `approved` | approved and still redeemable |
| `denied` | refused |
| `used` | already redeemed, or spent by a native "Yes" at finalize |
| `expired` | past its TTL while pending or approved; a redeem would fail |
| `unknown` | never issued by this guard, or a terminal record since pruned (pruning only drops `used`/`denied`/`expired`, so `unknown` is never a live approval). Treat it as **not approved**. |

`400` if `approvalIds` is missing, empty, not all non-empty strings, or longer than 100.

### `POST /v1/hold`

Hold a call that is waiting for a person's answer, so it can be answered away from
the terminal: on the VAIBot Authenticator, in the dashboard or from the alert email.
The guard posts a pending receipt ("Held for approval — the action has not run. …")
and learns the answer from the enforcement stream, signed with the policy key.

Request body (`runId` from `/v1/decide/tool`; `sessionId` must match the run's):

```json
{ "runId": "run_...", "sessionId": "..." }
```

Response when held:

```json
{ "ok": true, "held": true, "runId": "run_...", "approvalId": "appr_...", "contentHash": "0x...",
  "channels": { "authenticator": true, "email": true, "dashboard": true },
  "expiresAt": "...", "reason": "..." }
```

`channels` says where the person can answer; a host with neither `authenticator` nor
`email` should ask in its own prompt instead of waiting. When the call can't be held
the response is `{ "ok": true, "held": false, "reason": "observe" | "denied" | "offline" | "post_failed" | "approval_<status>" }`
and the host asks in its own prompt. `404 run_not_found`, `403 session_mismatch`.

A call the guard allowed but the host asks about anyway is held too, with reason "The
agent host asked for permission before running this call.".

Poll `POST /v1/approvals/status` for the answer: a held approval carries `held: true`
and `resolutionSource` (where it was answered, e.g. `authenticator`, `dashboard` or
`email`). `POST /v1/approvals/resolve` can deny a held
approval but not approve it (`403 held_approval`). Finalize the run as usual; its
receipt names where the call was answered.

| Env | Default | |
|---|---|---|
| `VAIBOT_HELD_APPROVAL_TTL_MS` | 15 min | how long a held approval stays answerable |
| `VAIBOT_HELD_REDEEM_MS` | 10 min | how long an answer stays redeemable |

## Ops endpoints

### `POST /v1/flush`

Attempt to flush/anchor checkpoints for a session.

```json
{ "sessionId": "<string>" }
```

### `POST /api/proof`

Compute an inclusion proof for a given leaf index at a checkpoint sequence.

```json
{ "sessionId": "<string>", "index": 0, "checkpointSeq": 1 }
```
