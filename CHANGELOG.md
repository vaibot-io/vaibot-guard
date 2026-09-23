# Changelog

All notable changes to `@vaibot/guard` are documented here.

## [2.2.0] — 2026-09-22 — per-account policy, honest approvals, Hermes hosts

Everything outstanding in the guard ships as one version: per-account policy,
the approval-receipt fixes, Hermes host support, the policy-governed approval
bypass and the Tier-0 containment switch.

### Security
- **Hermes tool names are classified.** On 2.1.1 a host whose tool vocabulary the
  classifier did not recognise — notably `terminal` — was not matched by the
  catastrophic floor, so the floor could be walked past by naming a tool
  differently. The classifier now carries the host vocabulary natively and
  `toolKind` is applied on both the tool and exec paths.

### Fixed
- **A resolved approval no longer records as pending.** The receipt's
  `approval.status` / `result.outcome` were built from the **decide-time**
  decision, hard-coding `pending` + `blocked_until_approved` for any gated
  action — but that code runs only from the finalize handlers, after the human
  has already answered and the tool has run. Every approved action therefore
  became a permanent card on the dashboard's approval queue.
- **`pending` is now conditional.** It is emitted for exactly one state: an
  approve verdict with nothing back yet, which is the only row the approval
  queue should hold. A gate that was answered records `approved` or `denied`; a
  policy-honoured bypass records `bypassed`; observe mode records
  `not_required`. The mapping lives in a pure `scripts/lib/receipt-shape.mjs`
  with unit tests that run without booting the daemon.
- **Observe-mode rows are `not_required`, not `pending`.** The old uniform
  shadow shape was kept out of the queue only by a downstream
  `approval_status = 'pending' AND observe_mode = false` filter; one consumer
  reading `approval_status` alone re-created the bug. Nothing is gated in
  observe, so nobody was asked and nobody is waiting.
- **`observe_mode` is sent** at all, so the control plane can key shadow rows.
- **A declined approval is recorded at all.** Declining in the agent's own
  prompt fires no post-tool hook, so no finalize ran and no receipt was written.
  Both sweeps now route through the local `/v1/finalize/tool` with
  `result.approval = "denied"` — the same path an accepted approval takes —
  instead of a `PATCH /deny` that sent a local `appr_<uuid>` to an API keyed by
  `content_hash` and always 404'd.
- **Receipts name the target path** of a tool call instead of falling through to
  the bare tool name.
- **`undefined` serialises the way `JSON.stringify` does**, so the run context
  stays parseable and the tamper-evident audit log stays valid JSON.

### Added
- **Tier-0 containment switch.** When armed, every decision short-circuits to a
  floor-deny *before* policy and classifier, holds even in observe mode, and is
  independent of whether a policy can be fetched or verified. Fail-static: only
  an explicit boolean flips it, so a poll blip can never silently lift it.
  ⚠️ Arms from `enforcement.contained` on the `/me` poll, which no API version
  serves yet — it ships inert until the control plane can arm it.
- **Policy-governed approval bypass**, with rule ids and grant provenance on
  receipts (`approval.scope`, `approval.choice`, `host_approval`).
  ⚠️ Reachable only once the API accepts `hostBypassAction` on a policy write
  **and** widens the receipt `approval.status` enum to include `bypassed`; until
  both land the guard never emits it.
- **Offline `classify` and `bootstrap` subcommands** for non-Node breakers.
- **`/health` advertises capabilities** (`host-vocab:hermes`, `host-bypass`,
  `rule-id`), so a client can ask what this guard understands rather than infer
  it from a version string.

### Added — per-account policy
- **The guard fetches its OWN account's policy.** `GET /v2/policy` now answers
  with the caller's effective policy — the admin-set global default plus
  whatever that account changed for itself — when the request carries an API
  key, and with the global default when it doesn't. The guard sends its key, so
  a per-account policy reaches the machine it governs. The key travels only to
  the control plane the guard already trusts with it; a `VAIBOT_POLICY_URL`
  pinned at another host is still fetched, just unauthenticated, since the
  Ed25519 signature is the trust anchor either way.
- **Reports what it is running.** The `/v2/accounts/me` poll carries
  `x-vaibot-guard-version` and `x-vaibot-policy-version`, so the control plane
  can tell an account that a policy it just set is not enforced yet. This is
  the release the API names as its `min_guard_version`.

### Changed
- A rejected key on the policy fetch is fail-static, like every other fetch
  failure: an account whose own policy is tighter than the global default is
  never loosened to the default because its key was revoked.

## [2.1.1] — 2026-07-04

### Docs
- README Installation now leads with the universal one-liner
  `curl -fsSL https://raw.githubusercontent.com/vaibot-io/command-cli/main/install.sh | sh`
  and links "the VAIBot CLI" to the [command-cli repo](https://github.com/vaibot-io/command-cli).
  (README ships in the package `files`, so this is a republish.)

## [2.1.0] — 2026-07-04 — fresh-install, graceful degrade & honest receipts

### Changed
- **System-config floor — destructive verbs HARD-DENY.** `systemctl stop|disable|mask`,
  `service … stop`, `launchctl unload|remove|bootout`, and `crontab` install are
  un-overridable denies, matched on wrapped/absolute/`sh -c` forms and not downgradable by
  any signed preset. Benign system-config (`status`/`list`/`-l`/`restart`) escalates to
  **approval (ask)** instead of hard-denying — closing the fresh-install bootstrap deadlock.
  The word appearing as an *argument* (`echo "restart the foo service"`) is not escalated.
- **The guard's OWN lifecycle is allow-listed.** Service-manager verbs on the guard
  (`systemctl`/`service`, macOS `launchctl io.vaibot.guard`), the `vaibot-guard` CLI/launcher,
  and the localhost `:39111` health probe run with **no prompt**; guard teardown still denies.
- **`policy.default.json` v0.2 → v0.3** — `denyTokens` empty; the floor now lives in the
  classifier's catastrophic + destructive-host-config patterns (un-overridable, offline-enforced).
- **Honest receipts.** `risk_level` reflects the classifier verdict that drove the decision on
  every path (ends "low risk but gated"); an allowed action's outcome reads `allowed`, not `blocked`.

### Added
- **`vaibot-guard install`** — non-interactive, platform-aware service install walking
  **systemd → launchd → self-spawn** (`--system` opts into the root/sudo tamper boundary).
  Health-verifies that the freshly-started unit actually took the port — no false "healthy"
  over a stale guard already holding it — and persists the endpoint.
- **macOS launchd support** (LaunchAgent / LaunchDaemon) alongside Linux systemd, with
  stdout/stderr + working-dir set for diagnosability.

### Fixed
- **Guard launch is no longer silent on failure.** The launcher tees the daemon's
  stdout/stderr to `~/.vaibot/guard/launch.log` (was `stdio: 'ignore'`) and raises the
  cold-start health budget 4s → 10s, so a fresh machine's first boot isn't a false "failed"
  and a real boot error is diagnosable.

### Security
- The catastrophic floor, Tier-0 guard self-protection, and the signed denylist /
  approve-token lanes are preserved; the destructive-host-config deny is a **new
  un-overridable local floor**. See `THREAT-MODEL.md` §9 for the adversarial-agent
  tamper-resistance analysis this work is scoped against.
