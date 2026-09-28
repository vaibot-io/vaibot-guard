# Changelog

All notable changes to `@vaibot/guard` are documented here.

## [2.2.2] — 2026-09-28 — the floor reads git's flags, and finds its subcommand

### Fixed
- **`git -C <path> …` laundered every destructive git command the floor guarded.**
  The subcommand was taken positionally (`segment.split(/\s+/)[1]`), but git accepts
  global options *before* the subcommand — so `git -C pkg reset --hard` reported its
  subcommand as `-c`. That misread the verb, and it also stopped the elevated-risk
  patterns matching, because they require `git` immediately followed by it. Inserting
  `-C <path>` silently downgraded `reset --hard`, `clean -fdx` and `push --force`
  from **ask** to **allow**. `git -C` is the ordinary way to act on another
  directory, not an exotic evasion. The subcommand is now resolved by skipping git's
  documented global options (`-C`, `-c`, `--git-dir`, `--work-tree`, `-P`, … in both
  attached and separate-value forms).

- **Deleting a branch or a tag was classified as a READ and allowed.** `branch` and
  `tag` are on the read list because bare `git branch` lists branches — and flags
  were never consulted, so `git branch -D` and `git tag -d` arrived as
  `git read: branch`, risk `safe`, verdict `allow`. This was found when an agent
  deleted 41 branches on a developer's machine, including one carrying unmerged work,
  and the floor recorded it as a read. Classification is now on (subcommand, flags)
  together.

- **The recovery path is guarded too.** `git gc --prune`, `git reflog expire|delete`,
  `git stash drop|clear`, `git update-ref -d` and `git filter-branch` were `low` ⇒
  allow. A deleted ref survives in the object store until it is pruned, which is the
  only reason those 41 branches came back; ending that is at least as consequential
  as the deletion it follows. Also added: `git checkout -- <path>`, `git checkout .`
  and `git restore`, all of which discard uncommitted work.

  Every one of these lands on **high** ⇒ *ask*, the same lane `reset --hard` and
  `clean -f` already used — not a hard deny. Deleting a merged branch is ordinary
  hygiene, and a floor that refuses it outright is a floor people switch off. What
  is not acceptable is doing it silently under a receipt that says "git read".

### Added
- **`floorAsk` — a third verdict tier: never silent.** The guard had two. `DANGEROUS`
  denies and no preset can override it; everything else is compared against the
  preset's `escalateAt`. The **permissive** preset sets that to `dangerous`, so a
  HIGH-risk action resolved to **allow** there — which is how branch deletion ran
  without a prompt, and how `npm publish`, `fly deploy` and a recursive `rm` ran
  silently on the default production preset. There was a notion of "never allowed"
  and none of "never silent".

  `floorAsk` always **asks**, whatever `escalateAt` says, and no preset can lower it.
  It is deliberately **not** a deny: deleting a merged branch and publishing a
  release are legitimate. It only means they cannot happen unseen. The bar for entry
  is narrow, because a floor that interrupts routine work is a floor people stop
  running — *the action cannot be undone by whoever authorised it, and it either
  leaves this machine or destroys the only copy*:

  - **registry publishes** — `npm/pnpm/yarn publish`, `cargo publish`,
    `twine upload`, `uv`/`poetry`/`flit publish`, `npm unpublish`, `cargo yank`
  - **production deploys** — `fly deploy` (its target comes from `fly.toml`, not the
    command, so it always asks), `vercel`/`netlify --prod`
  - **destruction with no reflog behind it** — `shred`, recursive `rm`,
    `find … -delete`, `find … -exec rm`, `truncate -s 0`
  - **hosted artefacts** — `gh`/`glab repo delete`, `gh release delete`
  - **a secret's only copy** — `fly secrets unset|remove`, `vercel env rm`,
    `gh secret delete` (`set`/`add` are additive and stay with the presets)
  - **`supabase db reset`**
  - **the git forms above**, except an ordinary `git push`, which adds commits rather
    than destroying them and stays with the presets

  Left to the presets on purpose: `gh pr merge`, `fly secrets set`, `psql`,
  `supabase db push`, `git submodule update`, ordinary `git push`. Each is either
  reversible, or its consequence is invisible in the command text, or it is frequent
  enough that prompting would train people to work around the floor.

- **Six commands were allowed on _every_ preset, including the default.** Found by
  auditing this machine's real workflow. `cargo publish` was the worst — crates.io is
  permanent and a yank does not remove the crate, and it was rated `low`.
  `find … -delete` was rated **`safe`**. Also `twine upload` via `python -m`,
  `npm unpublish`, `cargo yank` and `git submodule deinit -f`.

- `tests/classifier-floor-ask.test.mjs` — the tier asks on all four presets; it never
  becomes a deny; `DANGEROUS` still outranks it; every entry is receipted; and a
  second table asserts the **exclusions still allow on permissive**, which is what
  stops the tier growing into "ask about everything".

### Changed
- `classifierTables.readGitSub` is a live lever again. It is unioned into the
  structural read set, so a signed policy can still name a subcommand this file has
  not heard of as a read — but never a destructive form, because
  `gitDestructiveReason()` is consulted first. Narrowing it no longer removes
  anything, since destructiveness is decided structurally rather than by absence
  from a list. Both directions are tightenings.

### Added
- `tests/classifier-git.test.mjs` — there were **no** git tests in the classifier
  suite at all, which is how both bypasses survived. Tables over the destructive
  forms, the same forms behind every global-option spelling, the reads that must
  stay `safe` (a floor that prompts on `git status` gets turned off), and the
  ordinary mutations that must not escalate. Includes the verbatim command shape
  that caused the incident.
- `parseGitInvocation`, `gitDestructiveReason` and `isGitRead` are exported so the
  classification is testable directly, not only through `classifyBash`.

### Note
An unrecognised git subcommand is deliberately **not** a read. A future git verb
this file has never heard of should arrive governed rather than pre-approved.

## [2.2.1] — 2026-09-27 — the type declarations match the module

### Fixed
- **`lib/guard-bootstrap.d.mts` declares every export the module actually has.**
  It was missing seven: `CONTAINMENT_FILE`, `readContainment`, `writeContainment`,
  `LAUNCH_LOCK_FILE`, `acquireFileLock`, `releaseFileLock` and
  `defaultAcquireLock`. The launch-lock four had been undeclared since that work
  landed; containment added three more in 2.2.0.

  Runtime was never affected — a declaration file does not exist at runtime, and
  every function was genuinely exported, which is why the four `.mjs` breakers
  were fine. A **TypeScript** consumer importing them got
  `TS2305: has no exported member`. The openclaw breaker is TypeScript and imports
  `readContainment`, so 1.3.0 shipped code that does not typecheck. Its tests run
  under vitest, which strips types rather than checking them, so nothing failed.

### Tests
- **The parity test now covers `lib/guard-bootstrap.mjs`**, which is how the
  `@vaibot/shared` copy drifted unnoticed — first by the whole launch-lock mutex,
  then by the containment reader. It previously guarded only `classifier.mjs` and
  `policy-bundle.mjs`, and the two paths differ (`scripts/lib/` here,
  `src/` there), which is presumably why it was skipped.
- **A new test asserts every runtime export appears in the declaration file**, by
  importing the module and checking each key. A hand-written `.d.mts` beside a
  `.mjs` drifts by default; nothing inside this package imports it from
  TypeScript, so nothing else would notice.

## [2.2.0] — 2026-09-26 — per-account policy, honest approvals, containment

Everything outstanding in the guard ships as one version: per-account policy,
the approval-receipt fixes, Hermes host support, the policy-governed approval
bypass and the Tier-0 containment switch.

### Security
- **The floor no longer matches a command's DATA as though it were the command.**
  Patterns were tested against the raw string, which cannot tell an instruction
  from its data, so a heredoc body being written to a file — or a pattern being
  searched *for* — was matched as if it were running. Writing documentation
  about the guard, and grepping for the rule that fires, were both denied. Data
  payloads are now excluded before matching: heredoc bodies that are written
  rather than executed, search patterns (`grep`/`rg`), and request bodies
  (`-d`/`--data`).
  This is **not** a weakening. The same bytes were already unmatched when written
  through a file-write tool, which never inspected content at all — the two paths
  now agree. Anything that will be **executed** is still matched: a heredoc fed
  to an interpreter keeps its body, `echo … | sh` is untouched, and a stripped
  `-d` payload leaves the URL and any pipe visible. `commandForMatching()` is
  exported so a host can reason about it.
- **Hermes tool names are classified.** On 2.1.1 a host whose tool vocabulary the
  classifier did not recognise — notably `terminal` — was not matched by the
  catastrophic floor, so the floor could be walked past by naming a tool
  differently. The classifier now carries the host vocabulary natively and
  `toolKind` is applied on both the tool and exec paths.

### Fixed
- **`install-local` names the code it runs by absolute path, and refuses a
  source checkout.** `ExecStart` was `node scripts/vaibot-guard-service.mjs`
  resolved against `WorkingDirectory`, so the unit recorded whichever directory
  the installer ran from and then executed whatever code later sat there. On one
  machine that produced three candidate runtimes — an OpenClaw skill copy, a
  monorepo checkout, and the npm install — with the unit naming a directory that
  was not the one actually serving. Installing from a git checkout is now
  refused (`--allow-source-tree` to override): a checkout is not a runtime,
  because switching branches changes what the service runs and the version it
  reports follows whatever is checked out.
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
  Arming is live rather than pending: the control plane serves
  `/v2/enforcement/*` and pushes state over SSE, so a change lands in about a
  second, with the `/me` poll underneath as a reconciliation floor. Engaging is
  open to any credential on the account; releasing takes a signed-in session
  plus a second factor.
- **Containment is recorded machine-wide**, not in a workspace log dir, so every
  breaker on the machine reads one record — with no daemon, no network and no
  credentials. That is what carries containment onto the paths where a breaker
  degrades: daemon unreachable, no key, breaker tripped, fail-open, hook
  timeout. Those are precisely the paths that must still observe it, and all of
  them can read a file. The daemon treats the record as arm-only: it is read
  once at startup, so a contained machine does not come back permissive, and
  only an explicit value from the control plane clears the flag — it is not a
  local lever an agent could use to release itself. The reason given when
  engaging travels with it, so a halted breaker can say more than "blocked".
- **Policy-governed approval bypass**, with rule ids and grant provenance on
  receipts (`approval.scope`, `approval.choice`, `host_approval`). The guard
  resolves `hostBypassAction` itself and records the posture alongside the
  decision rather than folding it in, so a bypassed approval never reads as an
  approved one. It emits `bypassed` as soon as the control plane accepts that
  value on a policy write and admits it in the receipt `approval.status` enum.
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

### Tests
- **The suite no longer fails intermittently.** Fixtures drew a port from
  hand-assigned ranges that overlapped between files running in parallel —
  `guard-service` and `guard-containment` both from 39200-41199,
  `guard-signed-policy` and `guard-hermes-vocab` both from 41200-43199,
  `guard-host-bypass` and `guard-ephemeral-approvals` both from 43200-45199,
  plus four partial overlaps. A collision left the losing guard on `EADDRINUSE`,
  never reaching `/health`, and the file failed with "should start" — about one
  full run in three. Fixtures now take a port from the kernel. This is a
  harness concern only: the product's one-guard-per-machine rule is enforced by
  the rendezvous and by the service refusing to double-bind.

### Docs
- **README and THREAT-MODEL are written for the people who install this.** Both
  ship in the package `files`. Between them they gave the on-disk locations of
  the audit log, the credential store, and the service's unit and environment
  files; published how a machine fingerprint is derived; pre-announced an
  unreleased host integration together with its tool vocabulary; and, in the
  threat model, set out for each way a same-user adversary could defeat
  governance the specific file to corrupt or variable to flip, and why the
  self-protection pattern did not match it. The limitations are still stated
  plainly — the guard is tamper-evident rather than tamper-proof, and a
  determined same-user adversary is out of scope for a hook-only deployment.
  The methods are no longer shipped with it.

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
