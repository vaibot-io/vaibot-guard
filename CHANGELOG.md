# Changelog

All notable changes to `@vaibot/guard` are documented here.

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
