# Changelog

All notable changes to `@vaibot/guard` are documented here.

## [Unreleased] — fresh-install & system-config posture

### Changed
- **System-config commands now ask for approval instead of hard-denying.**
  `systemctl`, `service`, `launchctl`, `crontab`, and `cron` moved out of the
  local `denyTokens` floor; the classifier now rates them HIGH (⇒ human approval)
  **on the command head only**. Operators can manage schedulers / host process
  supervisors under approval, and a fresh install can bootstrap the guard's own
  unit under approval rather than being hard-blocked — closing the bootstrap
  deadlock. The same word appearing as an *argument*
  (`echo "restart the foo service"`) is no longer escalated (was a false positive).
- **`policy.default.json` v0.2 → v0.3:** `denyTokens` is now empty; the five
  system-config tokens moved to `approveTokens`. Only the classifier's
  catastrophic pattern floor (`rm -rf /`, `mkfs`, fork bomb, guard
  self-protection) still hard-denies.

### Fixed
- **Guard launch is no longer silent on failure.** The launcher tees the daemon's
  stdout/stderr to `~/.vaibot/guard/launch.log` (was `stdio: 'ignore'`) and raises
  the cold-start health budget 4s → 10s, so a fresh machine's first boot isn't
  reported as a false "failed" and a real boot error is diagnosable.

### Security
- Behavior is **strictly narrowing on false positives** and preserves every real
  detection: the catastrophic floor, Tier-0 guard self-protection, and the signed
  denylist / approve-token lanes are unchanged. See `THREAT-MODEL.md` §9 for the
  adversarial-agent tamper-resistance analysis this work is scoped against.
