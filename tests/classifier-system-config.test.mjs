import { test } from "node:test";
import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Phase-3 #4: destructive host-config verbs must HARD-DENY (un-overridable floor) covering
// wrapped/absolute/`sh -c`/`env` forms, while benign system-config (status/list/-l) stays
// on the ask lane. Guards against the regression where these dropped to ask (normal path)
// or silent-allow (balanced preset).
const __dirname = dirname(fileURLToPath(import.meta.url));
const { classify, verdictForRisk } = await import(join(__dirname, "..", "scripts", "classifier.mjs"));

const isDeny = (cmd) => classify({ tool: "exec", input: { command: cmd } }, {}).risk === "dangerous";

test("#4: destructive host-config verbs hard-deny (incl. wrapped/absolute/sh -c/env)", () => {
  for (const cmd of [
    "systemctl stop firewalld",
    "/usr/bin/systemctl disable auditd",
    "sh -c 'crontab mycron'",
    "env systemctl mask sshd",
    "launchctl unload /Library/LaunchDaemons/foo.plist",
    "launchctl bootout gui/501/com.foo",
    "crontab -",
    "crontab -r",
    "crontab mycron.txt",
    "crontab -u bob evil.cron",
    "service firewalld stop",
  ]) {
    assert.equal(isDeny(cmd), true, `should hard-deny: ${cmd}`);
  }
});

test("#4: the destructive deny cannot be downgraded by a balanced preset (escalateAt=high)", () => {
  const v = classify({ tool: "exec", input: { command: "/usr/bin/systemctl disable auditd" } }, {});
  assert.equal(verdictForRisk(v.risk, "high"), "deny", "balanced preset must not downgrade to ask/allow");
  assert.equal(verdictForRisk(v.risk, "dangerous"), "deny", "even a permissive preset must still deny");
});

test("#4: benign system-config stays on the ask lane, not denied", () => {
  for (const cmd of [
    "systemctl status firewalld",
    "systemctl restart myapp",
    "systemctl list-units",
    "crontab -l",
    "launchctl list",
    "service --status-all",
  ]) {
    assert.equal(isDeny(cmd), false, `should NOT hard-deny: ${cmd}`);
  }
});
