#!/bin/sh
# VAIBot fresh-install bootstrap (test branch).
#
#   curl -fsSL https://raw.githubusercontent.com/vaibot-io/vaibot-guard/feat/fresh-install-degrade/install.sh | sh
#
# Installs @vaibot/guard + the circuit-breaker plugin(s) for whichever agent hosts are
# present (Claude Code / Codex / OpenClaw), all from the test branch, brings the guard
# up via the platform-aware ladder (systemd / launchd / self-spawn), and verifies.
# Works on Linux, macOS, WSL, and containers/CI (self-spawn). Native Windows: run under
# Git Bash or WSL. Best-effort per host — one failing host never aborts the rest.
#
# Env knobs:
#   VAIBOT_BRANCH=<ref>   branch/tag to install (default: feat/fresh-install-degrade)
#   VAIBOT_SYSTEM=1       install the guard as a ROOT/system service (tamper boundary; needs sudo)
#   VAIBOT_WITH_CLI=1     also build+install the Rust `vaibot` CLI front door (needs cargo; slow)
#   VAIBOT_SKIP_GUARD_START=1  install the guard package but don't start the service
set -u

BRANCH="${VAIBOT_BRANCH:-feat/fresh-install-degrade}"
GH="https://github.com/vaibot-io"
GL="https://gitlab.com/campbell-labs/vaibot-v2.git"

info() { printf '\033[36m[vaibot]\033[0m %s\n' "$1"; }
warn() { printf '\033[33m[vaibot]\033[0m %s\n' "$1" >&2; }
die()  { printf '\033[31m[vaibot]\033[0m %s\n' "$1" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---- prerequisites (fatal) ----
have node || die "Node 18+ is required (the guard is a Node daemon). Install Node, then re-run."
have npm  || die "npm is required."
have git  || die "git is required."

OS="$(uname -s 2>/dev/null || echo unknown)"
info "OS=$OS  branch=$BRANCH  node=$(node -v)"

# ---- 1. guard from the branch (provides vaibot-guard + vaibot-guard-service) ----
# Install from a fresh CLONE, not `npm i -g github:...#branch`: npm (and version
# managers like Volta that key on package version) cache git-branch installs and
# happily serve a stale commit — a local-path install is deterministic every time.
info "Installing @vaibot/guard from the test branch (fresh clone → local install)..."
GUARD_SRC="$(mktemp -d)/guard"
git clone -q -b "$BRANCH" "${GH}/vaibot-guard.git" "$GUARD_SRC" || die "cloning the guard from the branch failed."
if command -v volta >/dev/null 2>&1; then volta uninstall @vaibot/guard >/dev/null 2>&1 || true; fi
npm uninstall -g @vaibot/guard >/dev/null 2>&1 || true
npm install -g "$GUARD_SRC" \
  || die "npm global install of the guard failed. If it's a permissions error, fix your npm global prefix (nvm, or 'npm config set prefix ~/.npm-global') and re-run."
have vaibot-guard || die "vaibot-guard did not land on PATH — ensure your npm (or ~/.volta/bin) global bin dir is on PATH."

# ---- 2. bring the guard up via the platform-aware ladder ----
if [ "${VAIBOT_SKIP_GUARD_START:-0}" != "1" ]; then
  info "Starting the guard (platform-aware: systemd / launchd / self-spawn)..."
  if [ "${VAIBOT_SYSTEM:-0}" = "1" ]; then
    vaibot-guard install --system || warn "guard --system install reported an issue — see ~/.vaibot/guard/launch.log"
  else
    vaibot-guard install || warn "guard install reported an issue — see ~/.vaibot/guard/launch.log (it self-spawns on the first tool call regardless)"
  fi
fi

# ---- 3. plugins for whichever hosts are present (best-effort) ----
hosts=0

if have claude; then
  info "Claude Code detected — adding the branch marketplace + installing the plugin..."
  claude plugin marketplace add "${GH}/claudecode-circuitbreaker-plugin.git#${BRANCH}" >/dev/null 2>&1 \
    || warn "  couldn't add the marketplace non-interactively — run inside a session: /plugin marketplace add ${GH}/claudecode-circuitbreaker-plugin.git#${BRANCH}"
  claude plugin install vaibot-governance@vaibot-claudecode --scope user >/dev/null 2>&1 \
    || warn "  finish in a session: /plugin install vaibot-governance@vaibot-claudecode  then  /reload-plugins"
  hosts=$((hosts + 1))
fi

if have codex; then
  info "Codex detected — adding the branch marketplace..."
  codex plugin marketplace add "${GH}/codex-circuitbreaker-plugin.git#${BRANCH}" >/dev/null 2>&1 \
    || warn "  codex marketplace add failed — try a local clone: git clone -b ${BRANCH} ${GH}/codex-circuitbreaker-plugin.git && codex plugin marketplace add ./codex-circuitbreaker-plugin"
  warn "  Codex install is interactive: run 'codex /plugins' and install 'vaibot-codex-circuitbreaker', then restart Codex."
  hosts=$((hosts + 1))
fi

if have openclaw; then
  info "OpenClaw detected — cloning, building + packing the branch plugin..."
  tmp="$(mktemp -d)"
  if git clone -q -b "$BRANCH" "${GH}/openclaw-plugin-vaibot-circuit-breaker.git" "$tmp/oc" \
     && ( cd "$tmp/oc" && npm install --silent >/dev/null 2>&1 && npm run build --silent >/dev/null 2>&1 && npm pack --silent >/dev/null 2>&1 ); then
    openclaw plugins install --dangerously-force-unsafe-install "$tmp"/oc/vaibot-circuit-breaker-openclaw-plugin-*.tgz \
      && openclaw gateway restart \
      || warn "  openclaw plugin install/restart reported an issue (see above)"
  else
    warn "  couldn't clone/build the openclaw plugin — check node/git and retry the Local dev install from its README."
  fi
  rm -rf "$tmp" 2>/dev/null || true
  hosts=$((hosts + 1))
fi

[ "$hosts" -gt 0 ] || warn "No agent host (claude/codex/openclaw) found on PATH — installed the guard only."

# ---- 4. optional Rust CLI front door ----
if [ "${VAIBOT_WITH_CLI:-0}" = "1" ]; then
  if have cargo; then
    info "Building the vaibot CLI from the branch (cargo — a few minutes)..."
    cargo install --git "$GL" --branch "$BRANCH" vaibot || warn "cargo install vaibot failed."
  else
    warn "VAIBOT_WITH_CLI=1 but cargo not found — skipping the Rust CLI."
  fi
fi

# ---- 5. verify ----
info "Verifying..."
if [ -f "$HOME/.vaibot/guard/guard.json" ]; then
  port="$(node -e 'try{process.stdout.write(String(JSON.parse(require("fs").readFileSync(process.env.HOME+"/.vaibot/guard/guard.json","utf8")).port||""))}catch{}' 2>/dev/null || true)"
  info "Guard is up — rendezvous at ~/.vaibot/guard/guard.json${port:+ (port $port)}"
else
  warn "No rendezvous yet — the guard self-spawns on the first agent tool call, or check ~/.vaibot/guard/launch.log"
fi

info "Done. Now open your agent and run the acceptance checks (system-config asks; 'echo ...service...' runs; fresh box isn't bricked)."
