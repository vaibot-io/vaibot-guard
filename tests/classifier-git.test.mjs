/**
 * Git classification: the floor has to read the flags, and find the subcommand.
 *
 * There were no git tests in this suite at all, which is how two bypasses lived in
 * it. Both were found the hard way — an agent deleted 41 branches on a developer's
 * machine and the floor classified every one as `git read: branch` and allowed it.
 *
 * 1. The subcommand was taken positionally, `seg.split(/\s+/)[1]`. Git takes global
 *    options BEFORE the subcommand, so `git -C pkg reset --hard` reported `-c`. That
 *    misread the verb and also stopped the elevated-risk regexes matching, because
 *    they require `git` immediately followed by it. Inserting `-C <path>` therefore
 *    downgraded `reset --hard`, `clean -fdx` and `push --force` from ask to allow.
 *    `git -C` is the ordinary way to act on another directory.
 *
 * 2. Flags were never consulted. `branch` and `tag` are on the read list because bare
 *    `git branch` lists. `git branch -D` force-deletes. Same word, opposite effect.
 *
 * The tables below are written so a new git form has to be classified deliberately.
 * The read table matters as much as the destructive one: a floor that prompts on
 * `git status` is a floor people turn off.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  classifyBash, RISK, CATEGORY,
  parseGitInvocation, gitDestructiveReason, isGitRead,
} from '../scripts/classifier.mjs'

/** Destroys work, or destroys the ability to get it back. Must reach HIGH ⇒ ask. */
const DESTRUCTIVE = [
  ['git branch -D feat/thing', 'branch force-delete'],
  ['git branch -d feat/thing', 'branch delete'],
  ['git branch --delete feat/thing', 'branch delete, long form'],
  ['git branch -Dr origin/feat', 'clustered short flags'],
  ['git tag -d v1.0.0', 'tag delete'],
  ['git tag --delete v1.0.0', 'tag delete, long form'],
  ['git checkout -- .', 'discards every uncommitted change'],
  ['git checkout -- src/app.ts', 'discards one file'],
  ['git checkout .', 'same, without the --'],
  ['git restore src/', 'the modern spelling'],
  ['git stash drop', 'destroys a stash'],
  ['git stash clear', 'destroys every stash'],
  ['git reset --hard origin/main', 'discards commits'],
  ['git clean -fdx', 'deletes untracked files'],
  ['git push --force origin main', 'rewrites remote history'],
  ['git push --delete origin feat/x', 'deletes a remote branch'],
  ['git update-ref -d refs/heads/x', 'deletes a ref directly'],
  ['git filter-branch --all', 'rewrites history across refs'],
  // The recovery path itself. A deleted branch survives in the object store until
  // it is pruned — that is the only reason 41 deleted branches came back. Ending
  // that is at least as consequential as the deletion it follows.
  ['git gc --prune=now', 'ends recoverability'],
  ['git reflog expire --expire=now --all', 'destroys the recovery log'],
  ['git reflog delete HEAD@{0}', 'deletes a reflog entry'],
]

/** The same destructive verbs behind git's global options. */
const DESTRUCTIVE_WITH_GLOBALS = [
  'git -C pkg branch -D feat/thing',
  'git -C /abs/path branch -D feat/thing',
  'git --git-dir=/x/.git branch -D feat/thing',
  'git --git-dir /x/.git branch -D feat/thing',
  'git -c user.name=x branch -D feat/thing',
  'git --work-tree=/x -C /y branch -D feat/thing',
  'git -P branch -D feat/thing',
  'git --no-pager branch -D feat/thing',
  'git -C pkg reset --hard origin/main',
  'git -C pkg clean -fdx',
  'git -C pkg push --force origin main',
  'git -C pkg stash clear',
  'git -C pkg gc --prune=now',
]

/** Reads. These MUST stay safe, or the floor becomes unusable and gets switched off. */
const READS = [
  'git status',
  'git status --porcelain',
  'git branch',
  "git branch --format='%(refname:short)'",
  'git branch -a',
  'git branch --list',
  'git log --oneline -5',
  'git diff --stat',
  'git show HEAD',
  'git rev-parse --short HEAD',
  'git describe --tags',
  'git blame file.ts',
  'git tag',
  'git ls-files',
  'git cat-file -p HEAD',
  'git merge-base --is-ancestor a b',
  'git show-ref --verify -q refs/heads/main',
  'git reflog show',
  'git -C pkg status',
  'git -C pkg branch --format=%(refname)',
  'git --no-pager log -1',
]

/** Mutating, but nothing is destroyed. LOW is the right lane; must not be HIGH. */
const ORDINARY_MUTATIONS = [
  'git add -A',
  'git commit -m "feat: x"',
  'git checkout -b feat/new',
  'git checkout -B feat/new',
  'git switch -c feat/new',
  'git branch -m old new',
  'git branch feat/new',
  'git fetch origin',
  'git pull --ff-only origin main',
  'git merge --no-ff feat/x',
  'git stash push -m wip',
  'git stash pop',
  'git tag -a v1 -m one',
]

test('destructive git forms reach HIGH, so they ask instead of running silently', () => {
  for (const [cmd, why] of DESTRUCTIVE) {
    const r = classifyBash(cmd)
    assert.equal(r.risk, RISK.HIGH, `${cmd} (${why}) → ${r.risk}: ${r.reasons.join('; ')}`)
    assert.equal(r.category, CATEGORY.WRITE, `${cmd} must not be categorised as a read`)
    assert.equal(r.reversible, false, `${cmd} is not reversible`)
  }
})

test("git's global options do not launder a destructive command", () => {
  // The whole bug: `-C <path>` moved the subcommand and the regexes stopped matching.
  for (const cmd of DESTRUCTIVE_WITH_GLOBALS) {
    const r = classifyBash(cmd)
    assert.equal(r.risk, RISK.HIGH, `${cmd} → ${r.risk}: ${r.reasons.join('; ')}`)
    assert.notEqual(r.category, CATEGORY.READ, `${cmd} must never read as a read`)
  }
})

test('a destructive form and its plain equivalent classify identically', () => {
  // Pins the property directly rather than trusting two separate tables.
  const pairs = [
    ['git reset --hard origin/main', 'git -C pkg reset --hard origin/main'],
    ['git clean -fdx', 'git -C pkg clean -fdx'],
    ['git push --force origin main', 'git -C pkg push --force origin main'],
    ['git branch -D x', 'git -C pkg branch -D x'],
  ]
  for (const [plain, withGlobal] of pairs) {
    const a = classifyBash(plain)
    const b = classifyBash(withGlobal)
    assert.equal(b.risk, a.risk, `${withGlobal} (${b.risk}) must match ${plain} (${a.risk})`)
  }
})

test('reads stay safe — a floor that prompts on `git status` gets turned off', () => {
  for (const cmd of READS) {
    const r = classifyBash(cmd)
    assert.equal(r.risk, RISK.SAFE, `${cmd} → ${r.risk}: ${r.reasons.join('; ')}`)
    assert.equal(r.category, CATEGORY.READ, `${cmd} should classify as a read`)
  }
})

test('ordinary mutations are not escalated to HIGH', () => {
  for (const cmd of ORDINARY_MUTATIONS) {
    const r = classifyBash(cmd)
    assert.notEqual(r.risk, RISK.HIGH, `${cmd} → HIGH: ${r.reasons.join('; ')}`)
  }
})

test('the subcommand is resolved past every global option form', () => {
  const cases = [
    ['git branch -D x', 'branch'],
    ['git -C pkg branch -D x', 'branch'],
    ['git -C pkg status', 'status'],
    ['git --git-dir=/x/.git log', 'log'],
    ['git --git-dir /x/.git log', 'log'],
    ['git -c a=b -c c=d commit', 'commit'],
    ['git --work-tree=/w -C /c reset', 'reset'],
    ['git -P --no-pager diff', 'diff'],
    ['/usr/bin/git status', 'status'],
    ['FOO=bar git status', 'status'],
    ['git', ''],
  ]
  for (const [cmd, want] of cases) {
    assert.equal(parseGitInvocation(cmd).sub, want, cmd)
  }
})

test('an unknown subcommand is never treated as a read', () => {
  // Fail toward "governed" rather than toward "safe". A git version that grows a
  // destructive verb this file has never heard of must not arrive pre-approved.
  for (const sub of ['', 'some-future-verb', 'nuke']) {
    assert.equal(isGitRead(sub, []), false, `${sub || '(empty)'} must not read as a read`)
  }
})

test('a read subcommand carrying a write flag is not a read', () => {
  // `branch` and `tag` earn their place on the read list from their bare form only.
  assert.equal(isGitRead('branch', ['-m', 'old', 'new']), false, 'branch -m renames')
  assert.equal(isGitRead('branch', ['--set-upstream-to=origin/x']), false, 'sets upstream')
  assert.equal(isGitRead('tag', ['-a', 'v1', '-m', 'x']), false, 'tag -a writes a tag')
  assert.equal(isGitRead('tag', ['v1']), false, 'tag <name> creates a tag')
  assert.equal(isGitRead('reflog', ['expire']), false, 'reflog expire is not a read')
  assert.equal(isGitRead('branch', []), true, 'bare branch lists')
  assert.equal(isGitRead('tag', []), true, 'bare tag lists')
  assert.equal(isGitRead('reflog', ['show']), true, 'reflog show reads')
})

test('everything after `--` is a pathspec, not a flag', () => {
  // A file genuinely named `-D` must not be read as the delete flag, and the flag
  // scan must stop at the separator.
  assert.equal(gitDestructiveReason('branch', ['--', '-D']), null, 'a pathspec named -D is not a flag')
  assert.equal(gitDestructiveReason('branch', ['-D', 'x'])?.reason, 'deletes a branch (git branch -d/-D)')
})

test('the shape that actually caused the incident', () => {
  // Verbatim from the loop that deleted 41 branches. It was classified
  // `git read: branch`, risk safe, and allowed.
  const cmd = 'git -C $p branch -D "$b"'
  const r = classifyBash(cmd)
  assert.equal(r.risk, RISK.HIGH, `${cmd} → ${r.risk}: ${r.reasons.join('; ')}`)
  assert.match(r.reasons.join('; '), /deletes a branch/)
})
