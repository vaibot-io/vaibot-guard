/**
 * floorAsk — the tier between "always denied" and "the preset decides".
 *
 * The guard had two tiers. `DANGEROUS` denies and no preset can override it.
 * Everything else is compared against the preset's `escalateAt`, and the
 * `permissive` preset sets that to `dangerous` — so on permissive, a HIGH-risk
 * action resolves to ALLOW. That is how an agent deleted 41 branches on a
 * developer's machine with no prompt, and measuring the rest of the workflow found
 * 32 commands in the same position: `npm publish`, `cargo publish`, `fly deploy`,
 * `rm -rf <dir>`, `shred`, `gh repo delete`.
 *
 * So there was a notion of "never allowed" but none of "never silent".
 *
 * floorAsk is that missing tier: always ASK, whatever `escalateAt` says. It is not
 * a deny — deleting a merged branch and publishing a release are both legitimate
 * things to do. It only means they cannot happen without someone seeing them.
 *
 * Two tables carry equal weight here. ALWAYS_ASKS is the point of the feature.
 * LEFT_TO_PRESETS is what keeps it honest: the criterion is "cannot be undone by
 * whoever authorised it, and it either leaves this machine or destroys the only
 * copy", and a tier that creeps past that becomes a tier people switch off. A new
 * entry has to fail LEFT_TO_PRESETS deliberately to get in.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { classify, classifyBash, verdictForRisk, RISK, VERDICT } from '../scripts/classifier.mjs'

/** Every shipped preset, with the escalateAt it sets (apps/api/src/policyPresets.ts). */
const PRESETS = [
  ['permissive', 'dangerous'],
  ['balanced', 'high'],
  ['strict', 'medium'],
  ['(default)', undefined],
]

const verdictsFor = (command) =>
  PRESETS.map(([name, escalateAt]) => [name, classify({ tool: 'Bash', input: { command } }, { escalateAt }).verdictHint])

/** Irreversible. Must ask on EVERY preset, permissive included. */
const ALWAYS_ASKS = [
  // registry publishes — a version number can never be reused
  'npm publish',
  'npm publish --access public',
  'pnpm publish -r',
  'yarn publish',
  'cargo publish',
  'twine upload dist/*',
  'python3 -m twine upload dist/*',
  'uv publish',
  'poetry publish',
  'npm unpublish @vaibot/guard@2.2.2',
  'cargo yank --version 0.7.0',

  // production deploys
  'fly deploy',
  'flyctl deploy --app vaibot-api',
  'vercel --prod',
  'vercel deploy --prod',
  'netlify deploy --prod',

  // destruction with no reflog behind it
  'rm -rf ./src',
  'rm -rf node_modules',
  'rm -fr ./dir',
  'shred -u secrets.txt',
  'find . -name "*.mjs" -delete',
  'find . -name "*.tmp" -exec rm {} ;',
  'truncate -s 0 important.log',

  // hosted artefacts — irreversible AND it affects everyone else
  'gh repo delete vaibot-io/thing',
  'glab repo delete campbell-labs/thing',
  'gh release delete v1.0.0',

  // a secret's only copy
  'fly secrets unset OLD_KEY',
  'flyctl secrets remove OLD_KEY',
  'vercel env rm SUPABASE_URL production',
  'gh secret delete NPM_TOKEN',

  // says outright that it is destructive
  'supabase db reset',

  // git — the incident that started this
  'git branch -D feat/thing',
  'git -C pkg branch -D feat/thing',
  'git tag -d v1.0.0',
  'git reset --hard origin/main',
  'git clean -fdx',
  'git checkout -- .',
  'git restore src/',
  'git stash drop',
  'git push --force origin main',
  'git push --delete origin feat/x',
  'git submodule deinit -f .',
  'git gc --prune=now',
  'git reflog expire --expire=now --all',
  'git update-ref -d refs/heads/x',
  'git filter-branch --all',
]

/**
 * Deliberately NOT floorAsk. Each is either reversible, or its consequence is not
 * visible in the command text, or it is frequent enough that prompting would train
 * people to switch the floor off. They must still ALLOW on permissive — that is the
 * proof the tier stayed narrow.
 */
const LEFT_TO_PRESETS = [
  // additive; the value is in the operator's hands
  'fly secrets set SUPABASE_URL=x',
  'vercel env add SUPABASE_URL production',
  'gh secret set NPM_TOKEN',
  // revertible, and constant in normal work
  'gh pr merge 11 --merge',
  'glab mr merge 58',
  'gh pr close 11',
  'git push origin main',
  // the command does not say which environment it points at, and these are frequent
  'psql -c "DROP TABLE receipts"',
  'supabase db push',
  // routine
  'git submodule update --init --recursive',
  'git add -A',
  'git commit -m "feat: x"',
  'git fetch origin',
]

/** Routine work. Must stay silent everywhere or the floor becomes unusable. */
const STAYS_SILENT = [
  'git status',
  'git branch',
  'git log --oneline -5',
  'git diff --stat',
  'npm test',
  'npm run build',
  'cargo test',
  'ls -la',
  'cat README.md',
]

test('an irreversible action asks on every preset, permissive included', () => {
  for (const cmd of ALWAYS_ASKS) {
    for (const [preset, verdict] of verdictsFor(cmd)) {
      assert.equal(verdict, VERDICT.ASK, `${cmd} on ${preset} → ${verdict}`)
    }
  }
})

test('floorAsk asks — it never becomes a deny', () => {
  // The distinction Briant drew: a legitimate reason to do these exists, so the
  // answer is "not silently", not "not at all".
  for (const cmd of ALWAYS_ASKS) {
    const r = classify({ tool: 'Bash', input: { command: cmd } }, { escalateAt: 'medium' })
    assert.notEqual(r.verdictHint, VERDICT.DENY, `${cmd} must not be denied outright`)
    assert.notEqual(r.risk, RISK.DANGEROUS, `${cmd} should be floorAsk, not the deny floor`)
  }
})

test('the catastrophic floor still outranks floorAsk', () => {
  // DANGEROUS is checked first, so a command that is both still denies.
  assert.equal(verdictForRisk(RISK.DANGEROUS, 'dangerous', true), VERDICT.DENY)
  assert.equal(verdictForRisk(RISK.DANGEROUS, 'medium', true), VERDICT.DENY)
})

test('verdictForRisk: the tier does exactly one thing', () => {
  // Without the flag, permissive allows HIGH — the bug this tier exists for.
  assert.equal(verdictForRisk(RISK.HIGH, 'dangerous', false), VERDICT.ALLOW)
  assert.equal(verdictForRisk(RISK.HIGH, 'dangerous', true), VERDICT.ASK)
  // And it does not disturb the ordinary threshold behaviour.
  assert.equal(verdictForRisk(RISK.HIGH, 'high', false), VERDICT.ASK)
  assert.equal(verdictForRisk(RISK.LOW, 'medium', false), VERDICT.ALLOW)
  assert.equal(verdictForRisk(RISK.SAFE, 'medium', true), VERDICT.ASK, 'the flag wins even from SAFE')
})

test('the tier stayed narrow — the exclusions still allow on permissive', () => {
  // This is the test that stops floorAsk growing into "ask about everything". If an
  // entry here starts asking, either it was added to the table on purpose (move it
  // to ALWAYS_ASKS and say why) or the pattern is too broad.
  for (const cmd of LEFT_TO_PRESETS) {
    const [, verdict] = verdictsFor(cmd)[0] // permissive
    assert.equal(verdict, VERDICT.ALLOW, `${cmd} is meant to be left to the preset, got ${verdict} on permissive`)
  }
})

test('routine work is untouched on every preset', () => {
  for (const cmd of STAYS_SILENT) {
    for (const [preset, verdict] of verdictsFor(cmd)) {
      assert.equal(verdict, VERDICT.ALLOW, `${cmd} on ${preset} → ${verdict}; a floor that prompts on this gets turned off`)
    }
  }
})

test('the flag is surfaced, and names the consequence', () => {
  // A receipt and an approval prompt want to say different things about "the preset
  // asked" versus "this may never be silent", so the reason has to be legible.
  const r = classify({ tool: 'Bash', input: { command: 'cargo publish' } }, { escalateAt: 'dangerous' })
  assert.equal(r.floorAsk, true)
  assert.match(r.reasons.join('; '), /irreversible: publishes to crates\.io/)

  const git = classifyBash('git branch -D x')
  assert.equal(git.floorAsk, true)
  assert.match(git.reasons.join('; '), /deletes a branch/)

  const ordinary = classify({ tool: 'Bash', input: { command: 'git push origin main' } })
  assert.equal(ordinary.floorAsk, false, 'an ordinary push is HIGH but not floorAsk')
})

test('every floorAsk action is receipted, not merely ledgered', () => {
  // An irreversible action that nobody can find afterwards is the other half of the
  // problem. floorAsk implies HIGH, and receiptTierFor keys off risk.
  for (const cmd of ALWAYS_ASKS) {
    const r = classify({ tool: 'Bash', input: { command: cmd } })
    assert.equal(r.receiptTier, 'receipt', `${cmd} → ${r.receiptTier}`)
    assert.equal(r.reversible, false, `${cmd} should not be marked reversible`)
  }
})

test('the six commands that were allowed on EVERY preset now ask', () => {
  // Found by auditing the real workflow on this machine. `cargo publish` was the
  // worst: crates.io is permanent, a yank does not remove it, and it was rated
  // `low`. `find -delete` was rated `safe`.
  const wereAlwaysAllowed = [
    'cargo publish',
    'python3 -m twine upload dist/*',
    'npm unpublish @vaibot/guard@2.2.2',
    'cargo yank --version 0.7.0',
    'find . -name "*.mjs" -delete',
    'git submodule deinit -f .',
  ]
  for (const cmd of wereAlwaysAllowed) {
    for (const [preset, verdict] of verdictsFor(cmd)) {
      assert.equal(verdict, VERDICT.ASK, `${cmd} on ${preset} → ${verdict}`)
    }
  }
})
