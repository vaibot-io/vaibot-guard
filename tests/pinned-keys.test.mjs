import test from "node:test";
import assert from "node:assert/strict";

import {
  PINNED_STAGING_PUBKEY,
  PINNED_PROD_PUBKEY,
  pickPolicyPubkey,
} from "../scripts/pinned-keys.mjs";

test("pinned staging pubkey is a well-formed Ed25519 SPKI PEM", () => {
  assert.match(PINNED_STAGING_PUBKEY, /-----BEGIN PUBLIC KEY-----/);
  assert.match(PINNED_STAGING_PUBKEY, /-----END PUBLIC KEY-----/);
  // Ed25519 SPKI in base64 is exactly 60 chars in the body (12-byte
  // ASN.1/OID prefix + 32-byte raw pubkey = 44 bytes → 60 b64 chars incl
  // padding) — quick sanity check that we didn't accidentally pin an RSA /
  // EC key, which would be much longer.
  const body = PINNED_STAGING_PUBKEY
    .replace("-----BEGIN PUBLIC KEY-----", "")
    .replace("-----END PUBLIC KEY-----", "")
    .replace(/\s/g, "");
  assert.equal(body.length, 60);
});

test("prod pubkey is provisioned (Ed25519 SPKI PEM, 32-byte key)", () => {
  // Provisioned 2026-07-01 on vaibot-api-v2. Mirrors the staging-shape check above.
  assert.match(PINNED_PROD_PUBKEY, /-----BEGIN PUBLIC KEY-----/);
  assert.match(PINNED_PROD_PUBKEY, /-----END PUBLIC KEY-----/);
  const body = PINNED_PROD_PUBKEY
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s/g, "");
  assert.equal(body.length, 60);
});

test("VAIBOT_POLICY_PUBKEY override wins over everything else", () => {
  const overrideKey = "-----BEGIN PUBLIC KEY-----\nOVERRIDE\n-----END PUBLIC KEY-----\n";
  assert.equal(pickPolicyPubkey({ VAIBOT_POLICY_PUBKEY: overrideKey, VAIBOT_ENV: "staging" }), overrideKey);
  assert.equal(pickPolicyPubkey({ VAIBOT_POLICY_PUBKEY: overrideKey, VAIBOT_ENV: "production" }), overrideKey);
  assert.equal(pickPolicyPubkey({ VAIBOT_POLICY_PUBKEY: overrideKey, VAIBOT_POLICY_URL: "https://staging-api.vaibot.io/v2/policy" }), overrideKey);
  assert.equal(pickPolicyPubkey({ VAIBOT_POLICY_PUBKEY: overrideKey }), overrideKey);
});

test("VAIBOT_ENV=staging picks the pinned staging pubkey", () => {
  assert.equal(pickPolicyPubkey({ VAIBOT_ENV: "staging" }), PINNED_STAGING_PUBKEY);
  assert.equal(pickPolicyPubkey({ VAIBOT_ENV: "STAGING" }), PINNED_STAGING_PUBKEY);
});

test("default and VAIBOT_ENV=production both fall through to the pinned prod pubkey", () => {
  assert.equal(pickPolicyPubkey({}), PINNED_PROD_PUBKEY);
  assert.equal(pickPolicyPubkey({ VAIBOT_ENV: "production" }), PINNED_PROD_PUBKEY);
  assert.equal(pickPolicyPubkey({ VAIBOT_ENV: "prod" }), PINNED_PROD_PUBKEY); // unknown env → fallthrough
});

test("empty VAIBOT_POLICY_PUBKEY is treated as 'no override' (falls through)", () => {
  // process.env values are strings; an empty string should not override the
  // pinned key (otherwise an unset-but-defined VAIBOT_POLICY_PUBKEY="" in a
  // .env file would silently disable verification).
  assert.equal(pickPolicyPubkey({ VAIBOT_POLICY_PUBKEY: "", VAIBOT_ENV: "staging" }), PINNED_STAGING_PUBKEY);
});

test("VAIBOT_POLICY_URL infers the env when VAIBOT_ENV is unset", () => {
  // The CLI pins VAIBOT_POLICY_URL (not VAIBOT_ENV) on the guard, so a staging
  // guard must still resolve the staging key from the URL alone.
  assert.equal(
    pickPolicyPubkey({ VAIBOT_POLICY_URL: "https://staging-api.vaibot.io/v2/policy" }),
    PINNED_STAGING_PUBKEY,
  );
  assert.equal(
    pickPolicyPubkey({ VAIBOT_POLICY_URL: "https://api.vaibot.io/v2/policy" }),
    PINNED_PROD_PUBKEY,
  );
});

test("an explicit VAIBOT_ENV wins over a mismatched VAIBOT_POLICY_URL", () => {
  assert.equal(
    pickPolicyPubkey({ VAIBOT_ENV: "production", VAIBOT_POLICY_URL: "https://staging-api.vaibot.io/v2/policy" }),
    PINNED_PROD_PUBKEY,
  );
});
