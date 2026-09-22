import assert from "node:assert/strict";
import test from "node:test";
import { escapeHtml, hashPassword, isAllowedEmailDomain, normalizeEmail, validateEmail, validatePassword, verifyPassword } from "../src/auth.js";

test("password hashes verify only the original password", async () => {
  const encoded = await hashPassword("a long test password");
  assert.equal(await verifyPassword("a long test password", encoded), true);
  assert.equal(await verifyPassword("the wrong password", encoded), false);
  assert.equal(encoded.includes("a long test password"), false);
});

test("auth input validation normalizes emails and rejects weak passwords", () => {
  assert.equal(normalizeEmail("  Person@Example.COM "), "person@example.com");
  assert.equal(validateEmail("person@example.com"), true);
  assert.equal(validateEmail("not-an-email"), false);
  assert.match(validatePassword("short") ?? "", /at least 12/);
  assert.equal(validatePassword("correct horse battery staple"), null);
});

test("email domains are matched exactly and case-insensitively", () => {
  assert.equal(isAllowedEmailDomain("person@shapira.xyz", "shapira.xyz"), true);
  assert.equal(isAllowedEmailDomain("person@SHAPIRA.XYZ", "shapira.xyz"), true);
  assert.equal(isAllowedEmailDomain("person@team.shapira.xyz", "shapira.xyz"), false);
  assert.equal(isAllowedEmailDomain("person@shapira.xyz.example", "shapira.xyz"), false);
});

test("HTML output is escaped", () => assert.equal(escapeHtml(`<script>alert("x")</script>`), "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"));
