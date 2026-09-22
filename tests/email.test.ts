import assert from "node:assert/strict";
import test from "node:test";
import { createSendGridEmailSender } from "../src/email.js";

test("SendGrid email configuration requires a valid sender", () => {
  assert.throws(() => createSendGridEmailSender({
    apiKey: "test-key",
    apiBaseUrl: "https://sendgrid-api.example.invalid",
    fromEmail: "not-an-email",
    fromName: "Auth Lab"
  }), /valid email address/);
});

test("SendGrid email configuration rejects insecure non-local endpoints", () => {
  assert.throws(() => createSendGridEmailSender({
    apiKey: "test-key",
    apiBaseUrl: "http://mail.example.com",
    fromEmail: "auth@example.com",
    fromName: "Auth Lab"
  }), /must use HTTPS/);
});
