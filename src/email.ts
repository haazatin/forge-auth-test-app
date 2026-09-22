import { Client } from "@sendgrid/client";
import sgMail from "@sendgrid/mail";
import { escapeHtml, validateEmail } from "./auth.js";

export interface TransactionalEmailSender {
  sendVerification(to: string, verificationUrl: string): Promise<void>;
  sendPasswordReset(to: string, resetUrl: string): Promise<void>;
}

type SendGridEmailConfig = {
  apiKey: string;
  apiBaseUrl: string;
  fromEmail: string;
  fromName: string;
};

export function createSendGridEmailSender(config: SendGridEmailConfig): TransactionalEmailSender {
  if (!validateEmail(config.fromEmail)) throw new Error("TRANSACTIONAL_EMAIL_FROM must be a valid email address");
  const apiUrl = new URL(config.apiBaseUrl);
  if (apiUrl.protocol !== "https:" && apiUrl.hostname !== "host.docker.internal" && apiUrl.hostname !== "127.0.0.1" && apiUrl.hostname !== "localhost") {
    throw new Error("SENDGRID_API_BASE_URL must use HTTPS outside local testing");
  }

  const client = new Client();
  client.setApiKey(config.apiKey);
  client.setDefaultRequest("baseUrl", config.apiBaseUrl.replace(/\/+$/, ""));
  sgMail.setClient(client);

  const send = async (to: string, subject: string, text: string, html: string): Promise<void> => {
    try {
      await sgMail.send({ to, from: { email: config.fromEmail, name: config.fromName }, subject, text, html });
    } catch {
      throw new Error("Transactional email delivery failed");
    }
  };

  return {
    sendVerification: async (to, verificationUrl) => send(
      to,
      "Verify your Auth Lab email",
      `Verify your email by opening this link: ${verificationUrl}\n\nThis link expires in 15 minutes.`,
      `<p>Verify your email to finish signing in to Auth Lab.</p><p><a href="${escapeHtml(verificationUrl)}">Verify email</a></p><p>This link expires in 15 minutes.</p>`
    ),
    sendPasswordReset: async (to, resetUrl) => send(
      to,
      "Reset your Auth Lab password",
      `Reset your password by opening this link: ${resetUrl}\n\nThis link expires in 30 minutes.`,
      `<p>Use this link to reset your Auth Lab password.</p><p><a href="${escapeHtml(resetUrl)}">Reset password</a></p><p>This link expires in 30 minutes.</p>`
    )
  };
}
