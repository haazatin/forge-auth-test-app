import { escapeHtml } from "./auth.js";

type PageOptions = { title: string; body: string; notice?: string; error?: string };

export function layout({ title, body, notice, error }: PageOptions): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)} · Auth Lab</title><link rel="stylesheet" href="/styles.css"></head><body><main class="shell"><a class="brand" href="/">Auth Lab</a>${notice ? `<div class="message notice" role="status">${escapeHtml(notice)}</div>` : ""}${error ? `<div class="message error" role="alert">${escapeHtml(error)}</div>` : ""}${body}</main></body></html>`;
}

export const csrfField = (token: string): string => `<input type="hidden" name="_csrf" value="${escapeHtml(token)}">`;

export function authForm(options: { title: string; action: string; csrf: string; submit: string; includeEmail?: boolean; confirm?: boolean; notice?: string; error?: string; links?: string }): string {
  const email = options.includeEmail === false ? "" : `<label>Email<input name="email" type="email" autocomplete="email" required maxlength="254"></label>`;
  const confirm = options.confirm ? `<label>Confirm new password<input name="confirmPassword" type="password" autocomplete="new-password" required minlength="12" maxlength="128"></label>` : "";
  return layout({ title: options.title, notice: options.notice, error: options.error, body: `<section class="card"><h1>${escapeHtml(options.title)}</h1><form method="post" action="${escapeHtml(options.action)}">${csrfField(options.csrf)}${email}<label>Password<input name="password" type="password" autocomplete="${options.confirm ? "new-password" : "current-password"}" required minlength="12" maxlength="128"></label>${confirm}<button type="submit">${escapeHtml(options.submit)}</button></form>${options.links ?? ""}</section>` });
}
