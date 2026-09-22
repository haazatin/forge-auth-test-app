import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import express, { type NextFunction, type Request, type Response } from "express";
import rateLimit from "express-rate-limit";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import helmet from "helmet";
import type pg from "pg";
import { escapeHtml, hashPassword, isAllowedEmailDomain, normalizeEmail, validateEmail, validatePassword, verifyPassword } from "./auth.js";
import { authForm, csrfField, layout } from "./pages.js";

declare module "express-session" {
  interface SessionData { userId?: string; email?: string; emailVerified?: boolean; csrfToken?: string; flash?: string; verificationTestUrl?: string }
}

type AppConfig = { pool: pg.Pool; sessionSecret: string; nodeEnv: string; baseUrl: string; resetDelivery: "screen" | "log"; allowedEmailDomain: string; emailVerificationDelivery: "screen" };
const sha256 = (value: string): string => createHash("sha256").update(value).digest("hex");

export function createApp(config: AppConfig): express.Express {
  const app = express();
  const PgSession = connectPgSimple(session);
  app.set("trust proxy", 1);
  app.disable("x-powered-by");
  app.use(helmet({ contentSecurityPolicy: { directives: { "style-src": ["'self'"] } } }));
  app.use(express.urlencoded({ extended: false, limit: "16kb" }));
  app.use(express.static("public", { maxAge: config.nodeEnv === "production" ? "1h" : 0 }));
  app.use(session({
    store: new PgSession({ pool: config.pool, tableName: "user_sessions", createTableIfMissing: true }),
    name: "auth_lab_session", secret: config.sessionSecret, resave: false, saveUninitialized: false, rolling: true,
    cookie: { httpOnly: true, sameSite: "lax", secure: config.nodeEnv === "production", maxAge: 1000 * 60 * 60 }
  }));
  app.use((req, res, next) => {
    const startedAt = Date.now();
    res.on("finish", () => console.log(JSON.stringify({ level: "info", event: "http_request", method: req.method, path: req.path, status: res.statusCode, duration_ms: Date.now() - startedAt })));
    next();
  });

  const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: "draft-8", legacyHeaders: false });
  const csrf = (req: Request): string => req.session.csrfToken ?? (req.session.csrfToken = randomBytes(32).toString("hex"));
  const verifyCsrf = (req: Request, res: Response, next: NextFunction): void => {
    const expected = req.session.csrfToken;
    const supplied = typeof req.body?._csrf === "string" ? req.body._csrf : "";
    const valid = expected && supplied.length === expected.length && timingSafeEqual(Buffer.from(supplied), Buffer.from(expected));
    if (!valid) { res.status(403).send(layout({ title: "Request rejected", error: "Your form expired. Please go back and try again.", body: `<a class="button" href="/">Return home</a>` })); return; }
    next();
  };
  const requireAuth = (req: Request, res: Response, next: NextFunction): void => {
    if (!req.session.userId) { res.redirect("/login"); return; }
    next();
  };
  const requireVerified = (req: Request, res: Response, next: NextFunction): void => {
    if (!req.session.userId) { res.redirect("/login"); return; }
    if (!req.session.emailVerified) { res.redirect("/verify-email"); return; }
    next();
  };
  const regenerateAndLogin = (req: Request, userId: string, email: string, emailVerified: boolean): Promise<void> => new Promise((resolve, reject) => {
    req.session.regenerate((error) => {
      if (error) return reject(error);
      req.session.userId = userId; req.session.email = email; req.session.emailVerified = emailVerified; req.session.csrfToken = randomBytes(32).toString("hex");
      req.session.save((saveError) => saveError ? reject(saveError) : resolve());
    });
  });
  const issueVerificationLink = async (userId: string): Promise<string> => {
    const token = randomBytes(32).toString("base64url");
    await config.pool.query("DELETE FROM email_verification_tokens WHERE user_id = $1 OR expires_at < NOW()", [userId]);
    await config.pool.query("INSERT INTO email_verification_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL '15 minutes')", [sha256(token), userId]);
    return `${config.baseUrl}/verify-email/confirm?token=${token}`;
  };
  const setTestVerificationLink = (req: Request, url: string): void => {
    if (config.emailVerificationDelivery === "screen") req.session.verificationTestUrl = url;
  };

  app.get("/healthz", (_req, res) => res.json({ status: "ok" }));
  app.get("/readyz", async (_req, res) => { try { await config.pool.query("SELECT 1"); res.json({ status: "ready" }); } catch { res.status(503).json({ status: "not_ready" }); } });
  app.get("/", (req, res) => {
    const links = req.session.userId ? `<a class="button" href="${req.session.emailVerified ? "/success" : "/verify-email"}">${req.session.emailVerified ? "Open success page" : "Verify email"}</a>` : `<a class="button" href="/login">Sign in</a><a class="button secondary" href="/signup">Create account</a>`;
    res.send(layout({ title: "Authentication test app", body: `<section class="hero"><span class="eyebrow">FORGE TEST APP</span><h1>Authentication, without the mystery.</h1><p>Exercise a complete account flow in a small, secure test application.</p><div class="actions">${links}</div></section>` }));
  });

  app.get(["/login", "/signin"], (req, res) => {
    const notice = req.session.flash; delete req.session.flash;
    res.send(authForm({ title: "Sign in", action: "/login", csrf: csrf(req), submit: "Sign in", notice, links: `<p class="links"><a href="/forgot-password">Forgot password?</a><a href="/signup">Create account</a></p>` }));
  });
  app.post("/login", authLimiter, verifyCsrf, async (req, res, next) => { try {
    const email = normalizeEmail(req.body.email); const password = typeof req.body.password === "string" ? req.body.password : "";
    const result = await config.pool.query<{ id: string; email: string; password_hash: string; email_verified_at: Date | null }>("SELECT id, email, password_hash, email_verified_at FROM users WHERE email = $1", [email]);
    const user = result.rows[0];
    if (!isAllowedEmailDomain(email, config.allowedEmailDomain) || !user || !(await verifyPassword(password, user.password_hash))) { res.status(401).send(authForm({ title: "Sign in", action: "/login", csrf: csrf(req), submit: "Sign in", error: "Email or password is incorrect.", links: `<p class="links"><a href="/forgot-password">Forgot password?</a><a href="/signup">Create account</a></p>` })); return; }
    const verified = Boolean(user.email_verified_at);
    await regenerateAndLogin(req, user.id, user.email, verified);
    if (!verified) { const verificationUrl = await issueVerificationLink(user.id); setTestVerificationLink(req, verificationUrl); res.redirect("/verify-email"); return; }
    res.redirect("/success");
  } catch (error) { next(error); } });

  app.get("/signup", (req, res) => res.send(authForm({ title: "Create account", action: "/signup", csrf: csrf(req), submit: "Create account", confirm: true, links: `<p class="links"><a href="/login">Already have an account?</a></p>` })));
  app.post("/signup", authLimiter, verifyCsrf, async (req, res, next) => { try {
    const email = normalizeEmail(req.body.email); const password = req.body.password;
    const problem = !validateEmail(email) ? "Enter a valid email address." : !isAllowedEmailDomain(email, config.allowedEmailDomain) ? `Use a ${config.allowedEmailDomain} email address.` : validatePassword(password) ?? (password !== req.body.confirmPassword ? "Passwords do not match." : null);
    if (problem) { res.status(400).send(authForm({ title: "Create account", action: "/signup", csrf: csrf(req), submit: "Create account", confirm: true, error: problem })); return; }
    const id = randomUUID(); const passwordHash = await hashPassword(password);
    try { await config.pool.query("INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)", [id, email, passwordHash]); }
    catch (error: unknown) { if ((error as { code?: string }).code === "23505") { res.status(409).send(authForm({ title: "Create account", action: "/signup", csrf: csrf(req), submit: "Create account", confirm: true, error: "An account with that email already exists." })); return; } throw error; }
    await regenerateAndLogin(req, id, email, false); const verificationUrl = await issueVerificationLink(id); setTestVerificationLink(req, verificationUrl); res.redirect("/verify-email");
  } catch (error) { next(error); } });

  app.get("/verify-email", requireAuth, (req, res) => {
    if (req.session.emailVerified) { res.redirect("/success"); return; }
    const notice = req.session.flash; delete req.session.flash;
    res.send(verificationPendingPage(csrf(req), req.session.email ?? "", req.session.verificationTestUrl, notice));
  });
  app.post("/verify-email/resend", requireAuth, authLimiter, verifyCsrf, async (req, res, next) => { try {
    if (req.session.emailVerified) { res.redirect("/success"); return; }
    const verificationUrl = await issueVerificationLink(req.session.userId!); setTestVerificationLink(req, verificationUrl); req.session.flash = "A new verification link was created."; res.redirect("/verify-email");
  } catch (error) { next(error); } });
  app.get("/verify-email/confirm", (req, res) => {
    const token = typeof req.query.token === "string" ? req.query.token : "";
    res.send(layout({ title: "Confirm your email", body: `<section class="card"><span class="eyebrow">ONE MORE STEP</span><h1>Confirm your email</h1><p>Continue to prove you opened the verification link.</p><form method="post" action="/verify-email/confirm">${csrfField(csrf(req))}<input type="hidden" name="token" value="${escapeHtml(token)}"><button type="submit">Verify email</button></form></section>` }));
  });
  app.post("/verify-email/confirm", authLimiter, verifyCsrf, async (req, res, next) => {
    const client = await config.pool.connect();
    try {
      const token = typeof req.body.token === "string" ? req.body.token : "";
      await client.query("BEGIN");
      const result = await client.query<{ user_id: string; email: string }>("SELECT token.user_id, users.email FROM email_verification_tokens token JOIN users ON users.id = token.user_id WHERE token.token_hash = $1 AND token.used_at IS NULL AND token.expires_at > NOW() FOR UPDATE OF token", [sha256(token)]);
      const row = result.rows[0];
      if (!row) { await client.query("ROLLBACK"); res.status(400).send(layout({ title: "Invalid verification link", error: "This verification link is invalid or has expired.", body: `<a class="button" href="/verify-email">Request a new link</a>` })); return; }
      await client.query("UPDATE users SET email_verified_at = COALESCE(email_verified_at, NOW()), updated_at = NOW() WHERE id = $1", [row.user_id]);
      await client.query("UPDATE email_verification_tokens SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL", [row.user_id]);
      await client.query("COMMIT");
      await regenerateAndLogin(req, row.user_id, row.email, true); req.session.flash = "Email verified successfully."; res.redirect("/success");
    } catch (error) { await client.query("ROLLBACK").catch(() => undefined); next(error); } finally { client.release(); }
  });

  app.get("/success", requireVerified, (req, res) => { const notice = req.session.flash; delete req.session.flash; res.send(layout({ title: "Success", notice, body: `<section class="card success"><div class="check">✓</div><span class="eyebrow">AUTHENTICATED &amp; VERIFIED</span><h1>Success!</h1><p>You are signed in as <strong>${escapeHtml(req.session.email)}</strong>.</p><div class="actions"><a class="button secondary" href="/change-password">Change password</a><form method="post" action="/logout">${csrfField(csrf(req))}<button type="submit">Sign out</button></form></div></section>` })); });
  app.post("/logout", requireAuth, verifyCsrf, (req, res, next) => req.session.destroy((error) => error ? next(error) : res.redirect("/login")));

  app.get("/change-password", requireVerified, (req, res) => res.send(changePasswordPage(csrf(req))));
  app.post("/change-password", requireVerified, authLimiter, verifyCsrf, async (req, res, next) => { try {
    const result = await config.pool.query<{ password_hash: string }>("SELECT password_hash FROM users WHERE id = $1", [req.session.userId]); const user = result.rows[0];
    const problem = !user || !(await verifyPassword(String(req.body.currentPassword ?? ""), user.password_hash)) ? "Current password is incorrect." : validatePassword(req.body.password) ?? (req.body.password !== req.body.confirmPassword ? "Passwords do not match." : null);
    if (problem) { res.status(400).send(changePasswordPage(csrf(req), problem)); return; }
    await config.pool.query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2", [await hashPassword(req.body.password), req.session.userId]); req.session.flash = "Password changed successfully."; res.redirect("/success");
  } catch (error) { next(error); } });

  app.get("/forgot-password", (req, res) => res.send(layout({ title: "Forgot password", body: `<section class="card"><h1>Reset your password</h1><p>Enter your account email. We’ll create a time-limited reset link.</p><form method="post" action="/forgot-password">${csrfField(csrf(req))}<label>Email<input name="email" type="email" autocomplete="email" required></label><button type="submit">Continue</button></form></section>` })));
  app.post("/forgot-password", authLimiter, verifyCsrf, async (req, res, next) => { try {
    const email = normalizeEmail(req.body.email); const user = (await config.pool.query<{ id: string }>("SELECT id FROM users WHERE email = $1", [email])).rows[0]; let resetUrl: string | undefined;
    if (user) { const token = randomBytes(32).toString("base64url"); await config.pool.query("DELETE FROM password_reset_tokens WHERE user_id = $1 OR expires_at < NOW()", [user.id]); await config.pool.query("INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL '30 minutes')", [sha256(token), user.id]); resetUrl = `${config.baseUrl}/reset-password?token=${token}`; if (config.resetDelivery === "log") console.log(JSON.stringify({ level: "info", event: "password_reset_requested", reset_url: resetUrl })); }
    const testLink = config.resetDelivery === "screen" && resetUrl ? `<p class="test-link"><strong>Test mode:</strong> <a href="${escapeHtml(resetUrl)}">open password reset link</a></p>` : "";
    res.send(layout({ title: "Check your reset instructions", body: `<section class="card"><h1>Check your reset instructions</h1><p>If an account exists for that email, a reset link has been created.</p>${testLink}<a class="button secondary" href="/login">Return to sign in</a></section>` }));
  } catch (error) { next(error); } });
  app.get("/reset-password", (req, res) => { const token = typeof req.query.token === "string" ? req.query.token : ""; res.send(resetPasswordPage(csrf(req), token)); });
  app.post("/reset-password", authLimiter, verifyCsrf, async (req, res, next) => {
    const client = await config.pool.connect();
    try {
      const token = typeof req.body.token === "string" ? req.body.token : ""; const problem = validatePassword(req.body.password) ?? (req.body.password !== req.body.confirmPassword ? "Passwords do not match." : null);
      if (problem) { res.status(400).send(resetPasswordPage(csrf(req), token, problem)); return; }
      await client.query("BEGIN"); const result = await client.query<{ user_id: string }>("SELECT user_id FROM password_reset_tokens WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW() FOR UPDATE", [sha256(token)]); const row = result.rows[0];
      if (!row) { await client.query("ROLLBACK"); res.status(400).send(layout({ title: "Invalid reset link", error: "This reset link is invalid or has expired.", body: `<a class="button" href="/forgot-password">Request a new link</a>` })); return; }
      await client.query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2", [await hashPassword(req.body.password), row.user_id]); await client.query("UPDATE password_reset_tokens SET used_at = NOW() WHERE token_hash = $1", [sha256(token)]); await client.query("DELETE FROM user_sessions WHERE sess->>'userId' = $1", [row.user_id]); await client.query("COMMIT"); req.session.flash = "Password reset. Sign in with your new password."; res.redirect("/login");
    } catch (error) { await client.query("ROLLBACK").catch(() => undefined); next(error); } finally { client.release(); }
  });

  app.use((_req, res) => res.status(404).send(layout({ title: "Not found", body: `<section class="card"><h1>Page not found</h1><a class="button" href="/">Return home</a></section>` })));
  app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => { console.error(JSON.stringify({ level: "error", event: "request_failed", message: error instanceof Error ? error.message : "unknown_error" })); res.status(500).send(layout({ title: "Something went wrong", error: "The request could not be completed.", body: `<a class="button" href="/">Return home</a>` })); });
  return app;
}

function changePasswordPage(csrf: string, error?: string): string {
  return layout({ title: "Change password", error, body: `<section class="card"><h1>Change password</h1><form method="post" action="/change-password">${csrfField(csrf)}<label>Current password<input name="currentPassword" type="password" autocomplete="current-password" required></label><label>New password<input name="password" type="password" autocomplete="new-password" minlength="12" maxlength="128" required></label><label>Confirm new password<input name="confirmPassword" type="password" autocomplete="new-password" minlength="12" maxlength="128" required></label><button type="submit">Update password</button></form></section>` });
}

function resetPasswordPage(csrf: string, token: string, error?: string): string {
  return layout({ title: "Choose a new password", error, body: `<section class="card"><h1>Choose a new password</h1><form method="post" action="/reset-password">${csrfField(csrf)}<input type="hidden" name="token" value="${escapeHtml(token)}"><label>New password<input name="password" type="password" autocomplete="new-password" minlength="12" maxlength="128" required></label><label>Confirm new password<input name="confirmPassword" type="password" autocomplete="new-password" minlength="12" maxlength="128" required></label><button type="submit">Reset password</button></form></section>` });
}

function verificationPendingPage(csrf: string, email: string, testUrl?: string, notice?: string): string {
  const testLink = testUrl ? `<p class="test-link"><strong>Local test mode:</strong> <a href="${escapeHtml(testUrl)}">open email verification link</a></p>` : "";
  return layout({ title: "Verify your email", notice, body: `<section class="card"><span class="eyebrow">EMAIL CHECK</span><h1>Verify your email</h1><p>We created a 15-minute verification link for <strong>${escapeHtml(email)}</strong>. You must verify this address before entering the app.</p>${testLink}<form method="post" action="/verify-email/resend">${csrfField(csrf)}<button type="submit">Create a new link</button></form><form method="post" action="/logout">${csrfField(csrf)}<button class="button secondary" type="submit">Sign out</button></form></section>` });
}
