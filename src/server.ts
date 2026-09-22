import { createApp } from "./app.js";
import { createPool, migrate } from "./database.js";
import { createSendGridEmailSender } from "./email.js";

const required = (name: string): string => { const value = process.env[name]; if (!value) throw new Error(`Missing required environment variable: ${name}`); return value; };
const port = Number(process.env.PORT ?? "8080");
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("PORT must be a valid TCP port");
const nodeEnv = process.env.NODE_ENV ?? "development";
const allowedEmailDomain = (process.env.ALLOWED_EMAIL_DOMAIN ?? "shapira.xyz").trim().toLowerCase();
if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(allowedEmailDomain)) throw new Error("ALLOWED_EMAIL_DOMAIN must be a valid domain name");
const emailSender = createSendGridEmailSender({
  apiKey: required("SENDGRID_API_KEY"),
  apiBaseUrl: required("SENDGRID_API_BASE_URL"),
  fromEmail: required("TRANSACTIONAL_EMAIL_FROM"),
  fromName: process.env.TRANSACTIONAL_EMAIL_FROM_NAME ?? "Auth Lab"
});
const pool = createPool(required("DATABASE_URL"));
await migrate(pool);
const app = createApp({ pool, sessionSecret: required("SESSION_SECRET"), nodeEnv, baseUrl: required("BASE_URL"), allowedEmailDomain, emailSender });
const server = app.listen(port, "0.0.0.0", () => console.log(JSON.stringify({ level: "info", event: "server_started", port })));
let shuttingDown = false;
const shutdown = (signal: string): void => { if (shuttingDown) return; shuttingDown = true; console.log(JSON.stringify({ level: "info", event: "shutdown_started", signal })); server.close(async () => { await pool.end(); console.log(JSON.stringify({ level: "info", event: "shutdown_complete" })); process.exit(0); }); setTimeout(() => process.exit(1), 10_000).unref(); };
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
