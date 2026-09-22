import assert from "node:assert/strict";
import { createServer } from "node:http";

const baseUrl = process.env.TEST_BASE_URL ?? "http://127.0.0.1:8080";
const emailApiPort = Number(process.env.TEST_EMAIL_API_PORT ?? "19090");
let cookie = "";
const deliveredMessages = [];

const emailApi = createServer((request, response) => {
  let body = "";
  request.setEncoding("utf8");
  request.on("data", (chunk) => { body += chunk; });
  request.on("end", () => {
    if (request.method !== "POST" || request.url !== "/v3/mail/send") { response.writeHead(404).end(); return; }
    deliveredMessages.push(JSON.parse(body));
    response.writeHead(202).end();
  });
});
await new Promise((resolve, reject) => { emailApi.once("error", reject); emailApi.listen(emailApiPort, "0.0.0.0", resolve); });

async function deliveredLink(path) {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    for (const message of deliveredMessages) {
      const content = (message.content ?? []).map((item) => item.value).join("\n");
      const match = content.match(new RegExp(`https?://[^\\s<\"]+${path.replaceAll("/", "\\/")}[^\\s<\"]*`));
      if (match) { deliveredMessages.splice(deliveredMessages.indexOf(message), 1); return match[0]; }
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.fail(`No transactional email containing ${path} was delivered`);
}

async function request(path, options = {}) {
  const headers = new Headers(options.headers);
  if (cookie) headers.set("cookie", cookie);
  const response = await fetch(new URL(path, baseUrl), { ...options, headers, redirect: "manual" });
  const setCookie = response.headers.get("set-cookie");
  if (setCookie) cookie = setCookie.split(";", 1)[0];
  return response;
}

async function page(path) {
  const response = await request(path);
  assert.equal(response.status, 200, `${path} returned ${response.status}`);
  return response.text();
}

function csrf(html) {
  const match = html.match(/name="_csrf" value="([a-f0-9]+)"/);
  assert.ok(match, "CSRF token is present");
  return match[1];
}

async function submit(path, values) {
  return request(path, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(values)
  });
}

const email = `smoke-${Date.now()}@shapira.xyz`;
const firstPassword = "first-password-123";
const secondPassword = "second-password-456";
const finalPassword = "final-password-789";

let html = await page("/signup");
let response = await submit("/signup", { _csrf: csrf(html), email: `blocked-${Date.now()}@example.test`, password: firstPassword, confirmPassword: firstPassword });
assert.equal(response.status, 400);
assert.match(await response.text(), /Use a shapira\.xyz email address/);

html = await page("/signup");
response = await submit("/signup", { _csrf: csrf(html), email, password: firstPassword, confirmPassword: firstPassword });
assert.equal(response.status, 302);
assert.equal(response.headers.get("location"), "/verify-email");

html = await page("/verify-email");
assert.match(html, /We sent a 15-minute verification link/);
const verificationUrl = await deliveredLink("/verify-email/confirm");
const verificationToken = new URL(verificationUrl).searchParams.get("token");
html = await page(verificationUrl);
response = await submit("/verify-email/confirm", { _csrf: csrf(html), token: verificationToken });
assert.equal(response.status, 302);
assert.equal(response.headers.get("location"), "/success");

html = await page(verificationUrl);
response = await submit("/verify-email/confirm", { _csrf: csrf(html), token: verificationToken });
assert.equal(response.status, 400, "verification links are single-use");
assert.match(await page("/success"), /Success!/);

html = await page("/change-password");
response = await submit("/change-password", { _csrf: csrf(html), currentPassword: firstPassword, password: secondPassword, confirmPassword: secondPassword });
assert.equal(response.status, 302);

html = await page("/success");
response = await submit("/logout", { _csrf: csrf(html) });
assert.equal(response.status, 302);

html = await page("/login");
response = await submit("/login", { _csrf: csrf(html), email, password: secondPassword });
assert.equal(response.status, 302);

html = await page("/forgot-password");
response = await submit("/forgot-password", { _csrf: csrf(html), email });
assert.equal(response.status, 200);
assert.match(await response.text(), /reset link has been sent/);
const resetUrl = await deliveredLink("/reset-password");

html = await page(resetUrl);
response = await submit("/reset-password", { _csrf: csrf(html), token: new URL(resetUrl).searchParams.get("token"), password: finalPassword, confirmPassword: finalPassword });
assert.equal(response.status, 302);

html = await page("/login");
response = await submit("/login", { _csrf: csrf(html), email, password: finalPassword });
assert.equal(response.status, 302);
assert.match(await page("/success"), /Success!/);

await new Promise((resolve) => emailApi.close(resolve));
console.log(JSON.stringify({ status: "ok", flow: "domain-rejection/signup/verify-once/change-password/logout/login/forgot/reset/login" }));
