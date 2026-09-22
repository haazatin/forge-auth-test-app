import assert from "node:assert/strict";

const baseUrl = process.env.TEST_BASE_URL ?? "http://127.0.0.1:8080";
let cookie = "";

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

const email = `smoke-${Date.now()}@example.test`;
const firstPassword = "first-password-123";
const secondPassword = "second-password-456";
const finalPassword = "final-password-789";

let html = await page("/signup");
let response = await submit("/signup", { _csrf: csrf(html), email, password: firstPassword, confirmPassword: firstPassword });
assert.equal(response.status, 302);
assert.equal(response.headers.get("location"), "/success");
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
html = await response.text();
const resetMatch = html.match(/href="([^"]+\/reset-password\?token=[^"]+)"/);
assert.ok(resetMatch, "test reset URL is shown");

html = await page(resetMatch[1]);
response = await submit("/reset-password", { _csrf: csrf(html), token: new URL(resetMatch[1]).searchParams.get("token"), password: finalPassword, confirmPassword: finalPassword });
assert.equal(response.status, 302);

html = await page("/login");
response = await submit("/login", { _csrf: csrf(html), email, password: finalPassword });
assert.equal(response.status, 302);
assert.match(await page("/success"), /Success!/);

console.log(JSON.stringify({ status: "ok", flow: "signup/change-password/logout/login/forgot/reset/login" }));
