// Browser qualification of console operator assurance (Hopae ADR-0021).
//
// A real Chrome (CDP, WebAuthn virtual authenticator) against Hopae (held by
// `g8_hold_operator_stack`) and the real Hangang authority and console. This
// script plays the TLS terminator and the gateway: portal requests go to
// Hopae's portal, every request for app.example.test and console.example.test
// is authorized through Hopae's verify endpoint first; allowed console
// requests are proxied to hangang-console, which signs the operator in over
// Hopae's native protocol and checks the signed operator assertion.
// Environment: see run-operator.sh. Nothing here is part of Hopae.
"use strict";
const fs = require("fs");
const https = require("https");
const http = require("http");
const path = require("path");
const crypto = require("crypto");
const { spawn } = require("child_process");
const { chromium } = require(process.env.PW_CORE || "playwright-core");

const WORK = process.env.G8_WORK;
const SHOTS = process.env.G8_SHOTS;
const PORT = Number(process.env.G8_PORT || 28444);
const BIN = process.env.HANGANG_BIN_DIR;
const stack = JSON.parse(fs.readFileSync(process.env.G8_STACK_FILE, "utf8"));
const [portalHost, portalPort] = stack.portal.split(":");
const [gwHost, gwPort] = stack.gateway.split(":");
const results = [];
const children = [];
let consolePort = 0;

function check(name, ok, detail) {
  results.push({ name, ok: !!ok, detail: detail ? String(detail).slice(0, 300) : "" });
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${detail ? " — " + String(detail).slice(0, 200) : ""}`);
}
function forward(target, method, url, headers, body) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: target[0], port: Number(target[1]), method, path: url, headers }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    r.on("error", reject);
    r.end(body);
  });
}
function freePort() {
  return new Promise((resolve) => {
    const s = require("net").createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
}
async function waitReady(url) {
  for (let i = 0; i < 200; i++) {
    try {
      const r = await forward(["127.0.0.1", new URL(url).port], "GET", "/ui/", {}, Buffer.alloc(0));
      if (r.status === 200) return;
    } catch (_) {}
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("not ready: " + url);
}

const server = https.createServer(
  { key: fs.readFileSync(path.join(WORK, "key.pem")), cert: fs.readFileSync(path.join(WORK, "cert.pem")) },
  (req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      const body = Buffer.concat(chunks);
      const host = (req.headers.host || "").split(":")[0];
      const ip = "127.0.0.1";
      try {
        if (host === "auth.example.test") {
          const out = await forward([portalHost, portalPort], req.method, req.url, Object.assign({}, req.headers, { "x-forwarded-for": ip, "x-forwarded-proto": "https" }), body);
          const loc = out.headers.location || "";
          if (out.status === 302 && /^http:\/\/127\.0\.0\.1:\d+\/authorize/.test(loc)) {
            const h = Object.assign({}, out.headers, { "content-type": "text/html" });
            delete h.location;
            delete h["content-length"];
            res.writeHead(200, h);
            return res.end(`<meta http-equiv="refresh" content="0;url=${loc.replace(/&/g, "&amp;")}">`);
          }
          res.writeHead(out.status, out.headers);
          return res.end(out.body);
        }
        const vh = {
          host: stack.gateway,
          "x-original-url": `https://${host}${req.url}`,
          "x-forwarded-host": host,
          "x-forwarded-proto": "https",
          "x-forwarded-for": ip,
          "x-real-ip": ip,
          "x-original-method": req.method,
          "x-hopae-gateway-key": stack.gateway_key,
        };
        for (const k of ["cookie", "user-agent", "accept", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "accept-language"]) {
          if (req.headers[k]) vh[k] = req.headers[k];
        }
        const v = await forward([gwHost, gwPort], "GET", "/_hopae/verify", vh, Buffer.alloc(0));
        if (v.status !== 200) {
          const h = {};
          for (const k of ["location", "set-cookie", "content-type", "retry-after", "cache-control"]) if (v.headers[k]) h[k] = v.headers[k];
          res.writeHead(v.status, h);
          return res.end(v.body);
        }
        if (host === "console.example.test" && consolePort) {
          const fh = {};
          for (const k of ["cookie", "content-type", "origin", "x-hangang-sso", "authorization", "accept", "user-agent", "sec-fetch-site", "if-match"]) {
            if (req.headers[k]) fh[k] = req.headers[k];
          }
          const out = await forward(["127.0.0.1", consolePort], req.method, req.url, fh, body);
          const h = Object.assign({}, out.headers);
          if (v.headers["set-cookie"]) h["set-cookie"] = [].concat(v.headers["set-cookie"], h["set-cookie"] || []);
          res.writeHead(out.status, h);
          return res.end(out.body);
        }
        const id = {};
        for (const k of ["x-forwarded-user", "x-hopae-aal", "x-hopae-factors"]) id[k] = v.headers[k] || "";
        const h = { "content-type": "text/html; charset=utf-8" };
        if (v.headers["set-cookie"]) h["set-cookie"] = v.headers["set-cookie"];
        res.writeHead(200, h);
        res.end(`<!doctype html><title>App</title><pre id="identity">${JSON.stringify(id)}</pre>`);
      } catch (e) {
        res.writeHead(502);
        res.end(String(e));
      }
    });
  }
);

async function shot(page, name) {
  if (SHOTS) await page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: true });
}
async function authenticator(page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable", { enableUI: false });
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  return { cdp, id: authenticatorId };
}

async function startHangang(userId) {
  const dir = fs.mkdtempSync(path.join(WORK, "hangang-"));
  fs.chmodSync(dir, 0o700);
  const system = crypto.randomBytes(32).toString("hex");
  const [pub, admin] = [await freePort(), await freePort()];
  consolePort = await freePort();
  const env = Object.assign({}, process.env, { HANGANG_ADMIN_TOKEN: system, OPERATOR_SSO_GATEWAY_KEY: stack.gateway_key, OPERATOR_SSO_SYSTEM: system });
  const log = fs.openSync(path.join(WORK, "hangang.log"), "a");
  const authority = spawn(path.join(BIN, "hangang"), ["--config", path.join(dir, "config.json"), "--listen", `127.0.0.1:${pub}`, "--admin", `127.0.0.1:${admin}`, "--threads", "2", "--lua-workers", "1"], { env, stdio: ["ignore", log, log] });
  children.push(authority);
  await waitReady(`http://127.0.0.1:${admin}`);
  const boot = await forward(["127.0.0.1", admin], "POST", "/v1/auth/bootstrap", { authorization: "Bearer " + system, "content-type": "application/json" }, Buffer.from(JSON.stringify({ username: "operator", password: "owned fixture secure password" })));
  if (boot.status !== 201) throw new Error("bootstrap " + boot.status);
  fs.writeFileSync(path.join(dir, "plugins.json"), JSON.stringify({ plugins: [] }), { mode: 0o600 });
  fs.writeFileSync(path.join(dir, "sso.json"), JSON.stringify({
    public_url: "https://console.example.test/",
    native_address: stack.native,
    gateway_key_env: "OPERATOR_SSO_GATEWAY_KEY",
    upstream_token_env: "OPERATOR_SSO_SYSTEM",
    cookie: stack.cookie,
    accounts: { [userId]: "operator" },
    operator_policy: { assertion_public_keys: { [stack.operator_key_id]: stack.operator_public_key }, minimum_aal: 2, require_factor: "webauthn", sensitive_max_age_seconds: 30 },
  }), { mode: 0o600 });
  const con = spawn(path.join(BIN, "hangang-console"), ["--listen", `127.0.0.1:${consolePort}`, "--upstream", `http://127.0.0.1:${admin}`, "--plugins", path.join(dir, "plugins.json"), "--hopae-sso", path.join(dir, "sso.json"), "--audit-log", path.join(WORK, "console-audit.jsonl")], { env, stdio: ["ignore", log, log] });
  children.push(con);
  await waitReady(`http://127.0.0.1:${consolePort}`);
}

async function exchangeAndPut(page) {
  return page.evaluate(async () => {
    const ex = await fetch("/v1/auth/sso/exchange", { method: "POST", headers: { "Content-Type": "application/json", "X-Hangang-SSO": "1" }, body: "{}" });
    const token = (await ex.json()).token;
    const put = await fetch("/v1/config", { method: "PUT", headers: { "Content-Type": "application/json", Authorization: "Bearer " + token }, body: "{}" });
    return { status: put.status, body: await put.json().catch(() => ({})) };
  });
}

async function stepUpWithPasskey(page, until) {
  await page.waitForURL(/auth\.example\.test\/stepup/);
  await page.click("button[data-webauthn=get]");
  await page.waitForURL(until);
}

async function main() {
  await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
  const browser = await chromium.connectOverCDP(process.env.G8_CDP);
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, locale: "en-US" });
  const page = await ctx.newPage();
  page.setDefaultTimeout(30000);
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  await authenticator(page);

  // Sign in at an ordinary application to learn the Hopae user id.
  await page.goto("https://app.example.test/home");
  if (await page.locator("form[action='/login/mock'] button").count()) await page.click("form[action='/login/mock'] button");
  await page.waitForURL(/app\.example\.test\/home/);
  const id = JSON.parse(await page.textContent("#identity"));
  check("provider sign-in at an ordinary application (AAL 1)", id["x-hopae-aal"] === "1" && id["x-forwarded-user"].startsWith("u_"), JSON.stringify(id));
  await startHangang(id["x-forwarded-user"]);

  // The console without a passkey: Hopae sends the operator to add one.
  await page.goto("https://console.example.test/ui/");
  await page.waitForURL(/auth\.example\.test\/stepup/);
  const missing = await page.textContent("main");
  check("console requires a passkey before the first grant", /Passkey required/.test(missing) && (await page.locator("a[href='/security/passkeys/new']").count()) === 1, missing);
  await shot(page, "op-01-passkey-required");
  await page.click("a[href='/security/passkeys/new']");
  await page.click("button[data-webauthn=create]");
  await page.waitForURL(/recovery-codes|passkeys\?done=added/);
  check("operator registers a passkey", true);

  // Back to the console: step up with the passkey, then the console signs in.
  await page.goto("https://console.example.test/ui/?sso=hopae");
  await shot(page, "op-02-stepup");
  await stepUpWithPasskey(page, /console\.example\.test\/ui\//);
  await page.waitForFunction(() => !document.getElementById("operator-assurance").hidden, null, { timeout: 30000 });
  const badge = await page.textContent("#operator-assurance");
  check("console header shows the operator's assurance", /AAL2/.test(badge) && /Passkey/.test(badge), badge);
  check("signed in as the mapped Hangang account", /operator/.test(await page.textContent("#signed-in-user")));
  await shot(page, "op-03-console-signed-in");

  // A sensitive change after the freshness window: re-authenticate.
  await page.waitForTimeout(31000);
  const stale = await exchangeAndPut(page);
  check("a sensitive change with a stale factor needs re-authentication", stale.status === 403 && stale.body.error === "operator_reauthentication_required", JSON.stringify(stale));
  await page.goto("https://console.example.test" + stale.body.step_up_url.split("?")[0] + "?return=%2Fui%2F%23status");
  await stepUpWithPasskey(page, /console\.example\.test\/ui\/\?sso=hopae/);
  await page.waitForFunction(() => !document.getElementById("operator-assurance").hidden, null, { timeout: 30000 });
  const fresh = await exchangeAndPut(page);
  check("after the step-up the sensitive change passes the console gate", !["operator_reauthentication_required", "operator_step_up_required"].includes(fresh.body.error), JSON.stringify(fresh));
  await shot(page, "op-04-after-reauthentication");

  const audit = fs.readFileSync(path.join(WORK, "console-audit.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  check("console audit records the SSO sign-in with the passkey", audit.some((r) => r.event === "console.sso_login" && r.outcome === "success" && r.assurance && r.assurance.factor === "webauthn"));
  check("console audit records the re-authentication refusal", audit.some((r) => r.event === "console.step_up_required" && r.reason === "operator_reauthentication_required"));
  check("no script errors", errors.length === 0, errors.join(" | "));
  await ctx.close();
}

main()
  .catch((e) => {
    console.error("FAIL driver:", e && e.stack ? e.stack : e);
    results.push({ name: "driver", ok: false, detail: String(e).slice(0, 300) });
    process.exitCode = 2;
  })
  .finally(() => {
    fs.writeFileSync(path.join(WORK, "results.json"), JSON.stringify(results, null, 1));
    if (results.some((r) => !r.ok) && !process.exitCode) process.exitCode = 1;
    for (const c of children.reverse()) c.kill("SIGTERM");
    server.close();
    setTimeout(() => process.exit(process.exitCode || 0), 500);
  });
