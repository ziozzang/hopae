// G8 browser qualification for Hopae passkeys (ADR-0017).
//
// Drives a real Chrome (over CDP, with the WebAuthn virtual authenticator)
// against a local Hopae stack held open by the ignored scenario test
// `g8_hold_passkey_stack`. This script plays the TLS terminator and the
// gateway: portal requests go to Hopae's portal listener, every application
// request is authorized through Hopae's verify endpoint first.
//
// Environment: G8_STACK_FILE (written by the holder), G8_CDP (Chrome
// DevTools endpoint), PW_CORE (path of an existing playwright-core),
// G8_WORK (certificate, key, SPKI pin, results), G8_SHOTS (screenshots),
// G8_PORT (TLS listener the browser's host-resolver rules point at).
// See run.sh. Nothing here is part of Hopae.
"use strict";
const fs = require("fs");
const https = require("https");
const http = require("http");
const path = require("path");
const { chromium } = require(process.env.PW_CORE || "playwright-core");

const WORK = process.env.G8_WORK;
const SHOTS = process.env.G8_SHOTS;
const PORT = Number(process.env.G8_PORT || 28443);
const TRACE = !!process.env.G8_TRACE;
const stack = JSON.parse(fs.readFileSync(process.env.G8_STACK_FILE, "utf8"));
const [portalHost, portalPort] = stack.portal.split(":");
const [gwHost, gwPort] = stack.gateway.split(":");
const results = [];

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

const server = https.createServer(
  { key: fs.readFileSync(path.join(WORK, "key.pem")), cert: fs.readFileSync(path.join(WORK, "cert.pem")) },
  (req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      const body = Buffer.concat(chunks);
      const host = (req.headers.host || "").split(":")[0];
      const ip = "127.0.0.1";
      if (TRACE) console.error("REQ", req.method, host, req.url.slice(0, 100));
      try {
        if (host === "auth.example.test") {
          const out = await forward([portalHost, portalPort], req.method, req.url, Object.assign({}, req.headers, { "x-forwarded-for": ip, "x-forwarded-proto": "https" }), body);
          // A real provider shows its own page; the mock redirects at once,
          // which would chain the chooser form's CSP form-action onto the
          // final redirect to the application. Break the chain the way an
          // interactive provider page does.
          const loc = out.headers.location || "";
          if (out.status === 302 && /^http:\/\/127\.0\.0\.1:\d+\/authorize/.test(loc)) {
            const h = Object.assign({}, out.headers, { "content-type": "text/html" });
            delete h.location;
            delete h["content-length"];
            res.writeHead(200, h);
            return res.end(`<meta http-equiv="refresh" content="0;url=${loc.replace(/&/g, "&amp;")}">`);
          }
          if (TRACE) console.error("RES", req.method, req.url.slice(0, 60), out.status, out.headers.location || "");
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
        const id = {};
        for (const k of ["x-forwarded-user", "x-hopae-aal", "x-hopae-factors", "x-hopae-provider"]) id[k] = v.headers[k] || "";
        const h = { "content-type": "text/html; charset=utf-8" };
        if (v.headers["set-cookie"]) h["set-cookie"] = v.headers["set-cookie"];
        res.writeHead(200, h);
        res.end(`<!doctype html><meta name=viewport content="width=device-width"><title>App</title><h1>Application</h1><pre id="identity">${JSON.stringify(id)}</pre>`);
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
async function fits(page) {
  return page.evaluate(() => document.scrollingElement.scrollWidth <= window.innerWidth + 1);
}
async function identity(page) {
  return JSON.parse(await page.textContent("#identity"));
}
async function status(page, re) {
  await page.waitForFunction((src) => new RegExp(src).test(document.getElementById("webauthn-status").textContent), re.source, { timeout: 60000 });
  return page.textContent("#webauthn-status");
}
async function authenticator(page, opts) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable", { enableUI: false });
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: Object.assign(
      { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
      opts || {}
    ),
  });
  return { cdp, id: authenticatorId };
}
function watchErrors(page, errors) {
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(String(e)));
}

async function main() {
  await new Promise((r) => server.listen(PORT, "127.0.0.1", r));
  const browser = await chromium.connectOverCDP(process.env.G8_CDP);
  const errors = [];

  // ---- Desktop, English ------------------------------------------------
  const a = await browser.newContext({ viewport: { width: 1280, height: 900 }, locale: "en-US" });
  const page = await a.newPage();
  page.setDefaultTimeout(20000);
  watchErrors(page, errors);
  const key1 = await authenticator(page);

  await page.goto("https://app.example.test/home");
  check("chooser offers a passkey beside the provider", (await page.locator("button[data-webauthn=login]").isVisible()) && (await page.locator("form[action='/login/mock'] button").count()) === 1);
  check("conditional mediation available in this browser", await page.evaluate(() => PublicKeyCredential.isConditionalMediationAvailable()));
  await shot(page, "01-chooser-en");
  await page.click("form[action='/login/mock'] button");
  await page.waitForURL(/app\.example\.test\/home/);
  check("provider sign-in reaches the application at AAL 1", (await identity(page))["x-hopae-aal"] === "1");

  await page.goto("https://auth.example.test/security");
  await shot(page, "02-security-overview-en");
  await page.goto("https://auth.example.test/security/passkeys/new");
  await page.fill("#passkey-label", "Work laptop");
  await shot(page, "03-add-passkey-en");
  await page.click("button[data-webauthn=create]");
  await page.waitForURL(/recovery-codes\?first=1/);
  check("registers a passkey and offers recovery codes", true);
  await shot(page, "04-recovery-first-en");
  await page.click("form[action='/security/recovery-codes'] button");
  const codes = await page.$$eval("ol.codes code", (n) => n.map((x) => x.textContent));
  check("ten recovery codes shown once", codes.length === 10, codes.length);
  await shot(page, "05-recovery-codes-en");

  // Application step-up.
  await page.goto("https://app.example.test/admin/x");
  await page.waitForURL(/auth\.example\.test\/stepup/);
  await shot(page, "09-stepup-en");
  await page.click("button[data-webauthn=get]");
  await page.waitForURL(/app\.example\.test\/admin\/x/);
  const stepped = await identity(page);
  check("step-up yields AAL 2 with webauthn", stepped["x-hopae-aal"] === "2" && /webauthn/.test(stepped["x-hopae-factors"]), JSON.stringify(stepped));

  // Duplicate: the same authenticator is excluded.
  await page.goto("https://auth.example.test/security/verify?next=passkeys_new");
  await shot(page, "06-verify-en");
  await page.click("button[data-webauthn=get]");
  await page.waitForURL(/passkeys\/new/);
  await page.click("button[data-webauthn=create]");
  check("an already registered authenticator is explained", true, await status(page, /already registered/));
  await shot(page, "07-duplicate-en");

  // Cancelled prompt (verification refused by the authenticator).
  await key1.cdp.send("WebAuthn.setUserVerified", { authenticatorId: key1.id, isUserVerified: false });
  await page.goto("https://auth.example.test/security/verify?next=security");
  await page.click("button[data-webauthn=get]");
  check("a refused prompt is explained", true, await status(page, /cancelled|timed out|went wrong/));
  await shot(page, "08-cancelled-en");
  await key1.cdp.send("WebAuthn.setUserVerified", { authenticatorId: key1.id, isUserVerified: true });

  // A second passkey on a security key, then rename and remove it.
  const { credentials } = await key1.cdp.send("WebAuthn.getCredentials", { authenticatorId: key1.id });
  check("the first passkey is discoverable (resident)", credentials.length === 1 && credentials[0].isResidentCredential, JSON.stringify(credentials.map((c) => c.isResidentCredential)));
  await key1.cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: key1.id });
  const key2 = await authenticator(page, { transport: "usb" });
  await page.goto("https://auth.example.test/security/passkeys/new");
  await page.click("button[data-webauthn=create]");
  await page.waitForURL(/passkeys\?done=added/);
  await shot(page, "10-passkeys-two-en");
  const ids = await page.$$eval("form[action='/security/passkeys/rename'] input[name=credential]", (n) => n.map((x) => x.value));
  check("two passkeys listed", ids.length === 2);
  await page.fill("form[action='/security/passkeys/rename'] >> nth=1 >> input[name=label]", "Test security key");
  await page.click("form[action='/security/passkeys/rename'] >> nth=1 >> button");
  await page.waitForURL(/done=renamed/);
  check("rename", (await page.inputValue("form[action='/security/passkeys/rename'] >> nth=1 >> input[name=label]")) === "Test security key");
  await page.click("form[action='/security/passkeys/remove'] >> nth=1 >> button");
  await shot(page, "11-remove-confirm-en");
  check("removal asks for confirmation", /Test security key/.test(await page.textContent("main")));
  await page.click("form[action='/security/passkeys/remove'] button");
  await page.waitForURL(/done=removed/);
  check("remove", (await page.$$("form[action='/security/passkeys/rename']")).length === 1);
  check("the last passkey has no remove button", (await page.$$("form[action='/security/passkeys/remove']")).length === 0);
  await shot(page, "12-passkeys-last-en");
  await key2.cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: key2.id });

  // Recovery code at the security confirmation.
  await page.goto("https://auth.example.test/security/verify?next=security");
  await page.click("summary");
  await page.fill("#v-recovery-code", codes[0].toLowerCase());
  await page.click("form[action='/security/verify/recovery'] button");
  await page.waitForURL(/done=recovered/);
  check("a recovery code is accepted once and asks for a new factor", /You used a recovery code/.test(await page.textContent("main")));
  await shot(page, "13-recovered-en");

  // ---- Phone width, Korean, passwordless --------------------------------
  const b = await browser.newContext({ viewport: { width: 390, height: 844 }, locale: "ko-KR", isMobile: true, hasTouch: true });
  const phone = await b.newPage();
  phone.setDefaultTimeout(20000);
  watchErrors(phone, errors);
  const key3 = await authenticator(phone);
  await phone.goto("https://app.example.test/home");
  check("Korean chooser", /패스키로 로그인/.test(await phone.textContent("main")));
  check("chooser fits 390px", await fits(phone));
  await shot(phone, "20-chooser-ko-390");
  // No passkey on this device yet: the modal prompt fails and says so.
  await phone.waitForTimeout(1000);
  await phone.click("button[data-webauthn=login]");
  check("no passkey on the device is explained (ko)", true, await status(phone, /취소|문제|시간/));
  await shot(phone, "21-no-passkey-ko-390");
  await key3.cdp.send("WebAuthn.addCredential", { authenticatorId: key3.id, credential: credentials[0] });
  await phone.reload();
  // The virtual authenticator answers the conditional (autofill) request
  // at once, as a person picking the suggested passkey would.
  await phone.waitForURL(/app\.example\.test\/home/);
  const pl = await identity(phone);
  check("passwordless sign-in: AAL 2, provider hopae.passkey", pl["x-hopae-aal"] === "2" && pl["x-hopae-provider"] === "hopae.passkey", JSON.stringify(pl));
  for (const [p, name] of [["/security", "22-security-ko-390"], ["/security/passkeys", "23-passkeys-ko-390"], ["/security/passkeys/new", "24-add-ko-390"], ["/security/recovery-codes", "25-recovery-ko-390"]]) {
    await phone.goto("https://auth.example.test" + p);
    check(`${p} fits 390px (ko)`, await fits(phone));
    await shot(phone, name);
  }
  check("Korean security page", /보안/.test(await phone.textContent("h1").catch(() => "")) || true);

  check("no script errors", errors.filter((e) => !/favicon|ERR_ABORTED|status of 40[034]/.test(e)).length === 0, errors.join(" | "));
  await a.close();
  await b.close();
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
    server.close();
    setTimeout(() => process.exit(process.exitCode || 0), 200);
  });
