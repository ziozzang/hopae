// Hopae portal WebAuthn ceremonies (ADR-0017 decision 3).
//
// The only script the portal serves. It never fetches: the server renders the
// ceremony options into a data attribute, this script runs the browser
// ceremony on a button press, writes the JSON result into a hidden field and
// submits the ordinary CSRF-protected form, which the server verifies.
// Text only: no HTML sinks, no dynamic code, no inline handlers (CSP and
// Trusted Types enforce it).
(function () {
  "use strict";

  function b64urlToBytes(s) {
    var pad = s.length % 4 === 0 ? "" : "====".slice(s.length % 4);
    var bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function bytesToB64url(buf) {
    var bytes = new Uint8Array(buf);
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function descriptors(list) {
    return (list || []).map(function (d) {
      var out = { type: d.type, id: b64urlToBytes(d.id) };
      if (d.transports) out.transports = d.transports;
      return out;
    });
  }

  function creationOptions(json) {
    var pk = JSON.parse(json).publicKey;
    pk.challenge = b64urlToBytes(pk.challenge);
    pk.user.id = b64urlToBytes(pk.user.id);
    pk.excludeCredentials = descriptors(pk.excludeCredentials);
    return { publicKey: pk };
  }

  function requestOptions(json) {
    var pk = JSON.parse(json).publicKey;
    pk.challenge = b64urlToBytes(pk.challenge);
    pk.allowCredentials = descriptors(pk.allowCredentials);
    return { publicKey: pk };
  }

  var TRANSPORTS = ["usb", "nfc", "ble", "internal", "hybrid"];

  function encodeCreation(cred) {
    var r = cred.response;
    var transports = typeof r.getTransports === "function" ? r.getTransports() : [];
    var ext = typeof cred.getClientExtensionResults === "function" ? cred.getClientExtensionResults() : {};
    var outExt = {};
    if (ext && ext.credProps) outExt.credProps = { rk: !!ext.credProps.rk };
    return {
      id: cred.id,
      rawId: bytesToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bytesToB64url(r.clientDataJSON),
        attestationObject: bytesToB64url(r.attestationObject),
        transports: transports.filter(function (t) { return TRANSPORTS.indexOf(t) >= 0; })
      },
      clientExtensionResults: outExt
    };
  }

  function encodeAssertion(cred) {
    var r = cred.response;
    return {
      id: cred.id,
      rawId: bytesToB64url(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bytesToB64url(r.clientDataJSON),
        authenticatorData: bytesToB64url(r.authenticatorData),
        signature: bytesToB64url(r.signature),
        userHandle: r.userHandle ? bytesToB64url(r.userHandle) : null
      },
      clientExtensionResults: {}
    };
  }

  function say(status, key) {
    if (!status) return;
    status.textContent = status.getAttribute("data-msg-" + key) || "";
    status.hidden = false;
  }

  function messageFor(err) {
    switch (err && err.name) {
      case "NotAllowedError":
      case "AbortError":
        return "cancelled";
      case "InvalidStateError":
        return "duplicate";
      case "SecurityError":
        return "security";
      case "NotSupportedError":
        return "unsupported";
      default:
        return "failed";
    }
  }

  function bind(button) {
    var form = button.form;
    var status = document.getElementById(button.getAttribute("data-status"));
    var field = form && form.querySelector("input[name=credential]");
    var mode = button.getAttribute("data-webauthn");
    var options = button.getAttribute("data-options");
    if (!form || !field || !options) return;
    if (!window.PublicKeyCredential || !navigator.credentials) {
      button.disabled = true;
      say(status, "unsupported");
      return;
    }
    button.hidden = false;
    button.disabled = false;
    var busy = false;
    button.addEventListener("click", function (event) {
      event.preventDefault();
      if (busy) return;
      busy = true;
      button.disabled = true;
      say(status, "waiting");
      var started;
      try {
        started = mode === "create"
          ? navigator.credentials.create(creationOptions(options)).then(encodeCreation)
          : navigator.credentials.get(requestOptions(options)).then(encodeAssertion);
      } catch (e) {
        started = Promise.reject(e);
      }
      started.then(function (json) {
        field.value = JSON.stringify(json);
        say(status, "verifying");
        form.submit();
      }, function (err) {
        busy = false;
        button.disabled = false;
        say(status, messageFor(err));
      });
    });
  }

  function start() {
    var buttons = document.querySelectorAll("button[data-webauthn]");
    for (var i = 0; i < buttons.length; i++) bind(buttons[i]);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
