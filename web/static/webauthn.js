// WebAuthn client. Uses the browser's native JSON helpers when available and
// falls back to manual base64url conversion otherwise.
(function () {
  "use strict";

  function b64uToBuf(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }
  function bufToB64u(buf) {
    const bytes = new Uint8Array(buf);
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function parseCreation(pk) {
    if (window.PublicKeyCredential && PublicKeyCredential.parseCreationOptionsFromJSON) {
      return PublicKeyCredential.parseCreationOptionsFromJSON(pk);
    }
    pk.challenge = b64uToBuf(pk.challenge);
    pk.user.id = b64uToBuf(pk.user.id);
    (pk.excludeCredentials || []).forEach((c) => (c.id = b64uToBuf(c.id)));
    return pk;
  }
  function parseRequest(pk) {
    if (window.PublicKeyCredential && PublicKeyCredential.parseRequestOptionsFromJSON) {
      return PublicKeyCredential.parseRequestOptionsFromJSON(pk);
    }
    pk.challenge = b64uToBuf(pk.challenge);
    (pk.allowCredentials || []).forEach((c) => (c.id = b64uToBuf(c.id)));
    return pk;
  }
  function credToJSON(cred) {
    if (cred.toJSON) return cred.toJSON();
    const r = cred.response;
    const out = {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      response: { clientDataJSON: bufToB64u(r.clientDataJSON) },
    };
    if (r.attestationObject) {
      out.response.attestationObject = bufToB64u(r.attestationObject);
      if (r.getTransports) out.response.transports = r.getTransports();
    } else {
      out.response.authenticatorData = bufToB64u(r.authenticatorData);
      out.response.signature = bufToB64u(r.signature);
      if (r.userHandle) out.response.userHandle = bufToB64u(r.userHandle);
    }
    return out;
  }

  async function post(url, body) {
    const res = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || "Request failed (" + res.status + ")");
    return data;
  }

  function showError(el, err) {
    if (!el) return;
    el.textContent = err && err.name === "NotAllowedError" ? "Cancelled or timed out." : (err.message || String(err));
    el.hidden = false;
  }

  const supported = !!(window.PublicKeyCredential && navigator.credentials);

  const loginBtn = document.getElementById("passkey-login");
  if (loginBtn) {
    const errEl = document.getElementById("passkey-error");
    if (!supported) {
      loginBtn.disabled = true;
      showError(errEl, new Error("This browser does not support passkeys."));
    }
    loginBtn.addEventListener("click", async () => {
      errEl.hidden = true;
      loginBtn.disabled = true;
      try {
        const begin = await post("/api/webauthn/login/begin");
        const cred = await navigator.credentials.get({ publicKey: parseRequest(begin.options.publicKey) });
        const fin = await post("/api/webauthn/login/finish", { challenge: begin.challenge, credential: credToJSON(cred) });
        window.location.href = fin.redirect || "/";
      } catch (e) {
        showError(errEl, e);
        loginBtn.disabled = false;
      }
    });
  }

  const addForm = document.getElementById("passkey-add");
  if (addForm) {
    const errEl = document.getElementById("passkey-error");
    if (!supported) {
      addForm.querySelector("button").disabled = true;
      showError(errEl, new Error("This browser does not support passkeys."));
    }
    addForm.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      errEl.hidden = true;
      const btn = addForm.querySelector("button");
      btn.disabled = true;
      try {
        const name = document.getElementById("passkey-name").value;
        const begin = await post("/api/webauthn/register/begin");
        const cred = await navigator.credentials.create({ publicKey: parseCreation(begin.options.publicKey) });
        await post("/api/webauthn/register/finish", { challenge: begin.challenge, name: name, credential: credToJSON(cred) });
        window.location.reload();
      } catch (e) {
        showError(errEl, e);
        btn.disabled = false;
      }
    });
  }
})();
