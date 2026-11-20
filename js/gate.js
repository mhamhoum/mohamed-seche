'use strict';
/* Page de connexion : déchiffre app.enc dans le navigateur (Web Crypto), puis lance l'application. */
(() => {
  const ITER = 600000; // doit rester identique à build.mjs
  const enc = new TextEncoder();
  const SKEY = 'seche-session-key';
  const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const toB64 = u => btoa(String.fromCharCode(...u));

  async function fetchBlob() {
    const r = await fetch('app.enc', { cache: 'no-cache' });
    if (!r.ok) throw new Error('fetch');
    return fromB64((await r.text()).trim());
  }
  async function bitsFromPassword(pw, salt) {
    const base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base, 256));
  }
  async function decryptWith(raw, bits) {
    const key = await crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(16, 28) }, key, raw.slice(28));
    return JSON.parse(new TextDecoder().decode(pt));
  }
  function launch(p) {
    document.body.innerHTML = p.html;
    const s = document.createElement('script');
    s.src = URL.createObjectURL(new Blob([p.js], { type: 'text/javascript' }));
    document.body.appendChild(s);
  }

  const form = document.getElementById('gate'), pwInput = document.getElementById('pw'), err = document.getElementById('err'), btn = form.querySelector('button');
  let raw;

  async function init() {
    try { raw = await fetchBlob(); } catch { err.textContent = 'Impossible de charger le site. Réessaie plus tard.'; return; }
    const saved = sessionStorage.getItem(SKEY);
    if (saved) {
      try { return launch(await decryptWith(raw, fromB64(saved))); } catch { sessionStorage.removeItem(SKEY); }
    }
    pwInput.focus();
  }

  form.addEventListener('submit', async e => {
    e.preventDefault();
    if (!raw) return;
    err.textContent = ''; btn.disabled = true; btn.textContent = 'Vérification…';
    try {
      const bits = await bitsFromPassword(pwInput.value, raw.slice(0, 16));
      const payload = await decryptWith(raw, bits);
      sessionStorage.setItem(SKEY, toB64(bits)); // valable pour cet onglet seulement
      launch(payload);
    } catch {
      err.textContent = 'Mot de passe incorrect.';
      pwInput.value = ''; pwInput.focus();
      btn.disabled = false; btn.textContent = 'Déverrouiller';
    }
  });
  init();
})();
