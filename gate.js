// The app itself exists only as ciphertext in app.enc. This page holds nothing worth reading: a
// wrong password cannot reveal the app, because the key comes from the password.
(async () => {
  const STORE = 'keys', RECORD = 'app';
  const form = document.getElementById('gate');
  const pw = document.getElementById('pw');
  const msg = document.getElementById('msg');
  const button = document.getElementById('open');
  const unbase64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  function db() {
    return new Promise((resolve, reject) => {
      const r = indexedDB.open('akaji-gate', 1);
      r.onupgradeneeded = () => r.result.createObjectStore(STORE);
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
  }

  async function keyStore(mode, action) {
    const d = await db();
    return new Promise((resolve, reject) => {
      const r = action(d.transaction(STORE, mode).objectStore(STORE));
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error);
    });
  }

  // Non-extractable, so a remembered key can decrypt here but can't be copied out as bytes.
  const rememberedKey = () => keyStore('readonly', (s) => s.get(RECORD)).catch(() => null);
  const rememberKey = (key) => keyStore('readwrite', (s) => s.put(key, RECORD)).catch(() => {});
  const forgetKey = () => keyStore('readwrite', (s) => s.delete(RECORD)).catch(() => {});

  async function deriveKey(password, sealed) {
    const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt: unbase64(sealed.salt), iterations: sealed.iterations },
      material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  }

  async function decrypt(key, sealed) {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unbase64(sealed.iv) }, key, unbase64(sealed.data));
    return new TextDecoder().decode(plain);
  }

  function launch(html) {
    document.open();
    document.write(html);
    document.close();
  }

  let sealed;
  try {
    sealed = await (await fetch('app.enc', { cache: 'no-cache' })).json();
  } catch {
    form.hidden = false;
    msg.textContent = '読み込めませんでした。通信を確認して再読み込みしてください。';
    button.disabled = true;
    return;
  }

  const saved = await rememberedKey();
  if (saved) {
    try {
      launch(await decrypt(saved, sealed));
      return;
    } catch {
      await forgetKey();
    }
  }

  form.hidden = false;
  pw.focus();
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    msg.textContent = '';
    button.disabled = true;
    button.textContent = '確認中…';
    try {
      const key = await deriveKey(pw.value, sealed);
      const html = await decrypt(key, sealed);
      if (document.getElementById('remember').checked) await rememberKey(key);
      launch(html);
    } catch {
      msg.textContent = 'パスワードが違います';
      button.disabled = false;
      button.textContent = '開く';
      pw.select();
    }
  });
})();
