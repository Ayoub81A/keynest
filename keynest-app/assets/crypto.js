// ============================================================
// KeyNest — Crypto Module
// AES-256-GCM encryption with PBKDF2 key derivation.
// The encryption key is derived from the user's password and
// a server-provided salt. It never leaves the browser.
// ============================================================

const Crypto = (() => {

  // Derive a 256-bit AES key from password + salt using PBKDF2
  // salt: hex string from server (stored in DB, unique per user)
  async function deriveKey(password, saltHex) {
    const enc = new TextEncoder();
    const saltBytes = hexToBytes(saltHex);

    const baseKey = await crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: 310000,   // NIST recommended minimum for SHA-256
        hash: 'SHA-256',
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,                  // not exportable — key stays in memory only
      ['encrypt', 'decrypt']
    );
  }

  // Encrypt a plain JS object → base64 string
  // Format: base64( iv[12] + ciphertext + authTag[16] )
  async function encrypt(key, plainObject) {
    const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV
    const enc = new TextEncoder();
    const plaintext = enc.encode(JSON.stringify(plainObject));

    const cipherBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      plaintext
    );

    // Prepend IV to ciphertext so we can extract it on decrypt
    const combined = new Uint8Array(iv.byteLength + cipherBuffer.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(cipherBuffer), iv.byteLength);

    return bytesToBase64(combined);
  }

  // Decrypt a base64 string → plain JS object
  async function decrypt(key, ciphertextBase64) {
    const combined = base64ToBytes(ciphertextBase64);
    const iv         = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

    const plainBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    );

    const dec = new TextDecoder();
    return JSON.parse(dec.decode(plainBuffer));
  }

  // ── UTILS ──────────────────────────────────────────────────

  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }
    return bytes;
  }

  function bytesToBase64(bytes) {
    let binary = '';
    bytes.forEach(b => binary += String.fromCharCode(b));
    return btoa(binary);
  }

  function base64ToBytes(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  return { deriveKey, encrypt, decrypt };

})();
