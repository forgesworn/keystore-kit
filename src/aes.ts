/**
 * Low-level AES-256-GCM helpers over Web Crypto. Uses PBKDF2 (600,000
 * iterations, SHA-256) for passphrase key derivation — OWASP 2023 recommendation
 * for PBKDF2-SHA-256.
 *
 * Wire formats are handled by the callers — this module exposes raw byte
 * operations only, so each consumer can compose its own layout.
 *
 * Lifted verbatim from the audited signet-app implementation (last reviewed
 * 2026-03-16). Pure: depends only on the platform `crypto.subtle`.
 */

/** PBKDF2 iteration count (OWASP 2023 recommendation for PBKDF2-SHA-256). */
export const PBKDF2_ITERATIONS = 600_000

/** Random salt length in bytes for PBKDF2 key derivation. */
export const SALT_LENGTH = 16

/** AES-GCM initialisation vector length in bytes. */
export const IV_LENGTH = 12

/**
 * Derive an AES-256-GCM CryptoKey from a passphrase and salt using PBKDF2.
 *
 * @param passphrase - The passphrase string (e.g. a PIN or credential ID).
 * @param salt       - A random salt; must be `SALT_LENGTH` bytes for new keys.
 * @returns A non-extractable AES-256-GCM key usable for encrypt and decrypt.
 */
export async function deriveAesKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  // SubtleCrypto requires a plain ArrayBuffer — slice to ensure no view offset.
  const saltBuf = new Uint8Array(salt.buffer.slice(salt.byteOffset, salt.byteOffset + salt.byteLength))
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  )
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBuf, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' } as Pbkdf2Params,
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

/**
 * Encrypt a UTF-8 plaintext string using AES-256-GCM with a random IV.
 *
 * @param plaintext - The string to encrypt.
 * @param key       - A CryptoKey with `encrypt` usage (AES-GCM, 256-bit).
 * @returns The random IV and the resulting ciphertext as separate byte arrays.
 *          The caller is responsible for serialising these into a wire format.
 */
export async function aesEncrypt(
  plaintext: string,
  key: CryptoKey,
): Promise<{ iv: Uint8Array; ciphertext: Uint8Array }> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH))
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext)),
  )
  return { iv, ciphertext }
}

/**
 * Decrypt AES-256-GCM ciphertext back to a UTF-8 string.
 *
 * @param iv         - The IV that was used during encryption (`IV_LENGTH` bytes).
 * @param ciphertext - The encrypted bytes (includes AES-GCM authentication tag).
 * @param key        - A CryptoKey with `decrypt` usage (AES-GCM, 256-bit).
 * @returns The decrypted plaintext string.
 * @throws  If the key is wrong or the ciphertext has been tampered with.
 */
export async function aesDecrypt(
  iv: Uint8Array,
  ciphertext: Uint8Array,
  key: CryptoKey,
): Promise<string> {
  // Copy into fresh Uint8Arrays backed by plain ArrayBuffers — SubtleCrypto
  // requires ArrayBufferView<ArrayBuffer>, not ArrayBufferView<ArrayBufferLike>.
  const ivBuf = Uint8Array.from(iv)
  const ctBuf = Uint8Array.from(ciphertext)
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBuf }, key, ctBuf)
  return new TextDecoder().decode(plaintext)
}
