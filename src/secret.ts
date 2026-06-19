/**
 * Encrypt/decrypt a secret under a user passphrase, self-describing wire format.
 * Uses PBKDF2 (600,000 iterations, SHA-256) to derive an AES-256-GCM key.
 *
 * Wire format: base64(salt[16] || iv[12] || ciphertext)
 *
 * This is the minimal "protect a secret with a passphrase" primitive — the whole
 * salt is carried in the payload, so a single passphrase is all that is needed to
 * round-trip. Lifted verbatim from the audited signet-app implementation.
 */

import { deriveAesKey, aesEncrypt, aesDecrypt, SALT_LENGTH, IV_LENGTH } from './aes.js'

export async function encryptSecret(plaintext: string, passphrase: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH))
  const key = await deriveAesKey(passphrase, salt)
  const { iv, ciphertext } = await aesEncrypt(plaintext, key)

  // Format: base64(salt || iv || ciphertext)
  const combined = new Uint8Array(SALT_LENGTH + IV_LENGTH + ciphertext.length)
  combined.set(salt)
  combined.set(iv, SALT_LENGTH)
  combined.set(ciphertext, SALT_LENGTH + IV_LENGTH)

  let binary = ''
  combined.forEach(b => { binary += String.fromCharCode(b) })
  return btoa(binary)
}

export async function decryptSecret(encrypted: string, passphrase: string): Promise<string> {
  const combined = Uint8Array.from(atob(encrypted), (c) => c.charCodeAt(0))
  if (combined.length < SALT_LENGTH + IV_LENGTH + 16) {
    throw new Error('Encrypted payload too short')
  }

  const salt = combined.slice(0, SALT_LENGTH)
  const iv = combined.slice(SALT_LENGTH, SALT_LENGTH + IV_LENGTH)
  const ciphertext = combined.slice(SALT_LENGTH + IV_LENGTH)

  const key = await deriveAesKey(passphrase, salt)
  return aesDecrypt(iv, ciphertext, key)
}

/**
 * Check if a string looks like an encrypted value produced by `encryptSecret`.
 * Must be valid base64 and decode to at least salt + iv + 16 bytes (minimum AES-GCM ciphertext).
 */
export function isEncrypted(value: string): boolean {
  try {
    const decoded = atob(value)
    return decoded.length >= SALT_LENGTH + IV_LENGTH + 16
  } catch {
    return false
  }
}
