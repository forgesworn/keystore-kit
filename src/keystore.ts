/**
 * Keystore — protect one opaque secret behind a PIN, WebAuthn-PRF biometric, or
 * a short-lived in-memory grace key, with a "burn it all" wipe.
 *
 * The secret is an opaque string: a random hex key, an `nsec`, a Curve25519/Ed25519
 * secret, anything. The keystore never interprets it — it is *curve-agnostic*.
 *
 * Generalised from the audited signet-app `auth.ts`: its three couplings —
 * `localStorage`, the IndexedDB grace store, and the hardcoded RP-id / PRF salt /
 * app name — are replaced by the injected {@link KeystoreStorage},
 * {@link WebAuthnProvider}, and {@link KeystoreConfig}. The crypto is unchanged.
 */

import { deriveAesKey, aesEncrypt, aesDecrypt, IV_LENGTH } from './aes.js'
import type {
  KeystoreStorage,
  KeystoreConfig,
  WebAuthnProvider,
  UnlockMethod,
  SetupBiometricResult,
} from './types.js'

const DEFAULT_NAMESPACE = 'keystore'
const DEFAULT_HKDF_INFO = 'keystore-kit-encryption-key'

export class Keystore {
  private readonly ns: string
  private readonly hkdfInfo: string

  constructor(
    private readonly storage: KeystoreStorage,
    private readonly config: KeystoreConfig,
    private readonly webauthn?: WebAuthnProvider,
  ) {
    this.ns = config.namespace ?? DEFAULT_NAMESPACE
    this.hkdfInfo = config.hkdfInfo ?? DEFAULT_HKDF_INFO
  }

  private get CRED(): string { return `${this.ns}.credentialId` }
  private get ENC(): string { return `${this.ns}.encryptedKey` }
  private get METHOD(): string { return `${this.ns}.method` }

  /** Generate a random 256-bit secret as a 64-char hex string. */
  generateSecret(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(32))
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
  }

  /** Has any unlock method been set up? */
  isSetUp(): boolean {
    return this.storage.getItem(this.METHOD) !== null
  }

  /** The currently configured unlock method, or null. */
  method(): UnlockMethod | null {
    const v = this.storage.getItem(this.METHOD)
    return v === 'pin' || v === 'biometric' || v === 'grace' ? v : null
  }

  // --- PIN ---

  /** Protect `secret` behind a passphrase (PBKDF2 → AES-GCM). */
  async setupPIN(passphrase: string, secret: string): Promise<void> {
    if (passphrase.length === 0) throw new Error('passphrase must not be empty')
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const key = await deriveAesKey(passphrase, salt)
    const encrypted = await this.encryptWithKey(secret, key)
    this.storage.setItem(this.ENC, JSON.stringify({ encrypted, salt: toB64(salt) }))
    this.storage.setItem(this.METHOD, 'pin')
  }

  /** Recover the secret from a passphrase, or null if wrong / not set up. */
  async unlockPIN(passphrase: string): Promise<string | null> {
    try {
      const raw = this.storage.getItem(this.ENC)
      if (!raw) return null
      const stored = JSON.parse(raw) as Record<string, unknown>
      if (typeof stored.encrypted !== 'string' || typeof stored.salt !== 'string') return null
      const salt = fromB64(stored.salt)
      const key = await deriveAesKey(passphrase, salt)
      return await this.decryptWithKey(stored.encrypted, key)
    } catch {
      return null
    }
  }

  /** Re-wrap the secret under a new passphrase. Returns false if the current one is wrong. */
  async changePIN(current: string, next: string): Promise<boolean> {
    const secret = await this.unlockPIN(current)
    if (secret === null) return false
    await this.setupPIN(next, secret)
    return true
  }

  // --- Biometric (WebAuthn) ---

  /** Is a user-verifying platform authenticator available? */
  async isBiometricAvailable(): Promise<boolean> {
    return this.webauthn ? this.webauthn.isAvailable() : false
  }

  /**
   * Protect `secret` behind a platform biometric. Prefers the hardware-derived
   * PRF key; falls back to a credential-id-derived key (weaker — see
   * {@link SetupBiometricResult}). No-op `{ ok: false }` if no provider is wired.
   */
  async setupBiometric(secret: string): Promise<SetupBiometricResult> {
    if (!this.webauthn) return { ok: false, prfSupported: false }
    try {
      const cred = await this.webauthn.createCredential(this.config.rpId, this.config.rpName)
      if (!cred) return { ok: false, prfSupported: false }
      this.storage.setItem(this.CRED, cred.credId)

      if (cred.prfEnabled) {
        const prf = await this.webauthn.getPRF(cred.credId, this.config.prfSalt)
        if (prf) {
          const key = await this.deriveKeyFromPRF(prf)
          const encrypted = await this.encryptWithKey(secret, key)
          this.storage.setItem(this.ENC, JSON.stringify({ encrypted, prf: true }))
          this.storage.setItem(this.METHOD, 'biometric')
          return { ok: true, prfSupported: true }
        }
      }

      // Fallback: the biometric assertion still gates access, but the key material
      // derives from the (stored) credential id — secure against live attacks,
      // not against offline extraction of the stored blob.
      const deviceSalt = crypto.getRandomValues(new Uint8Array(16))
      const key = await deriveAesKey(cred.credId, deviceSalt)
      const encrypted = await this.encryptWithKey(secret, key)
      this.storage.setItem(this.ENC, JSON.stringify({ encrypted, salt: toB64(deviceSalt), prf: false }))
      this.storage.setItem(this.METHOD, 'biometric')
      return { ok: true, prfSupported: false }
    } catch {
      return { ok: false, prfSupported: false }
    }
  }

  /** Recover the secret via biometric, or null on failure/abort. */
  async unlockBiometric(): Promise<string | null> {
    if (!this.webauthn) return null
    try {
      const credId = this.storage.getItem(this.CRED)
      if (!credId) return null
      const raw = this.storage.getItem(this.ENC)
      if (!raw) return null
      const stored = JSON.parse(raw) as Record<string, unknown>
      if (typeof stored.encrypted !== 'string') return null

      if (stored.prf === true) {
        const prf = await this.webauthn.getPRF(credId, this.config.prfSalt)
        if (!prf) return null
        const key = await this.deriveKeyFromPRF(prf)
        return await this.decryptWithKey(stored.encrypted, key)
      }

      const verified = await this.webauthn.assert(credId)
      if (!verified) return null
      if (typeof stored.salt !== 'string') return null
      const salt = fromB64(stored.salt)
      const key = await deriveAesKey(credId, salt)
      return await this.decryptWithKey(stored.encrypted, key)
    } catch {
      return null
    }
  }

  // --- Grace ---

  /**
   * Protect `secret` behind a non-extractable AES-GCM handle held in storage —
   * a short-lived unlock that survives a page-wake but not a key wipe.
   */
  async setupGrace(secret: string): Promise<void> {
    const handle = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      /* extractable */ false,
      ['encrypt', 'decrypt'],
    )
    const wrapped = await this.encryptWithKey(secret, handle)
    await this.storage.saveGraceKey(handle, wrapped)
    this.storage.setItem(this.METHOD, 'grace')
  }

  /** Recover the secret via the grace handle, or null if absent/cleared. */
  async unlockGrace(): Promise<string | null> {
    try {
      const rec = await this.storage.getGraceKey()
      if (!rec) return null
      return await this.decryptWithKey(rec.wrapped, rec.handle)
    } catch {
      return null
    }
  }

  // --- Switching ---

  /** Add biometric unlock (caller must already hold the decrypted secret). */
  async enableBiometric(secret: string): Promise<SetupBiometricResult> {
    return this.setupBiometric(secret)
  }

  /** Drop the biometric credential and re-wrap under a passphrase. */
  async disableBiometric(secret: string, newPassphrase: string): Promise<void> {
    this.storage.removeItem(this.CRED)
    await this.setupPIN(newPassphrase, secret)
  }

  /** End the grace period by re-wrapping under a passphrase (atomic: clears grace only on success). */
  async endGraceWithPin(passphrase: string, secret: string): Promise<void> {
    await this.setupPIN(passphrase, secret) // throws on empty passphrase; flips method to 'pin'
    await this.storage.clearGraceKey()       // only reached on success
  }

  /** End the grace period by re-wrapping under biometric (throws if setup fails; grace left intact). */
  async endGraceWithBiometric(secret: string): Promise<void> {
    const result = await this.setupBiometric(secret)
    if (!result.ok) throw new Error('biometric setup failed')
    await this.storage.clearGraceKey()
  }

  /** Wipe every trace — the "burn it all". */
  async burn(): Promise<void> {
    this.storage.removeItem(this.CRED)
    this.storage.removeItem(this.ENC)
    this.storage.removeItem(this.METHOD)
    await this.storage.clearGraceKey()
  }

  // --- internals ---

  private async deriveKeyFromPRF(prf: ArrayBuffer): Promise<CryptoKey> {
    const keyMaterial = await crypto.subtle.importKey('raw', prf, 'HKDF', false, ['deriveKey'])
    const salt = Uint8Array.from(this.config.prfSalt)
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode(this.hkdfInfo) },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    )
  }

  /** base64(iv[12] || ciphertext) — the key is pre-derived, so no salt is carried. */
  private async encryptWithKey(plaintext: string, key: CryptoKey): Promise<string> {
    const { iv, ciphertext } = await aesEncrypt(plaintext, key)
    const combined = new Uint8Array(IV_LENGTH + ciphertext.length)
    combined.set(iv)
    combined.set(ciphertext, IV_LENGTH)
    return toB64(combined)
  }

  private async decryptWithKey(encrypted: string, key: CryptoKey): Promise<string> {
    const combined = fromB64(encrypted)
    if (combined.length < IV_LENGTH + 16 + 1) throw new Error('ciphertext too short')
    const iv = combined.slice(0, IV_LENGTH)
    const ciphertext = combined.slice(IV_LENGTH)
    return aesDecrypt(iv, ciphertext, key)
  }
}

function toB64(bytes: Uint8Array): string {
  let binary = ''
  bytes.forEach(b => { binary += String.fromCharCode(b) })
  return btoa(binary)
}

function fromB64(s: string): Uint8Array {
  return Uint8Array.from(atob(s), c => c.charCodeAt(0))
}
