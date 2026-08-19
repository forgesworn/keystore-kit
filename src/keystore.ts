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
  BiometricSetupOptions,
  SetupBiometricResult,
} from './types.js'

const DEFAULT_NAMESPACE = 'keystore'
const DEFAULT_HKDF_INFO = 'keystore-kit-encryption-key'

/**
 * A parsed stored wrap. PIN wraps are `{ encrypted, salt }`; biometric wraps add
 * a `prf` flag (`{ encrypted, prf: true }` or `{ encrypted, salt, prf: false }`).
 * The `prf` property's presence is what distinguishes the two — including in the
 * legacy single-slot layout, where both were written to the same key.
 */
interface StoredWrap {
  encrypted: string
  salt?: string
  prf?: boolean
}

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

  // PIN and biometric wraps live in independent slots, so enabling one method
  // never destroys the other. The `.method` flag records the most recently
  // configured method (informational; both unlock paths stay usable).
  private get PIN_ENC(): string { return `${this.ns}.pin.encryptedKey` }
  private get BIO_CRED(): string { return `${this.ns}.biometric.credentialId` }
  private get BIO_ENC(): string { return `${this.ns}.biometric.encryptedKey` }
  private get METHOD(): string { return `${this.ns}.method` }
  // Pre-0.2 single-slot layout — read for migration tolerance, wiped on burn,
  // and cleared entry-by-entry when the corresponding method is re-enabled.
  private get LEGACY_CRED(): string { return `${this.ns}.credentialId` }
  private get LEGACY_ENC(): string { return `${this.ns}.encryptedKey` }

  /** Generate a random 256-bit secret as a 64-char hex string. */
  generateSecret(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(32))
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
  }

  /** Has any unlock method been set up? */
  isSetUp(): boolean {
    return this.storage.getItem(this.METHOD) !== null
      || this.storage.getItem(this.PIN_ENC) !== null
      || this.storage.getItem(this.BIO_ENC) !== null
      || this.storage.getItem(this.LEGACY_ENC) !== null
  }

  /**
   * The most recently configured unlock method, or null. Note that PIN and
   * biometric wraps are independent: `method()` says which was set up last,
   * not which are usable — both may be.
   */
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
    this.storage.setItem(this.PIN_ENC, JSON.stringify({ encrypted, salt: toB64(salt) }))
    this.storage.setItem(this.METHOD, 'pin')
    // Migrate a legacy single-slot PIN wrap to the new slot: drop the stale copy
    // (the old passphrase could still open it). A legacy biometric wrap is left
    // alone — it belongs to the other method.
    const legacy = this.parseWrap(this.storage.getItem(this.LEGACY_ENC))
    if (legacy && legacy.prf === undefined) this.storage.removeItem(this.LEGACY_ENC)
  }

  /** Recover the secret from a passphrase, or null if wrong / not set up. */
  async unlockPIN(passphrase: string): Promise<string | null> {
    try {
      const stored = this.parseWrap(this.storage.getItem(this.PIN_ENC))
        ?? this.parseWrap(this.storage.getItem(this.LEGACY_ENC))
      // PIN wraps carry a salt and no `prf` flag; anything else is not ours.
      if (!stored || stored.prf !== undefined || typeof stored.salt !== 'string') return null
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
   * Protect `secret` behind a platform biometric, in its own slot (an existing
   * PIN wrap is untouched). Prefers the hardware-derived PRF key. When the
   * authenticator lacks PRF, the weaker credential-id-derived fallback is used
   * only with an explicit `allowDeviceFallback: true` opt-in; otherwise nothing
   * is written and the result is `{ ok: false, reason: 'prf-unsupported' }`.
   */
  async setupBiometric(secret: string, opts?: BiometricSetupOptions): Promise<SetupBiometricResult> {
    if (!this.webauthn) return { ok: false, prfSupported: false, reason: 'no-provider' }
    try {
      const cred = await this.webauthn.createCredential(this.config.rpId, this.config.rpName)
      if (!cred) return { ok: false, prfSupported: false, reason: 'cancelled' }

      if (cred.prfEnabled) {
        const prf = await this.webauthn.getPRF(cred.credId, this.config.prfSalt)
        if (prf) {
          const key = await this.deriveKeyFromPRF(prf)
          const encrypted = await this.encryptWithKey(secret, key)
          this.writeBiometricSlot(cred.credId, { encrypted, prf: true })
          return { ok: true, prfSupported: true }
        }
      }

      // Fallback: the biometric assertion still gates access, but the key material
      // derives from the (stored) credential id — anyone who can read the storage
      // can unwrap without user verification. Opt-in only, never silent.
      if (opts?.allowDeviceFallback !== true) {
        return { ok: false, prfSupported: false, reason: 'prf-unsupported' }
      }
      const deviceSalt = crypto.getRandomValues(new Uint8Array(16))
      const key = await deriveAesKey(cred.credId, deviceSalt)
      const encrypted = await this.encryptWithKey(secret, key)
      this.writeBiometricSlot(cred.credId, { encrypted, salt: toB64(deviceSalt), prf: false })
      return { ok: true, prfSupported: false, fallback: 'device' }
    } catch {
      return { ok: false, prfSupported: false, reason: 'error' }
    }
  }

  /** Recover the secret via biometric, or null on failure/abort. */
  async unlockBiometric(): Promise<string | null> {
    if (!this.webauthn) return null
    try {
      const credId = this.storage.getItem(this.BIO_CRED) ?? this.storage.getItem(this.LEGACY_CRED)
      if (!credId) return null
      const stored = this.parseWrap(this.storage.getItem(this.BIO_ENC))
        ?? this.parseWrap(this.storage.getItem(this.LEGACY_ENC))
      // Biometric wraps always carry a `prf` flag; a PIN wrap is not ours.
      if (!stored || stored.prf === undefined) return null

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
  async enableBiometric(secret: string, opts?: BiometricSetupOptions): Promise<SetupBiometricResult> {
    return this.setupBiometric(secret, opts)
  }

  /** Drop the biometric credential and re-wrap under a passphrase. */
  async disableBiometric(secret: string, newPassphrase: string): Promise<void> {
    this.storage.removeItem(this.BIO_CRED)
    this.storage.removeItem(this.BIO_ENC)
    this.storage.removeItem(this.LEGACY_CRED)
    // A legacy single-slot biometric wrap becomes inert once its credential id
    // is gone, but drop it explicitly. A legacy PIN wrap is left for setupPIN.
    const legacy = this.parseWrap(this.storage.getItem(this.LEGACY_ENC))
    if (legacy && legacy.prf !== undefined) this.storage.removeItem(this.LEGACY_ENC)
    await this.setupPIN(newPassphrase, secret)
  }

  /** End the grace period by re-wrapping under a passphrase (atomic: clears grace only on success). */
  async endGraceWithPin(passphrase: string, secret: string): Promise<void> {
    await this.setupPIN(passphrase, secret) // throws on empty passphrase; flips method to 'pin'
    await this.storage.clearGraceKey()       // only reached on success
  }

  /** End the grace period by re-wrapping under biometric (throws if setup fails; grace left intact). */
  async endGraceWithBiometric(secret: string, opts?: BiometricSetupOptions): Promise<void> {
    const result = await this.setupBiometric(secret, opts)
    if (!result.ok) throw new Error('biometric setup failed')
    await this.storage.clearGraceKey()
  }

  /** Wipe every trace — the "burn it all". */
  async burn(): Promise<void> {
    this.storage.removeItem(this.PIN_ENC)
    this.storage.removeItem(this.BIO_CRED)
    this.storage.removeItem(this.BIO_ENC)
    this.storage.removeItem(this.METHOD)
    this.storage.removeItem(this.LEGACY_CRED)
    this.storage.removeItem(this.LEGACY_ENC)
    await this.storage.clearGraceKey()
  }

  // --- internals ---

  /** Write the biometric slot, migrating any legacy single-slot biometric entries. */
  private writeBiometricSlot(credId: string, wrap: StoredWrap): void {
    this.storage.setItem(this.BIO_CRED, credId)
    this.storage.setItem(this.BIO_ENC, JSON.stringify(wrap))
    this.storage.setItem(this.METHOD, 'biometric')
    const legacy = this.parseWrap(this.storage.getItem(this.LEGACY_ENC))
    if (legacy && legacy.prf !== undefined) this.storage.removeItem(this.LEGACY_ENC)
    this.storage.removeItem(this.LEGACY_CRED)
  }

  /**
   * Parse a stored wrap, tolerating anything: returns null unless the value is
   * JSON with a string `encrypted` field. Non-string `salt` / non-boolean `prf`
   * fields are dropped, so callers' own shape checks still fail closed.
   */
  private parseWrap(raw: string | null): StoredWrap | null {
    if (!raw) return null
    try {
      const parsed = JSON.parse(raw) as Record<string, unknown>
      if (typeof parsed.encrypted !== 'string') return null
      const wrap: StoredWrap = { encrypted: parsed.encrypted }
      if (typeof parsed.salt === 'string') wrap.salt = parsed.salt
      if (typeof parsed.prf === 'boolean') wrap.prf = parsed.prf
      return wrap
    } catch {
      return null
    }
  }

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
