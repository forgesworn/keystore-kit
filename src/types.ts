/** The three unlock methods a {@link Keystore} can protect a secret behind. */
export type UnlockMethod = 'pin' | 'biometric' | 'grace'

/**
 * Result of a biometric setup attempt. `prfSupported: false` means the device
 * lacks the WebAuthn PRF extension and the key material was derived from the
 * credential ID instead (still biometric-gated, but weaker — vulnerable to
 * offline extraction of stored data). Surface this so the user can opt into PIN
 * as the primary unlock instead.
 */
export interface SetupBiometricResult {
  ok: boolean
  prfSupported: boolean
}

/** The grace-key record: a non-extractable AES-GCM handle plus the secret wrapped under it. */
export interface GraceKeyRecord {
  handle: CryptoKey
  wrapped: string
}

/**
 * Persistence seam. The string KV (`getItem`/`setItem`/`removeItem`) holds the
 * small encrypted blobs and metadata (localStorage-shaped, may be synchronous);
 * the grace methods hold a non-extractable `CryptoKey`, which cannot be
 * serialised to a string and so needs structured storage (IndexedDB-shaped).
 *
 * Provide a real implementation per platform — {@link InMemoryKeystoreStorage}
 * for Node/tests, `browserStorage()` for a PWA.
 */
export interface KeystoreStorage {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
  saveGraceKey(handle: CryptoKey, wrapped: string): Promise<void>
  getGraceKey(): Promise<GraceKeyRecord | null>
  clearGraceKey(): Promise<void>
}

/**
 * WebAuthn seam. Abstracts `navigator.credentials` so the keystore core stays
 * testable (mock it in Node) and platform-portable. `browserWebAuthn()` provides
 * the real implementation; omit the provider entirely to disable biometric unlock.
 */
export interface WebAuthnProvider {
  /** Is a user-verifying platform authenticator available? */
  isAvailable(): Promise<boolean>
  /**
   * Create a platform credential requesting the PRF extension.
   * @returns base64 credential id + whether PRF is enabled, or null on failure/abort.
   */
  createCredential(rpId: string, rpName: string): Promise<{ credId: string; prfEnabled: boolean } | null>
  /** Get PRF output for `credId` evaluated against `salt`, or null on failure/abort. */
  getPRF(credId: string, salt: Uint8Array): Promise<ArrayBuffer | null>
  /** Perform a plain assertion (no PRF) for the fallback path; resolves true on user verification. */
  assert(credId: string): Promise<boolean>
}

/** Per-app configuration for a {@link Keystore}. */
export interface KeystoreConfig {
  /** WebAuthn relying-party id (typically the host, e.g. `app.example`). */
  rpId: string
  /** WebAuthn relying-party display name. */
  rpName: string
  /** 32-byte app-constant PRF salt (also used as the HKDF salt over the PRF output). */
  prfSalt: Uint8Array
  /** HKDF `info` label for the PRF-derived key. Defaults to `keystore-kit-encryption-key`. */
  hkdfInfo?: string
  /** Storage-key namespace, so multiple keystores can coexist. Defaults to `keystore`. */
  namespace?: string
}
