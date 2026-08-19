/** The three unlock methods a {@link Keystore} can protect a secret behind. */
export type UnlockMethod = 'pin' | 'biometric' | 'grace'

/** Options for {@link Keystore.setupBiometric} / {@link Keystore.enableBiometric}. */
export interface BiometricSetupOptions {
  /**
   * Explicitly opt in to the weaker device-bound fallback when the
   * authenticator lacks the WebAuthn PRF extension: the wrapping key is then
   * derived from the credential id, which is stored alongside the ciphertext —
   * anyone with read access to the underlying storage can unwrap the secret
   * without any user verification. Leave unset to refuse the fallback; setup
   * then returns `{ ok: false, reason: 'prf-unsupported' }` and writes nothing.
   */
  allowDeviceFallback?: boolean
}

/** Why a biometric setup attempt did not complete. */
export type SetupBiometricFailureReason =
  | 'no-provider'      // no WebAuthnProvider wired into the Keystore
  | 'cancelled'        // credential creation failed or was aborted by the user
  | 'prf-unsupported'  // authenticator lacks PRF and allowDeviceFallback was not set
  | 'error'            // the provider threw (hardware/platform error)

/**
 * Result of a biometric setup attempt. The weaker device-bound fallback never
 * happens silently: it requires `allowDeviceFallback: true`, and when it was
 * used the result is the `{ ok: true, prfSupported: false, fallback: 'device' }`
 * variant — surface that to the user and prefer PIN as the primary unlock on
 * devices without PRF. When PRF is absent and no opt-in was given, the result
 * is `{ ok: false, reason: 'prf-unsupported' }` and nothing is written.
 */
export type SetupBiometricResult =
  | { ok: true; prfSupported: true }
  | { ok: true; prfSupported: false; fallback: 'device' }
  | { ok: false; prfSupported: false; reason: SetupBiometricFailureReason }

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
