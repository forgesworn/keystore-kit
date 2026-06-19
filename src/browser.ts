/**
 * Browser adapters for {@link Keystore}: `localStorage` + IndexedDB storage and a
 * real `navigator.credentials` WebAuthn provider.
 *
 * Platform-only — these touch `localStorage`, `indexedDB`, `navigator`, and
 * `window`, so they run in a browser, not in Node. They are exercised in a real
 * PWA, not in the unit suite (which uses {@link InMemoryKeystoreStorage} + a mock
 * provider). The WebAuthn logic is lifted from the audited signet-app `auth.ts`.
 */

import type { KeystoreStorage, WebAuthnProvider, GraceKeyRecord } from './types.js'

const DB_NAME = 'keystore-kit'
const DB_VERSION = 1
const GRACE_STORE = 'grace'
const GRACE_KEY = 'current'

function openGraceDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION)
    request.onupgradeneeded = () => {
      const db = request.result
      if (!db.objectStoreNames.contains(GRACE_STORE)) db.createObjectStore(GRACE_STORE)
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error)
  })
}

/**
 * A {@link KeystoreStorage} over `localStorage` (string KV) and IndexedDB (the
 * non-extractable grace `CryptoKey`, which `localStorage` cannot hold).
 */
export function browserStorage(): KeystoreStorage {
  return {
    getItem: (key) => localStorage.getItem(key),
    setItem: (key, value) => localStorage.setItem(key, value),
    removeItem: (key) => localStorage.removeItem(key),

    async saveGraceKey(handle: CryptoKey, wrapped: string): Promise<void> {
      const db = await openGraceDB()
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(GRACE_STORE, 'readwrite')
        tx.objectStore(GRACE_STORE).put({ handle, wrapped } satisfies GraceKeyRecord, GRACE_KEY)
        tx.oncomplete = () => { db.close(); resolve() }
        tx.onerror = () => { db.close(); reject(tx.error) }
      })
    },

    async getGraceKey(): Promise<GraceKeyRecord | null> {
      const db = await openGraceDB()
      return new Promise((resolve, reject) => {
        const tx = db.transaction(GRACE_STORE, 'readonly')
        const req = tx.objectStore(GRACE_STORE).get(GRACE_KEY)
        req.onsuccess = () => { db.close(); resolve((req.result as GraceKeyRecord | undefined) ?? null) }
        req.onerror = () => { db.close(); reject(req.error) }
      })
    },

    async clearGraceKey(): Promise<void> {
      const db = await openGraceDB()
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(GRACE_STORE, 'readwrite')
        tx.objectStore(GRACE_STORE).delete(GRACE_KEY)
        tx.oncomplete = () => { db.close(); resolve() }
        tx.onerror = () => { db.close(); reject(tx.error) }
      })
    },
  }
}

const b64 = (buf: ArrayBuffer): string => btoa(String.fromCharCode(...new Uint8Array(buf)))
// No return annotation: let inference keep `Uint8Array<ArrayBuffer>` so it satisfies BufferSource.
const unb64 = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0))

/** A real WebAuthn provider over `navigator.credentials`, requesting the PRF extension. */
export function browserWebAuthn(): WebAuthnProvider {
  return {
    async isAvailable(): Promise<boolean> {
      if (!window.PublicKeyCredential) return false
      try {
        return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
      } catch {
        return false
      }
    },

    async createCredential(rpId: string, rpName: string) {
      const challenge = crypto.getRandomValues(new Uint8Array(32))
      const createOptions: PublicKeyCredentialCreationOptions & { extensions?: Record<string, unknown> } = {
        challenge,
        rp: { name: rpName, id: rpId },
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: 'keystore-user',
          displayName: 'Keystore User',
        },
        pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
          residentKey: 'preferred',
        },
        extensions: { prf: {} },
        timeout: 60000,
      }
      const credential = await navigator.credentials.create({ publicKey: createOptions }) as PublicKeyCredential | null
      if (!credential) return null
      const ext = (credential as PublicKeyCredential & { getClientExtensionResults(): Record<string, unknown> }).getClientExtensionResults()
      const prfEnabled = !!(ext?.prf && (ext.prf as Record<string, unknown>)?.enabled)
      return { credId: b64(credential.rawId), prfEnabled }
    },

    async getPRF(credId: string, salt: Uint8Array): Promise<ArrayBuffer | null> {
      try {
        const challenge = crypto.getRandomValues(new Uint8Array(32))
        const assertion = await navigator.credentials.get({
          publicKey: {
            challenge,
            allowCredentials: [{ id: unb64(credId), type: 'public-key', transports: ['internal'] }],
            userVerification: 'required',
            extensions: { prf: { eval: { first: salt } } } as Record<string, unknown>,
            timeout: 60000,
          },
        }) as PublicKeyCredential | null
        if (!assertion) return null
        const ext = (assertion as PublicKeyCredential & { getClientExtensionResults(): Record<string, unknown> }).getClientExtensionResults()
        const prf = ext?.prf as Record<string, unknown> | undefined
        const results = prf?.results as Record<string, ArrayBuffer> | undefined
        return results?.first ?? null
      } catch {
        return null
      }
    },

    async assert(credId: string): Promise<boolean> {
      try {
        const challenge = crypto.getRandomValues(new Uint8Array(32))
        const assertion = await navigator.credentials.get({
          publicKey: {
            challenge,
            allowCredentials: [{ id: unb64(credId), type: 'public-key', transports: ['internal'] }],
            userVerification: 'required',
            timeout: 60000,
          },
        }) as PublicKeyCredential | null
        return !!assertion
      } catch {
        return false
      }
    },
  }
}
