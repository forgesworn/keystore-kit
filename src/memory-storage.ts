import type { KeystoreStorage, GraceKeyRecord } from './types.js'

/**
 * In-memory {@link KeystoreStorage} — for Node, tests, and ephemeral sessions.
 * Holds the grace `CryptoKey` as a live object reference (it is never serialised).
 * Nothing survives process exit.
 */
export class InMemoryKeystoreStorage implements KeystoreStorage {
  private readonly kv = new Map<string, string>()
  private grace: GraceKeyRecord | null = null

  getItem(key: string): string | null {
    return this.kv.has(key) ? this.kv.get(key)! : null
  }

  setItem(key: string, value: string): void {
    this.kv.set(key, value)
  }

  removeItem(key: string): void {
    this.kv.delete(key)
  }

  async saveGraceKey(handle: CryptoKey, wrapped: string): Promise<void> {
    this.grace = { handle, wrapped }
  }

  async getGraceKey(): Promise<GraceKeyRecord | null> {
    return this.grace
  }

  async clearGraceKey(): Promise<void> {
    this.grace = null
  }
}
