import { describe, it, expect } from 'vitest'
import { InMemoryKeystoreStorage } from './memory-storage.js'

/**
 * Direct contract tests for InMemoryKeystoreStorage, independent of Keystore.
 * These document the KeystoreStorage contract that any custom adapter (for
 * React Native, Electron, a server-side vault, …) must satisfy.
 */
describe('InMemoryKeystoreStorage', () => {
  it('getItem returns null for a key that was never set', () => {
    const storage = new InMemoryKeystoreStorage()
    expect(storage.getItem('missing')).toBeNull()
  })

  it('setItem then getItem round-trips a value', () => {
    const storage = new InMemoryKeystoreStorage()
    storage.setItem('k', 'v')
    expect(storage.getItem('k')).toBe('v')
  })

  it('setItem overwrites an existing value', () => {
    const storage = new InMemoryKeystoreStorage()
    storage.setItem('k', 'first')
    storage.setItem('k', 'second')
    expect(storage.getItem('k')).toBe('second')
  })

  it('removeItem deletes a stored value', () => {
    const storage = new InMemoryKeystoreStorage()
    storage.setItem('k', 'v')
    storage.removeItem('k')
    expect(storage.getItem('k')).toBeNull()
  })

  it('removeItem on a key that was never set is a safe no-op', () => {
    const storage = new InMemoryKeystoreStorage()
    expect(() => storage.removeItem('never-set')).not.toThrow()
    expect(storage.getItem('never-set')).toBeNull()
  })

  it('getGraceKey returns null before any grace key has been saved', async () => {
    const storage = new InMemoryKeystoreStorage()
    expect(await storage.getGraceKey()).toBeNull()
  })

  it('saveGraceKey then getGraceKey round-trips the handle and wrapped payload', async () => {
    const storage = new InMemoryKeystoreStorage()
    const handle = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
    await storage.saveGraceKey(handle, 'wrapped-payload')
    const rec = await storage.getGraceKey()
    expect(rec).not.toBeNull()
    expect(rec?.handle).toBe(handle)
    expect(rec?.wrapped).toBe('wrapped-payload')
  })

  it('saveGraceKey overwrites a previously saved grace key', async () => {
    const storage = new InMemoryKeystoreStorage()
    const first = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
    const second = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
    await storage.saveGraceKey(first, 'first')
    await storage.saveGraceKey(second, 'second')
    const rec = await storage.getGraceKey()
    expect(rec?.handle).toBe(second)
    expect(rec?.wrapped).toBe('second')
  })

  it('clearGraceKey clears a saved grace key', async () => {
    const storage = new InMemoryKeystoreStorage()
    const handle = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
    await storage.saveGraceKey(handle, 'wrapped')
    await storage.clearGraceKey()
    expect(await storage.getGraceKey()).toBeNull()
  })

  it('clearGraceKey when nothing was saved is a safe no-op', async () => {
    const storage = new InMemoryKeystoreStorage()
    await expect(storage.clearGraceKey()).resolves.toBeUndefined()
    expect(await storage.getGraceKey()).toBeNull()
  })

  it('independent instances do not share KV or grace state', async () => {
    const a = new InMemoryKeystoreStorage()
    const b = new InMemoryKeystoreStorage()
    a.setItem('k', 'a-value')
    const handle = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
    await a.saveGraceKey(handle, 'a-wrapped')

    expect(b.getItem('k')).toBeNull()
    expect(await b.getGraceKey()).toBeNull()
  })
})
