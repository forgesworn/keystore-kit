import { describe, it, expect } from 'vitest'
import { Keystore } from './keystore.js'
import { InMemoryKeystoreStorage } from './memory-storage.js'
import type { KeystoreConfig, WebAuthnProvider } from './types.js'

const config: KeystoreConfig = { rpId: 'localhost', rpName: 'Test', prfSalt: new Uint8Array(32) }

/** A deterministic mock WebAuthn provider: returns stable PRF bytes so setup and unlock agree. */
function mockWebAuthn(opts: { prf?: boolean; available?: boolean } = {}): WebAuthnProvider {
  const prfEnabled = opts.prf ?? true
  const available = opts.available ?? true
  const prfBytes = crypto.getRandomValues(new Uint8Array(32))
  return {
    async isAvailable() { return available },
    async createCredential() { return { credId: 'cred-1', prfEnabled } },
    async getPRF() { return prfBytes.buffer.slice(0) }, // same bytes every call
    async assert() { return true },
  }
}

const SECRET = 'deadbeef'.repeat(8) // 64-char hex — but any opaque string works

describe('Keystore — PIN', () => {
  it('sets up and unlocks with the right passphrase', async () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config)
    expect(ks.isSetUp()).toBe(false)
    await ks.setupPIN('123456', SECRET)
    expect(ks.isSetUp()).toBe(true)
    expect(ks.method()).toBe('pin')
    expect(await ks.unlockPIN('123456')).toBe(SECRET)
  })

  it('returns null on the wrong passphrase', async () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config)
    await ks.setupPIN('123456', SECRET)
    expect(await ks.unlockPIN('000000')).toBeNull()
  })

  it('returns null when nothing is set up', async () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config)
    expect(await ks.unlockPIN('whatever')).toBeNull()
    expect(ks.method()).toBeNull()
  })

  it('rejects an empty passphrase', async () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config)
    await expect(ks.setupPIN('', SECRET)).rejects.toThrow('must not be empty')
  })

  it('changePIN re-wraps under the new passphrase and rejects a wrong current one', async () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config)
    await ks.setupPIN('111111', SECRET)
    expect(await ks.changePIN('999999', '222222')).toBe(false)
    expect(await ks.changePIN('111111', '222222')).toBe(true)
    expect(await ks.unlockPIN('222222')).toBe(SECRET)
    expect(await ks.unlockPIN('111111')).toBeNull()
  })

  it('generateSecret returns 64 hex chars', () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config)
    expect(ks.generateSecret()).toMatch(/^[0-9a-f]{64}$/)
  })
})

describe('Keystore — grace', () => {
  it('sets up and unlocks via the grace handle', async () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config)
    await ks.setupGrace(SECRET)
    expect(ks.method()).toBe('grace')
    expect(await ks.unlockGrace()).toBe(SECRET)
  })

  it('returns null when there is no grace record', async () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config)
    expect(await ks.unlockGrace()).toBeNull()
  })

  it('endGraceWithPin re-wraps under a PIN and clears the grace key', async () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config)
    await ks.setupGrace(SECRET)
    await ks.endGraceWithPin('424242', SECRET)
    expect(ks.method()).toBe('pin')
    expect(await ks.unlockPIN('424242')).toBe(SECRET)
    expect(await ks.unlockGrace()).toBeNull()
  })

  it('endGraceWithBiometric re-wraps under biometric and clears the grace key', async () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config, mockWebAuthn())
    await ks.setupGrace(SECRET)
    await ks.endGraceWithBiometric(SECRET)
    expect(ks.method()).toBe('biometric')
    expect(await ks.unlockBiometric()).toBe(SECRET)
    expect(await ks.unlockGrace()).toBeNull()
  })
})

describe('Keystore — biometric (mock WebAuthn)', () => {
  it('PRF path: sets up and unlocks', async () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config, mockWebAuthn({ prf: true }))
    expect(await ks.isBiometricAvailable()).toBe(true)
    const r = await ks.setupBiometric(SECRET)
    expect(r).toEqual({ ok: true, prfSupported: true })
    expect(ks.method()).toBe('biometric')
    expect(await ks.unlockBiometric()).toBe(SECRET)
  })

  it('fallback path (no PRF): sets up and unlocks via credential-id key', async () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config, mockWebAuthn({ prf: false }))
    const r = await ks.setupBiometric(SECRET)
    expect(r).toEqual({ ok: true, prfSupported: false })
    expect(await ks.unlockBiometric()).toBe(SECRET)
  })

  it('fallback path returns null when the assertion is not verified', async () => {
    const base = mockWebAuthn({ prf: false })
    const ks = new Keystore(new InMemoryKeystoreStorage(), config, { ...base, assert: async () => false })
    await ks.setupBiometric(SECRET)
    expect(await ks.unlockBiometric()).toBeNull()
  })

  it('is a no-op without a provider', async () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config)
    expect(await ks.isBiometricAvailable()).toBe(false)
    expect(await ks.setupBiometric(SECRET)).toEqual({ ok: false, prfSupported: false })
    expect(await ks.unlockBiometric()).toBeNull()
  })

  it('enable then disable biometric leaves a working PIN', async () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config, mockWebAuthn())
    await ks.setupPIN('111111', SECRET)
    expect((await ks.enableBiometric(SECRET)).ok).toBe(true)
    await ks.disableBiometric(SECRET, '333333')
    expect(ks.method()).toBe('pin')
    expect(await ks.unlockPIN('333333')).toBe(SECRET)
  })
})

describe('Keystore — burn', () => {
  it('wipes every trace', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ks = new Keystore(storage, config)
    await ks.setupPIN('123456', SECRET)
    await ks.setupGrace(SECRET)
    await ks.burn()
    expect(ks.isSetUp()).toBe(false)
    expect(ks.method()).toBeNull()
    expect(await ks.unlockPIN('123456')).toBeNull()
    expect(await ks.unlockGrace()).toBeNull()
  })
})
