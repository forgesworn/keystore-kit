import { describe, it, expect } from 'vitest'
import { Keystore } from './keystore.js'
import { InMemoryKeystoreStorage } from './memory-storage.js'
import type { KeystoreConfig, WebAuthnProvider, KeystoreStorage, GraceKeyRecord } from './types.js'

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

  it('returns null when the stored blob has a malformed shape (encrypted field not a string)', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ks = new Keystore(storage, config)
    await ks.setupPIN('123456', SECRET)
    storage.setItem('keystore.pin.encryptedKey', JSON.stringify({ encrypted: 12345, salt: 'AAAA' }))
    expect(await ks.unlockPIN('123456')).toBeNull()
  })

  it('returns null when the stored blob has a malformed shape (salt field not a string)', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ks = new Keystore(storage, config)
    await ks.setupPIN('123456', SECRET)
    storage.setItem('keystore.pin.encryptedKey', JSON.stringify({ encrypted: 'abcd', salt: 42 }))
    expect(await ks.unlockPIN('123456')).toBeNull()
  })

  it('returns null (not a thrown error) when the stored value is not valid JSON', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ks = new Keystore(storage, config)
    storage.setItem('keystore.pin.encryptedKey', 'not-json-at-all{{{')
    await expect(ks.unlockPIN('123456')).resolves.toBeNull()
  })

  it('returns null (not a thrown error) when the ciphertext has been tampered with', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ks = new Keystore(storage, config)
    await ks.setupPIN('123456', SECRET)
    const raw = JSON.parse(storage.getItem('keystore.pin.encryptedKey')!) as { encrypted: string; salt: string }
    const bytes = Uint8Array.from(atob(raw.encrypted), (c) => c.charCodeAt(0))
    bytes[bytes.length - 1] ^= 0xff // flip a byte inside the GCM tag
    raw.encrypted = btoa(String.fromCharCode(...bytes))
    storage.setItem('keystore.pin.encryptedKey', JSON.stringify(raw))
    expect(await ks.unlockPIN('123456')).toBeNull()
  })

  it('returns null when the stored ciphertext is too short to be valid (truncated/corrupted blob)', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ks = new Keystore(storage, config)
    await ks.setupPIN('123456', SECRET)
    const raw = JSON.parse(storage.getItem('keystore.pin.encryptedKey')!) as { encrypted: string; salt: string }
    raw.encrypted = btoa('short') // decodes to far fewer bytes than IV + GCM tag requires
    storage.setItem('keystore.pin.encryptedKey', JSON.stringify(raw))
    expect(await ks.unlockPIN('123456')).toBeNull()
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

  it('holds the grace key as a non-extractable CryptoKey', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ks = new Keystore(storage, config)
    await ks.setupGrace(SECRET)
    const rec = await storage.getGraceKey()
    expect(rec?.handle.extractable).toBe(false)
  })

  it('returns null (not a thrown error) when the wrapped ciphertext has been tampered with', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ks = new Keystore(storage, config)
    await ks.setupGrace(SECRET)
    const rec = await storage.getGraceKey()
    const bytes = Uint8Array.from(atob(rec!.wrapped), (c) => c.charCodeAt(0))
    bytes[bytes.length - 1] ^= 0xff // flip a byte inside the GCM tag
    await storage.saveGraceKey(rec!.handle, btoa(String.fromCharCode(...bytes)))
    expect(await ks.unlockGrace()).toBeNull()
  })

  it('endGraceWithBiometric throws and leaves the grace key intact when biometric setup fails', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ks = new Keystore(storage, config) // no webauthn provider wired up — setupBiometric is a no-op
    await ks.setupGrace(SECRET)
    await expect(ks.endGraceWithBiometric(SECRET)).rejects.toThrow('biometric setup failed')
    expect(ks.method()).toBe('grace')
    expect(await ks.unlockGrace()).toBe(SECRET)
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

  it('fallback path (no PRF, explicit opt-in): sets up and unlocks via credential-id key', async () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config, mockWebAuthn({ prf: false }))
    const r = await ks.setupBiometric(SECRET, { allowDeviceFallback: true })
    expect(r).toEqual({ ok: true, prfSupported: false, fallback: 'device' })
    expect(await ks.unlockBiometric()).toBe(SECRET)
  })

  it('fallback path returns null when the assertion is not verified', async () => {
    const base = mockWebAuthn({ prf: false })
    const ks = new Keystore(new InMemoryKeystoreStorage(), config, { ...base, assert: async () => false })
    await ks.setupBiometric(SECRET, { allowDeviceFallback: true })
    expect(await ks.unlockBiometric()).toBeNull()
  })

  it('is a no-op without a provider', async () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config)
    expect(await ks.isBiometricAvailable()).toBe(false)
    expect(await ks.setupBiometric(SECRET)).toEqual({ ok: false, prfSupported: false, reason: 'no-provider' })
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

  it('setupBiometric returns ok:false when createCredential returns null (e.g. the user cancels)', async () => {
    const base = mockWebAuthn()
    const ks = new Keystore(new InMemoryKeystoreStorage(), config, { ...base, createCredential: async () => null })
    expect(await ks.setupBiometric(SECRET)).toEqual({ ok: false, prfSupported: false, reason: 'cancelled' })
    expect(ks.isSetUp()).toBe(false)
  })

  it('setupBiometric returns ok:false when the provider throws (e.g. a hardware error)', async () => {
    const base = mockWebAuthn()
    const ks = new Keystore(new InMemoryKeystoreStorage(), config, {
      ...base,
      createCredential: async () => { throw new Error('hardware error') },
    })
    expect(await ks.setupBiometric(SECRET)).toEqual({ ok: false, prfSupported: false, reason: 'error' })
  })

  it('reports prf-unsupported (and writes nothing) when the credential enables PRF but getPRF fails at setup time', async () => {
    const storage = new InMemoryKeystoreStorage()
    const base = mockWebAuthn({ prf: true })
    const ks = new Keystore(storage, config, { ...base, getPRF: async () => null })
    const r = await ks.setupBiometric(SECRET)
    expect(r).toEqual({ ok: false, prfSupported: false, reason: 'prf-unsupported' })
    expect(storage.getItem('keystore.biometric.credentialId')).toBeNull()
    expect(storage.getItem('keystore.biometric.encryptedKey')).toBeNull()
    expect(ks.isSetUp()).toBe(false)
  })

  it('uses the credential-id-derived key for the same credential when getPRF fails at setup time and the fallback was opted into', async () => {
    const base = mockWebAuthn({ prf: true })
    const ks = new Keystore(new InMemoryKeystoreStorage(), config, { ...base, getPRF: async () => null })
    const r = await ks.setupBiometric(SECRET, { allowDeviceFallback: true })
    expect(r).toEqual({ ok: true, prfSupported: false, fallback: 'device' })
    // Unlock still goes through getPRF first... no: the stored blob is a fallback blob, so assert() gates it.
    expect(await ks.unlockBiometric()).toBe(SECRET)
  })

  it('unlockBiometric returns null when biometric was never set up (no stored credential id)', async () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config, mockWebAuthn())
    expect(await ks.unlockBiometric()).toBeNull()
  })

  it('unlockBiometric returns null when the credential id is present but the encrypted blob is missing (corrupted storage)', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ks = new Keystore(storage, config, mockWebAuthn())
    storage.setItem('keystore.credentialId', 'orphaned-cred-id') // simulate a partial/corrupted write
    expect(await ks.unlockBiometric()).toBeNull()
  })

  it('unlockBiometric returns null when the PRF becomes unavailable at unlock time (setup succeeded earlier)', async () => {
    const storage = new InMemoryKeystoreStorage()
    const setupProvider = mockWebAuthn({ prf: true })
    await new Keystore(storage, config, setupProvider).setupBiometric(SECRET)

    const brokenProvider = { ...setupProvider, getPRF: async () => null }
    const ks = new Keystore(storage, config, brokenProvider)
    expect(await ks.unlockBiometric()).toBeNull()
  })

  it('unlockBiometric returns null on a malformed stored shape (encrypted field not a string)', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ks = new Keystore(storage, config, mockWebAuthn())
    await ks.setupBiometric(SECRET)
    storage.setItem('keystore.biometric.encryptedKey', JSON.stringify({ encrypted: 999, prf: true }))
    expect(await ks.unlockBiometric()).toBeNull()
  })

  it('unlockBiometric returns null on a malformed fallback shape (salt field not a string)', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ks = new Keystore(storage, config, mockWebAuthn({ prf: false }))
    await ks.setupBiometric(SECRET, { allowDeviceFallback: true })
    storage.setItem('keystore.biometric.encryptedKey', JSON.stringify({ encrypted: 'abcd', prf: false }))
    expect(await ks.unlockBiometric()).toBeNull()
  })

  it('unlockBiometric returns null (not a thrown error) when the PRF-path ciphertext has been tampered with', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ks = new Keystore(storage, config, mockWebAuthn({ prf: true }))
    await ks.setupBiometric(SECRET)
    const raw = JSON.parse(storage.getItem('keystore.biometric.encryptedKey')!) as { encrypted: string; prf: boolean }
    const bytes = Uint8Array.from(atob(raw.encrypted), (c) => c.charCodeAt(0))
    bytes[bytes.length - 1] ^= 0xff // flip a byte inside the GCM tag
    raw.encrypted = btoa(String.fromCharCode(...bytes))
    storage.setItem('keystore.biometric.encryptedKey', JSON.stringify(raw))
    expect(await ks.unlockBiometric()).toBeNull()
  })
})

describe('Keystore — independent PIN and biometric slots', () => {
  it('writes the PIN wrap and the biometric wrap to separate storage entries', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ks = new Keystore(storage, config, mockWebAuthn())
    await ks.setupPIN('123456', SECRET)
    await ks.setupBiometric(SECRET)
    expect(storage.getItem('keystore.pin.encryptedKey')).not.toBeNull()
    expect(storage.getItem('keystore.biometric.encryptedKey')).not.toBeNull()
    expect(storage.getItem('keystore.biometric.credentialId')).not.toBeNull()
    expect(storage.getItem('keystore.encryptedKey')).toBeNull() // legacy single slot is never written
    expect(storage.getItem('keystore.credentialId')).toBeNull()
  })

  it('enabling biometric unlock does not destroy PIN unlock', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ks = new Keystore(storage, config, mockWebAuthn())
    await ks.setupPIN('123456', SECRET)
    const pinBlobBefore = storage.getItem('keystore.pin.encryptedKey')
    const r = await ks.enableBiometric(SECRET)
    expect(r).toEqual({ ok: true, prfSupported: true })
    expect(storage.getItem('keystore.pin.encryptedKey')).toBe(pinBlobBefore) // untouched
    expect(await ks.unlockPIN('123456')).toBe(SECRET)
    expect(await ks.unlockBiometric()).toBe(SECRET)
  })

  it('setting a PIN after biometric setup does not destroy biometric unlock', async () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config, mockWebAuthn())
    await ks.setupBiometric(SECRET)
    await ks.setupPIN('123456', SECRET)
    expect(await ks.unlockBiometric()).toBe(SECRET)
    expect(await ks.unlockPIN('123456')).toBe(SECRET)
  })

  it('changePIN re-wraps only the PIN slot; biometric unlock keeps working', async () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config, mockWebAuthn())
    await ks.setupPIN('111111', SECRET)
    await ks.enableBiometric(SECRET)
    expect(await ks.changePIN('111111', '222222')).toBe(true)
    expect(await ks.unlockPIN('222222')).toBe(SECRET)
    expect(await ks.unlockPIN('111111')).toBeNull()
    expect(await ks.unlockBiometric()).toBe(SECRET)
  })

  it('disableBiometric drops only the biometric slot and re-wraps the PIN', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ks = new Keystore(storage, config, mockWebAuthn())
    await ks.setupPIN('111111', SECRET)
    await ks.enableBiometric(SECRET)
    await ks.disableBiometric(SECRET, '333333')
    expect(storage.getItem('keystore.biometric.credentialId')).toBeNull()
    expect(storage.getItem('keystore.biometric.encryptedKey')).toBeNull()
    expect(await ks.unlockBiometric()).toBeNull()
    expect(await ks.unlockPIN('333333')).toBe(SECRET)
  })
})

describe('Keystore — device-fallback consent', () => {
  const ALL_WRAP_KEYS = [
    'keystore.pin.encryptedKey',
    'keystore.biometric.credentialId',
    'keystore.biometric.encryptedKey',
    'keystore.credentialId',
    'keystore.encryptedKey',
    'keystore.method',
  ]

  it('refuses the fallback without an explicit opt-in, writing nothing', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ks = new Keystore(storage, config, mockWebAuthn({ prf: false }))
    const r = await ks.setupBiometric(SECRET)
    expect(r).toEqual({ ok: false, prfSupported: false, reason: 'prf-unsupported' })
    for (const key of ALL_WRAP_KEYS) expect(storage.getItem(key)).toBeNull()
    expect(ks.isSetUp()).toBe(false)
    expect(await ks.unlockBiometric()).toBeNull()
  })

  it('enableBiometric without an opt-in refuses the fallback and leaves an existing PIN untouched', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ks = new Keystore(storage, config, mockWebAuthn({ prf: false }))
    await ks.setupPIN('123456', SECRET)
    const r = await ks.enableBiometric(SECRET)
    expect(r).toEqual({ ok: false, prfSupported: false, reason: 'prf-unsupported' })
    expect(await ks.unlockPIN('123456')).toBe(SECRET)
    expect(await ks.unlockBiometric()).toBeNull()
  })

  it('accepts the fallback with an explicit opt-in and flags it in the result', async () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config, mockWebAuthn({ prf: false }))
    const r = await ks.enableBiometric(SECRET, { allowDeviceFallback: true })
    expect(r).toEqual({ ok: true, prfSupported: false, fallback: 'device' })
    expect(await ks.unlockBiometric()).toBe(SECRET)
  })

  it('endGraceWithBiometric refuses the fallback without an opt-in and leaves the grace key intact', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ks = new Keystore(storage, config, mockWebAuthn({ prf: false }))
    await ks.setupGrace(SECRET)
    await expect(ks.endGraceWithBiometric(SECRET)).rejects.toThrow('biometric setup failed')
    expect(await ks.unlockGrace()).toBe(SECRET)
  })
})

describe('Keystore — legacy single-slot storage (pre-0.2) tolerance', () => {
  /** Move the current new-format entries into the pre-0.2 layout: one slot + method flag. */
  function downgradeToLegacyLayout(storage: InMemoryKeystoreStorage, method: 'pin' | 'biometric'): void {
    if (method === 'pin') {
      storage.setItem('keystore.encryptedKey', storage.getItem('keystore.pin.encryptedKey')!)
      storage.removeItem('keystore.pin.encryptedKey')
    } else {
      storage.setItem('keystore.credentialId', storage.getItem('keystore.biometric.credentialId')!)
      storage.setItem('keystore.encryptedKey', storage.getItem('keystore.biometric.encryptedKey')!)
      storage.removeItem('keystore.biometric.credentialId')
      storage.removeItem('keystore.biometric.encryptedKey')
    }
    storage.setItem('keystore.method', method)
  }

  it('unlocks a legacy PIN blob', async () => {
    const storage = new InMemoryKeystoreStorage()
    await new Keystore(storage, config).setupPIN('123456', SECRET)
    downgradeToLegacyLayout(storage, 'pin')

    const ks = new Keystore(storage, config)
    expect(ks.isSetUp()).toBe(true)
    expect(ks.method()).toBe('pin')
    expect(await ks.unlockPIN('123456')).toBe(SECRET)
    expect(await ks.unlockPIN('000000')).toBeNull()
  })

  it('unlocks a legacy biometric PRF blob', async () => {
    const storage = new InMemoryKeystoreStorage()
    const wa = mockWebAuthn({ prf: true })
    await new Keystore(storage, config, wa).setupBiometric(SECRET)
    downgradeToLegacyLayout(storage, 'biometric')

    const ks = new Keystore(storage, config, wa)
    expect(await ks.unlockBiometric()).toBe(SECRET)
    expect(await ks.unlockPIN('123456')).toBeNull() // a biometric blob is not PIN-unlockable
  })

  it('unlocks a legacy biometric device-fallback blob', async () => {
    const storage = new InMemoryKeystoreStorage()
    const wa = mockWebAuthn({ prf: false })
    await new Keystore(storage, config, wa).setupBiometric(SECRET, { allowDeviceFallback: true })
    downgradeToLegacyLayout(storage, 'biometric')

    const ks = new Keystore(storage, config, wa)
    expect(await ks.unlockBiometric()).toBe(SECRET)
  })

  it('never treats a legacy PIN blob as biometric-unlockable, even with a credential id present', async () => {
    const storage = new InMemoryKeystoreStorage()
    await new Keystore(storage, config).setupPIN('123456', SECRET)
    downgradeToLegacyLayout(storage, 'pin')
    storage.setItem('keystore.credentialId', 'orphaned-cred-id') // partial/corrupted state

    const ks = new Keystore(storage, config, mockWebAuthn())
    expect(await ks.unlockBiometric()).toBeNull()
  })

  it('re-enabling the PIN rewrites to the new slot and removes the legacy blob', async () => {
    const storage = new InMemoryKeystoreStorage()
    await new Keystore(storage, config).setupPIN('123456', SECRET)
    downgradeToLegacyLayout(storage, 'pin')

    const ks = new Keystore(storage, config)
    await ks.setupPIN('654321', SECRET)
    expect(storage.getItem('keystore.pin.encryptedKey')).not.toBeNull()
    expect(storage.getItem('keystore.encryptedKey')).toBeNull() // stale wrap under the old PIN is gone
    expect(await ks.unlockPIN('654321')).toBe(SECRET)
    expect(await ks.unlockPIN('123456')).toBeNull()
  })

  it('re-enabling biometric rewrites to the new slots and removes the legacy entries', async () => {
    const storage = new InMemoryKeystoreStorage()
    const wa = mockWebAuthn({ prf: true })
    await new Keystore(storage, config, wa).setupBiometric(SECRET)
    downgradeToLegacyLayout(storage, 'biometric')

    const ks = new Keystore(storage, config, wa)
    await ks.setupBiometric(SECRET)
    expect(storage.getItem('keystore.biometric.encryptedKey')).not.toBeNull()
    expect(storage.getItem('keystore.encryptedKey')).toBeNull()
    expect(storage.getItem('keystore.credentialId')).toBeNull()
    expect(await ks.unlockBiometric()).toBe(SECRET)
  })

  it('re-enabling the PIN leaves a legacy biometric blob unlockable', async () => {
    const storage = new InMemoryKeystoreStorage()
    const wa = mockWebAuthn({ prf: true })
    await new Keystore(storage, config, wa).setupBiometric(SECRET)
    downgradeToLegacyLayout(storage, 'biometric')

    const ks = new Keystore(storage, config, wa)
    await ks.setupPIN('123456', SECRET) // must not clobber the legacy biometric wrap
    expect(await ks.unlockBiometric()).toBe(SECRET)
    expect(await ks.unlockPIN('123456')).toBe(SECRET)
  })

  it('burn wipes the legacy keys too', async () => {
    const storage = new InMemoryKeystoreStorage()
    const wa = mockWebAuthn({ prf: true })
    await new Keystore(storage, config, wa).setupBiometric(SECRET)
    downgradeToLegacyLayout(storage, 'biometric')

    await new Keystore(storage, config, wa).burn()
    expect(storage.getItem('keystore.encryptedKey')).toBeNull()
    expect(storage.getItem('keystore.credentialId')).toBeNull()
    expect(storage.getItem('keystore.method')).toBeNull()
    expect(storage.getItem('keystore.pin.encryptedKey')).toBeNull()
    expect(storage.getItem('keystore.biometric.encryptedKey')).toBeNull()
    expect(storage.getItem('keystore.biometric.credentialId')).toBeNull()
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

  it('wipes a biometric-protected secret too', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ks = new Keystore(storage, config, mockWebAuthn())
    await ks.setupBiometric(SECRET)
    await ks.burn()
    expect(await ks.unlockBiometric()).toBeNull()
  })

  it('is safe to call when nothing was ever set up', async () => {
    const ks = new Keystore(new InMemoryKeystoreStorage(), config)
    await expect(ks.burn()).resolves.toBeUndefined()
    expect(ks.isSetUp()).toBe(false)
    expect(ks.method()).toBeNull()
  })
})

describe('Keystore — namespacing', () => {
  it('keeps PIN storage isolated across namespaces on a shared storage backend', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ksA = new Keystore(storage, { ...config, namespace: 'app-a' })
    const ksB = new Keystore(storage, { ...config, namespace: 'app-b' })
    await ksA.setupPIN('111111', 'secret-a')
    await ksB.setupPIN('222222', 'secret-b')

    expect(await ksA.unlockPIN('111111')).toBe('secret-a')
    expect(await ksB.unlockPIN('222222')).toBe('secret-b')
    expect(await ksA.unlockPIN('222222')).toBeNull() // B's PIN doesn't unlock A's namespace

    await ksA.burn()
    expect(await ksB.unlockPIN('222222')).toBe('secret-b') // burning A must not touch B
  })

  it('documents current behaviour: the grace slot is per storage instance, not per namespace', async () => {
    const storage = new InMemoryKeystoreStorage()
    const ksA = new Keystore(storage, { ...config, namespace: 'app-a' })
    const ksB = new Keystore(storage, { ...config, namespace: 'app-b' })
    await ksA.setupGrace('secret-a')
    await ksB.setupGrace('secret-b')
    // Unlike PIN/biometric storage keys, KeystoreStorage.saveGraceKey/getGraceKey
    // take no namespace, so the second setupGrace() overwrites the first's slot
    // on a shared storage instance. Use one storage instance per app if grace
    // isolation between keystores is required.
    expect(await ksA.unlockGrace()).toBe('secret-b')
    expect(await ksB.unlockGrace()).toBe('secret-b')
  })
})

describe('Keystore — key domain separation', () => {
  it('derives different keys for different hkdfInfo labels sharing the same PRF output', async () => {
    const storage = new InMemoryKeystoreStorage()
    const wa = mockWebAuthn({ prf: true })
    const ksA = new Keystore(storage, { ...config, hkdfInfo: 'app-a-key' }, wa)
    const ksB = new Keystore(storage, { ...config, hkdfInfo: 'app-b-key' }, wa)

    await ksA.setupBiometric(SECRET)
    expect(await ksB.unlockBiometric()).toBeNull() // same stored blob, different derived key
    expect(await ksA.unlockBiometric()).toBe(SECRET) // ksA still works
  })
})

describe('Keystore — pluggable storage (custom adapter)', () => {
  /**
   * A from-scratch KeystoreStorage implementation, distinct from
   * InMemoryKeystoreStorage, proving the storage seam is genuinely pluggable.
   */
  class CustomObjectStorage implements KeystoreStorage {
    private data: Record<string, string> = {}
    private graceRecord: GraceKeyRecord | null = null

    getItem(key: string): string | null {
      return key in this.data ? this.data[key] : null
    }
    setItem(key: string, value: string): void {
      this.data[key] = value
    }
    removeItem(key: string): void {
      delete this.data[key]
    }
    async saveGraceKey(handle: CryptoKey, wrapped: string): Promise<void> {
      this.graceRecord = { handle, wrapped }
    }
    async getGraceKey(): Promise<GraceKeyRecord | null> {
      return this.graceRecord
    }
    async clearGraceKey(): Promise<void> {
      this.graceRecord = null
    }
  }

  it('works end-to-end (PIN, grace, burn) with a bespoke KeystoreStorage implementation', async () => {
    const storage = new CustomObjectStorage()
    const ks = new Keystore(storage, config)

    await ks.setupPIN('123456', SECRET)
    expect(await ks.unlockPIN('123456')).toBe(SECRET)

    await ks.setupGrace(SECRET)
    expect(await ks.unlockGrace()).toBe(SECRET)

    await ks.burn()
    expect(await ks.unlockPIN('123456')).toBeNull()
    expect(await ks.unlockGrace()).toBeNull()
  })
})
