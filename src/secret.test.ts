import { describe, it, expect } from 'vitest'
import { encryptSecret, decryptSecret, isEncrypted } from './secret.js'

describe('secret', () => {
  it('round-trips under the same passphrase', async () => {
    const enc = await encryptSecret('my-nsec-or-key-hex', 'pass-1')
    expect(enc).not.toContain('my-nsec-or-key-hex')
    expect(await decryptSecret(enc, 'pass-1')).toBe('my-nsec-or-key-hex')
  })

  it('rejects decryption under the wrong passphrase', async () => {
    const enc = await encryptSecret('value', 'right')
    await expect(decryptSecret(enc, 'wrong')).rejects.toThrow()
  })

  it('rejects a too-short payload', async () => {
    await expect(decryptSecret(btoa('aaa'), 'pass')).rejects.toThrow('too short')
  })

  it('isEncrypted recognises real output and rejects junk', async () => {
    expect(isEncrypted(await encryptSecret('x', 'p'))).toBe(true)
    expect(isEncrypted('YWJj')).toBe(false) // valid base64 but only 3 bytes
    expect(isEncrypted('!!!')).toBe(false)  // not base64 at all
  })
})
