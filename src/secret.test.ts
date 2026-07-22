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

  it('rejects decryption of non-base64 garbage rather than returning silently-wrong plaintext', async () => {
    await expect(decryptSecret('!!!not-base64!!!', 'pass')).rejects.toThrow()
  })

  it('produces different ciphertext for the same plaintext and passphrase each call (random salt + iv)', async () => {
    const a = await encryptSecret('same secret', 'same pass')
    const b = await encryptSecret('same secret', 'same pass')
    expect(a).not.toBe(b)
    // Both still round-trip correctly under the same passphrase.
    expect(await decryptSecret(a, 'same pass')).toBe('same secret')
    expect(await decryptSecret(b, 'same pass')).toBe('same secret')
  })

  it('rejects a tampered payload (flipped byte in the ciphertext region)', async () => {
    const enc = await encryptSecret('my-nsec-or-key-hex', 'pass')
    const bytes = Uint8Array.from(atob(enc), (c) => c.charCodeAt(0))
    bytes[bytes.length - 1] ^= 0xff // flip a byte inside the GCM-tagged ciphertext
    const tampered = btoa(String.fromCharCode(...bytes))
    await expect(decryptSecret(tampered, 'pass')).rejects.toThrow()
  })
})
