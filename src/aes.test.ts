import { describe, it, expect } from 'vitest'
import { deriveAesKey, aesEncrypt, aesDecrypt, PBKDF2_ITERATIONS, SALT_LENGTH, IV_LENGTH } from './aes.js'

describe('aes', () => {
  it('round-trips a string through derive → encrypt → decrypt', async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const key = await deriveAesKey('correct horse', salt)
    const { iv, ciphertext } = await aesEncrypt('attack at dawn', key)
    expect(await aesDecrypt(iv, ciphertext, key)).toBe('attack at dawn')
  })

  it('fails to decrypt under a key derived from a different passphrase', async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const good = await deriveAesKey('right', salt)
    const bad = await deriveAesKey('wrong', salt)
    const { iv, ciphertext } = await aesEncrypt('secret', good)
    await expect(aesDecrypt(iv, ciphertext, bad)).rejects.toThrow()
  })

  it('fails to decrypt under a key derived from a different salt (same passphrase)', async () => {
    const passphrase = 'same passphrase'
    const saltA = crypto.getRandomValues(new Uint8Array(16))
    const saltB = crypto.getRandomValues(new Uint8Array(16))
    const keyA = await deriveAesKey(passphrase, saltA)
    const keyB = await deriveAesKey(passphrase, saltB)
    const { iv, ciphertext } = await aesEncrypt('secret', keyA)
    await expect(aesDecrypt(iv, ciphertext, keyB)).rejects.toThrow()
  })

  it('fails to decrypt tampered ciphertext (GCM tag mismatch)', async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const key = await deriveAesKey('pw', salt)
    const { iv, ciphertext } = await aesEncrypt('msg', key)
    ciphertext[0] ^= 0xff
    await expect(aesDecrypt(iv, ciphertext, key)).rejects.toThrow()
  })

  it('fails to decrypt when the IV has been tampered with', async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const key = await deriveAesKey('pw', salt)
    const { iv, ciphertext } = await aesEncrypt('msg', key)
    iv[0] ^= 0xff
    await expect(aesDecrypt(iv, ciphertext, key)).rejects.toThrow()
  })

  it('produces a non-extractable AES-256-GCM key', async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const key = await deriveAesKey('pw', salt)
    expect(key.extractable).toBe(false)
    expect(key.algorithm).toMatchObject({ name: 'AES-GCM', length: 256 })
    expect(key.usages.sort()).toEqual(['decrypt', 'encrypt'])
  })

  it('encrypts the same plaintext under the same key to different ciphertext each time (random IV)', async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const key = await deriveAesKey('pw', salt)
    const a = await aesEncrypt('same message', key)
    const b = await aesEncrypt('same message', key)
    expect(a.iv).not.toEqual(b.iv)
    expect(Array.from(a.ciphertext)).not.toEqual(Array.from(b.ciphertext))
    // Both still decrypt correctly under their own IV.
    expect(await aesDecrypt(a.iv, a.ciphertext, key)).toBe('same message')
    expect(await aesDecrypt(b.iv, b.ciphertext, key)).toBe('same message')
  })

  it('locks in the documented crypto parameters (regression guard against silent weakening)', () => {
    expect(PBKDF2_ITERATIONS).toBe(600_000) // OWASP 2023 recommendation for PBKDF2-SHA-256
    expect(SALT_LENGTH).toBe(16)
    expect(IV_LENGTH).toBe(12) // standard AES-GCM nonce size
  })
})
