import { describe, it, expect } from 'vitest'
import { deriveAesKey, aesEncrypt, aesDecrypt } from './aes.js'

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

  it('fails to decrypt tampered ciphertext (GCM tag mismatch)', async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const key = await deriveAesKey('pw', salt)
    const { iv, ciphertext } = await aesEncrypt('msg', key)
    ciphertext[0] ^= 0xff
    await expect(aesDecrypt(iv, ciphertext, key)).rejects.toThrow()
  })
})
