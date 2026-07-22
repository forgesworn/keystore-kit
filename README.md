# keystore-kit

![zero deps](https://img.shields.io/badge/dependencies-0-brightgreen)
![TypeScript](https://img.shields.io/badge/TypeScript-native-blue)
![licence](https://img.shields.io/badge/licence-MIT-blue)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/TheCryptoDonkey?logo=githubsponsors&color=ea4aaa&label=Sponsor)](https://github.com/sponsors/TheCryptoDonkey)

> Browser key-at-rest: protect one opaque secret behind a **PIN**, a **WebAuthn-PRF** biometric, or a short-lived **grace** key — with pluggable storage and a **burn-it-all** wipe. Curve-agnostic, pure Web Crypto, **zero runtime dependencies**.

A small building block for any web/PWA app that holds a private key on-device. The secret it protects is an **opaque string** — a random hex key, an `nsec`, a Curve25519/Ed25519 secret — so the keystore is **curve-agnostic**: it never interprets what it guards.

Extracted from the audited [`signet-app`](https://github.com/forgesworn/signet-app) `auth.ts` (last reviewed 2026-03-16), with its three couplings — `localStorage`, the IndexedDB grace store, and the hardcoded RP-id / PRF salt / app name — replaced by injected seams. **The crypto is unchanged from the reviewed source.**

## Why keystore-kit?

- **Curve-agnostic** — the protected secret is never parsed, so the same package serves a secp256k1 Nostr app (`nsec`/hex) and a Noise-based app with Curve25519/Ed25519 keys.
- **Audited crypto lineage** — the PBKDF2/AES-GCM and WebAuthn-PRF logic is lifted verbatim from a reviewed production keystore, not written fresh for this package.
- **Pluggable everywhere** — storage (`KeystoreStorage`) and WebAuthn (`WebAuthnProvider`) are injected seams, so the core is unit-tested on Node's Web Crypto with in-memory fakes, while `browserStorage()`/`browserWebAuthn()` supply the real PWA adapters.
- **Zero runtime dependencies** — pure Web Crypto (`crypto.subtle`), no third-party crypto libraries to audit or update.
- **Tested failure modes, not just happy paths** — wrong PIN, tampered ciphertext, absent PRF, cancelled biometric prompts, cleared/shared grace slots, and burn are all exercised, not just successful unlocks.

## Install

```bash
npm install keystore-kit
```

## Quick Start

```typescript
import { Keystore, browserStorage, browserWebAuthn } from 'keystore-kit'

const ks = new Keystore(
  browserStorage(),
  { rpId: location.hostname, rpName: 'My App', prfSalt: APP_PRF_SALT }, // 32 app-constant bytes
  browserWebAuthn(),
)

// First run: protect a freshly generated (or your own) secret.
const secret = ks.generateSecret()            // or your Curve25519/Ed25519 key as hex
await ks.setupPIN('123456', secret)
if (await ks.isBiometricAvailable()) await ks.enableBiometric(secret)

// Later: unlock.
const recovered = await ks.unlockBiometric() ?? await ks.unlockPIN(pin)

// Wipe everything.
await ks.burn()
```

Node.js and tests use the same API over `InMemoryKeystoreStorage` — no browser globals required:

```typescript
import { Keystore, InMemoryKeystoreStorage } from 'keystore-kit'

const config = { rpId: 'localhost', rpName: 'Test', prfSalt: new Uint8Array(32) }
const ks = new Keystore(new InMemoryKeystoreStorage(), config)

await ks.setupPIN('123456', ks.generateSecret())
await ks.unlockPIN('123456') // → the secret, or null if the PIN is wrong
```

Need only "encrypt this string under a passphrase", with no storage or lifecycle at all?

```typescript
import { encryptSecret, decryptSecret } from 'keystore-kit'

const enc = await encryptSecret('my-nsec-or-key-hex', 'a-passphrase')
const plain = await decryptSecret(enc, 'a-passphrase') // throws on the wrong passphrase or a tampered payload
```

## API Reference

### `Keystore`

`new Keystore(storage: KeystoreStorage, config: KeystoreConfig, webauthn?: WebAuthnProvider)`

| Method | Description |
|--------|-------------|
| `generateSecret()` | Random 256-bit secret as a 64-char hex string |
| `isSetUp()` | Has any unlock method been configured? |
| `method()` | Current `UnlockMethod` (`'pin' \| 'biometric' \| 'grace'`) or `null` |
| `burn()` | Wipe every blob and the grace key — irreversible |

**PIN:**

| Method | Description |
|--------|-------------|
| `setupPIN(passphrase, secret)` | Protect `secret` behind a passphrase (PBKDF2 → AES-GCM) |
| `unlockPIN(passphrase)` | Recover the secret, or `null` on the wrong passphrase / not set up |
| `changePIN(current, next)` | Re-wrap under a new passphrase; `false` if `current` is wrong |

**Biometric (WebAuthn-PRF):**

| Method | Description |
|--------|-------------|
| `isBiometricAvailable()` | Is a user-verifying platform authenticator available? |
| `setupBiometric(secret)` | Protect `secret` behind a platform biometric; returns `{ ok, prfSupported }` |
| `unlockBiometric()` | Recover the secret via biometric, or `null` on failure/abort |
| `enableBiometric(secret)` | Alias for `setupBiometric` |
| `disableBiometric(secret, newPassphrase)` | Drop the credential, re-wrap under a PIN |

**Grace (short-lived, no-prompt unlock):**

| Method | Description |
|--------|-------------|
| `setupGrace(secret)` | Wrap `secret` under a non-extractable in-storage `CryptoKey` |
| `unlockGrace()` | Recover the secret via the grace handle, or `null` if absent/cleared |
| `endGraceWithPin(passphrase, secret)` | Re-wrap under a PIN, then clear the grace key (atomic — only clears on success) |
| `endGraceWithBiometric(secret)` | Re-wrap under biometric, then clear the grace key; throws if biometric setup fails (grace left intact) |

### Storage & WebAuthn adapters

| Export | Description |
|--------|-------------|
| `InMemoryKeystoreStorage` | For Node, tests, and ephemeral sessions. Nothing survives process exit |
| `browserStorage()` | Real PWA adapter: `localStorage` (string KV) + IndexedDB (grace key). **Browser-only** |
| `browserWebAuthn()` | Real PWA adapter over `navigator.credentials`, requesting the PRF extension. **Browser-only** |
| `KeystoreStorage` | Type to implement for another platform: string KV + async grace-key methods |
| `WebAuthnProvider` | Type to implement for another platform: `isAvailable`/`createCredential`/`getPRF`/`assert` |
| `KeystoreConfig` | `{ rpId, rpName, prfSalt, hkdfInfo?, namespace? }` |

### Standalone primitives

| Export | Description |
|--------|-------------|
| `encryptSecret(plaintext, passphrase)` | Self-describing wire format: `base64(salt‖iv‖ciphertext)` |
| `decryptSecret(encrypted, passphrase)` | Throws on the wrong passphrase or a malformed/tampered payload |
| `isEncrypted(value)` | Heuristic check that a string looks like `encryptSecret` output |
| `deriveAesKey(passphrase, salt)` | PBKDF2-SHA-256 (600,000 iterations) → non-extractable AES-256-GCM `CryptoKey` |
| `aesEncrypt(plaintext, key)` | → `{ iv, ciphertext }` with a random 96-bit IV |
| `aesDecrypt(iv, ciphertext, key)` | Throws on the wrong key or a tampered ciphertext (GCM tag check) |
| `PBKDF2_ITERATIONS` / `SALT_LENGTH` / `IV_LENGTH` | `600000` / `16` / `12` |

## Security Model

**PBKDF2-SHA-256, 600,000 iterations** (OWASP 2023 recommendation) → **AES-256-GCM**. All derived keys are non-extractable `CryptoKey`s.

What each unlock method protects against, and what it does not:

| Method | Protects against | Does **not** protect against |
|--------|-------------------|-------------------------------|
| **PIN** | Casual/opportunistic reads of the stored blob; tampering (GCM auth tag) | Offline brute force of a **short numeric PIN** — 600,000 PBKDF2 iterations slow guessing but cannot make a 4–6 digit keyspace strong. Prefer biometric or a longer passphrase where possible |
| **Biometric — PRF path** | Offline extraction of the stored blob: the wrapping key is derived from authenticator hardware output (HKDF), never stored | Loss/reset of the authenticator itself (no PRF ⇒ no key; there is no separate recovery path) |
| **Biometric — fallback path (no PRF)** | A live attacker without the authenticator (still gated by `assert()`) | **Offline extraction** — the credential id used as key material is stored in the same KV as the ciphertext in plaintext, so anyone who reads the raw storage can re-derive the key without ever touching the device. `SetupBiometricResult.prfSupported: false` flags this — surface it to the user and prefer PIN as the primary method on devices without PRF |
| **Grace** | Nothing beyond casual reads — `unlockGrace()` requires **no passphrase and no biometric check** at all. It exists purely to smooth over a page reload shortly after an explicit unlock | Anyone with script execution in the page, or read access to the grace store, for as long as the grace key is live. Call `burn()` or `endGraceWith…()` to close the window deliberately |
| **Burn** | — | Data already exfiltrated before `burn()` was called; it is a wipe, not a revocation |

Other things worth knowing:

- **Tampering is detected, not silently accepted.** AES-GCM's authentication tag makes a modified ciphertext fail to decrypt; the higher-level `Keystore` API turns that failure into a `null` return (never a distinguishable error) so callers can't tell "wrong PIN" from "corrupted blob" from the response shape alone.
- **The grace slot is per storage instance, not per namespace.** `KeystoreConfig.namespace` isolates PIN/biometric storage keys between multiple `Keystore`s sharing one storage backend, but `KeystoreStorage.saveGraceKey`/`getGraceKey` take no namespace — two keystores sharing a storage instance share one grace slot. Use one storage instance per app if independent grace windows are required.
- **The browser adapters are platform-only.** `browserStorage()`/`browserWebAuthn()` touch `localStorage`/`indexedDB`/`navigator` and so are exercised in a real browser, not the unit suite, which runs the core over Node's Web Crypto with `InMemoryKeystoreStorage` and a mock `WebAuthnProvider`.

## Curve-agnostic by design

The secret is never parsed, so this kit serves **both** a secp256k1 Nostr app (pass an `nsec`/hex) **and** a Noise-based app whose keys are Curve25519/Ed25519 (pass that secret). A BIP39-mnemonic → secp256k1 derivation adapter is a deliberate follow-up — it is *not* in this core, to keep the package dependency-free and curve-neutral.

## Development

```bash
npm install        # nothing to fetch — zero runtime deps
npm test            # vitest, per-file coverage gates
npm run test:coverage
npm run typecheck
npm run build       # tsc → dist/
```

> ESM-only, target ES2022, Node16 module resolution, `lib: DOM` (Web Crypto / WebAuthn / IndexedDB). British English throughout.

## For AI Assistants

See [llms.txt](./llms.txt) for a concise, machine-readable API summary.

## Part of the ForgeSworn Toolkit

[ForgeSworn](https://forgesworn.dev) builds open-source cryptographic identity, payments, and coordination tools for Nostr.

| Library | What it does |
|---------|-------------|
| [nsec-tree](https://github.com/forgesworn/nsec-tree) | Deterministic sub-identity derivation |
| [ring-sig](https://github.com/forgesworn/ring-sig) | SAG/LSAG ring signatures on secp256k1 |
| [range-proof](https://github.com/forgesworn/range-proof) | Pedersen commitment range proofs |
| [canary-kit](https://github.com/forgesworn/canary-kit) | Coercion-resistant spoken verification |
| [spoken-token](https://github.com/forgesworn/spoken-token) | Human-speakable verification tokens |
| [toll-booth](https://github.com/forgesworn/toll-booth) | L402 payment middleware |
| [geohash-kit](https://github.com/forgesworn/geohash-kit) | Geohash toolkit with polygon coverage |
| [keystore-kit](https://github.com/forgesworn/keystore-kit) | Curve-agnostic browser key-at-rest |
| [nostr-attestations](https://github.com/forgesworn/nostr-attestations) | NIP-VA verifiable attestations |
| [dominion](https://github.com/forgesworn/dominion) | Epoch-based encrypted access control |
| [rendezvous-kit](https://github.com/forgesworn/rendezvous-kit) | Fair meeting point discovery using isochrones |
| [nostr-veil](https://github.com/forgesworn/nostr-veil) | Privacy-preserving Web of Trust |

## Licence

[MIT](https://github.com/forgesworn/keystore-kit/blob/main/LICENSE)

## Support

- [GitHub Sponsors](https://github.com/sponsors/TheCryptoDonkey)
- [Ko-fi](https://ko-fi.com/brays)
- [Geyser](https://geyser.fund/project/forgesworn)

For issues and feature requests, see [GitHub Issues](https://github.com/forgesworn/keystore-kit/issues).
