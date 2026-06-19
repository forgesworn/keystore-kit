# keystore-kit

> Browser key-at-rest: protect one opaque secret behind a **PIN**, a **WebAuthn-PRF** biometric, or a short-lived **grace** key — with pluggable storage and a **burn-it-all** wipe. Curve-agnostic, pure Web Crypto, **zero runtime dependencies**.

A small building block for any web/PWA app that holds a private key on-device. The secret it protects is an **opaque string** — a random hex key, an `nsec`, a Curve25519/Ed25519 secret — so the keystore is **curve-agnostic**: it never interprets what it guards.

Extracted from the audited [`signet-app`](https://github.com/forgesworn/signet-app) `auth.ts` (last reviewed 2026-03-16), with its three couplings — `localStorage`, the IndexedDB grace store, and the hardcoded RP-id / PRF salt / app name — replaced by injected seams. **The crypto is unchanged from the reviewed source.**

## What's in it

| Export | What |
|--------|------|
| `Keystore` | The protector: `setupPIN`/`unlockPIN`, `setupBiometric`/`unlockBiometric`, `setupGrace`/`unlockGrace`, `changePIN`, `enableBiometric`/`disableBiometric`, `endGraceWith…`, `burn`, `generateSecret`. |
| `KeystoreStorage` | Persistence seam — string KV (localStorage-shaped) + the grace `CryptoKey` (IndexedDB-shaped). |
| `WebAuthnProvider` | WebAuthn seam — mock it in tests, or use `browserWebAuthn()`. Omit it to disable biometric. |
| `KeystoreConfig` | `{ rpId, rpName, prfSalt, hkdfInfo?, namespace? }`. |
| `InMemoryKeystoreStorage` | Storage for Node / tests / ephemeral sessions. |
| `browserStorage()` / `browserWebAuthn()` | Real PWA adapters (localStorage + IndexedDB; `navigator.credentials`). **Browser-only.** |
| `encryptSecret` / `decryptSecret` / `isEncrypted` | The standalone "protect a secret under a passphrase" primitive (self-describing wire format). |
| `deriveAesKey` / `aesEncrypt` / `aesDecrypt` | The raw AES-256-GCM + PBKDF2 helpers. |

## Security posture

- **PBKDF2-SHA-256, 600,000 iterations** (OWASP 2023) → **AES-256-GCM**.
- **WebAuthn-PRF** path derives the wrapping key from the authenticator hardware (HKDF over the PRF output); falls back to a credential-id-derived key if PRF is absent — still biometric-gated, but weaker (`SetupBiometricResult.prfSupported: false` flags it; surface that to the user).
- **Grace** wraps the secret under a non-extractable `CryptoKey` held in storage — a short unlock that survives a page-wake but not a wipe.
- **`burn()`** clears every blob and the grace key.
- The browser adapters (`browserStorage`/`browserWebAuthn`) touch `localStorage`/`indexedDB`/`navigator` and so are exercised in a real browser, not the unit suite, which runs the core over Node's Web Crypto with `InMemoryKeystoreStorage` + a mock provider.

## Curve-agnostic by design

The secret is never parsed, so this kit serves **both** a secp256k1 Nostr app (pass an `nsec`/hex) **and** a Noise-based app whose keys are Curve25519/Ed25519 (pass that secret). A BIP39-mnemonic → secp256k1 derivation adapter is a deliberate follow-up — it is *not* in this core, to keep the package dependency-free and curve-neutral.

## Use

```ts
import { Keystore, browserStorage, browserWebAuthn } from 'keystore-kit'

const ks = new Keystore(
  browserStorage(),
  { rpId: location.hostname, rpName: 'My App', prfSalt: APP_PRF_SALT /* 32 app-constant bytes */ },
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

```bash
npm install   # nothing — zero runtime deps
npm test      # vitest, per-file coverage gates
npm run build # tsc → dist/
```

> ESM-only, target ES2022, Node16 module resolution, `lib: DOM` (Web Crypto / WebAuthn / IndexedDB). British English throughout.
