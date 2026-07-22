# CLAUDE.md — keystore-kit

Browser key-at-rest: protect a secret with PIN / WebAuthn-PRF / grace, pluggable storage, burn. Curve-agnostic, pure Web Crypto, zero runtime deps.

## Commands

- `npm run build` — compile TypeScript to dist/
- `npm test` — run all tests (vitest)
- `npm run test:watch` — watch mode
- `npm run test:coverage` — coverage with per-file thresholds enforced
- `npm run typecheck` — type-check without emitting

## Structure

- `src/aes.ts` — AES-256-GCM + PBKDF2 helpers over Web Crypto
- `src/secret.ts` — encryptSecret/decryptSecret/isEncrypted (standalone passphrase primitive)
- `src/keystore.ts` — the Keystore class (PIN, WebAuthn-PRF, grace, burn)
- `src/memory-storage.ts` — InMemoryKeystoreStorage (Node/tests/ephemeral)
- `src/browser.ts` — browserStorage()/browserWebAuthn() (real PWA adapters — browser-only, not unit-tested)
- `src/types.ts` — KeystoreStorage, WebAuthnProvider, KeystoreConfig, and related types
- `src/index.ts` — barrel re-export

## Exports

Single entry point, no subpath exports: `import { ... } from 'keystore-kit'`.

- `Keystore` — setupPIN/unlockPIN/changePIN, isBiometricAvailable/setupBiometric/unlockBiometric/enableBiometric/disableBiometric, setupGrace/unlockGrace/endGraceWithPin/endGraceWithBiometric, generateSecret/isSetUp/method/burn
- `InMemoryKeystoreStorage`, `browserStorage()`, `browserWebAuthn()` — storage/WebAuthn adapters
- `encryptSecret`, `decryptSecret`, `isEncrypted` — standalone passphrase-protection primitive
- `deriveAesKey`, `aesEncrypt`, `aesDecrypt`, `PBKDF2_ITERATIONS`, `SALT_LENGTH`, `IV_LENGTH` — raw AES-GCM/PBKDF2 helpers and constants
- Types: `KeystoreStorage`, `WebAuthnProvider`, `KeystoreConfig`, `UnlockMethod`, `SetupBiometricResult`, `GraceKeyRecord`

## Conventions

- **British English** — colour, licence, behaviour
- **Zero dependencies** — no runtime deps, only vitest + typescript (+ coverage-v8) as dev deps
- **ESM-only** — `"type": "module"` in package.json; `.js` extensions on relative imports (Node16 resolution)
- **TDD** — write failing test first, then implement
- **Security** — never log/print key material, passphrases, PRF output or decrypted secrets; don't weaken `PBKDF2_ITERATIONS` or non-extractable key flags without an explicit, reasoned request
- **Git:** commit messages use `type: description` format
- **Git:** Do NOT include `Co-Authored-By` lines in commits

## Release & Versioning

No automated release workflow yet. `.github/workflows/ci.yml` runs `typecheck` → `test` → `build` → `npm pack --dry-run` on every push to `main`/`dev`/`feat/**`/`fix/**`/`chore/**` and on PRs into `main`/`dev`. Publishing to npm is manual:

1. Bump `package.json` version by hand (e.g. `0.1.0` → `0.2.0`)
2. Add a `CHANGELOG.md` entry under the new version heading
3. Commit (`chore: release 0.2.0`), push main
4. Tag the commit (`git tag v0.2.0 && git push --tags`)
5. `npm publish`

Semver rules of thumb:

| Change | Bump |
|---|---|
| Bug fix, no API change | Patch (0.1.x) |
| New feature, backwards compatible | Minor (0.x.0) |
| Breaking API change | Major (x.0.0) |
| Tooling, docs, refactor with no behaviour change | Patch or none |

If this repo adopts the `forgesworn/anvil` release workflow that sibling kits use (see `geohash-kit/.github/workflows/release.yml` for the pattern), update this section to match.
