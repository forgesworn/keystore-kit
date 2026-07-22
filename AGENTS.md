# AGENTS.md — keystore-kit

Instructions in this file apply to the entire repository.

## Project Summary
- Curve-agnostic, zero-runtime-dependency TypeScript library for browser key-at-rest.
- Protects one opaque secret behind a PIN, a WebAuthn-PRF biometric, or a short-lived grace key; pluggable storage; irreversible burn.
- Extracted from the audited `signet-app` `auth.ts` (last reviewed 2026-03-16) — the crypto is unchanged from the reviewed source.
- ESM-only package (`"type": "module"`).
- Requires Node.js 18+.

## Key Commands
- `npm run build` — compile TypeScript into `dist/`
- `npm test` — run the Vitest suite
- `npm run test:watch` — run tests in watch mode
- `npm run test:coverage` — run tests with per-file coverage thresholds enforced (see `vitest.config.ts`)
- `npm run typecheck` — TypeScript type-check without emitting

## Repository Structure
- `src/aes.ts` — low-level AES-256-GCM + PBKDF2 helpers over Web Crypto
- `src/secret.ts` — `encryptSecret`/`decryptSecret`/`isEncrypted`, the standalone passphrase-protection primitive
- `src/keystore.ts` — the `Keystore` class: PIN, WebAuthn-PRF biometric, grace, burn
- `src/memory-storage.ts` — `InMemoryKeystoreStorage`, for Node/tests/ephemeral sessions
- `src/browser.ts` — `browserStorage()`/`browserWebAuthn()`, the real PWA adapters (localStorage/IndexedDB/`navigator.credentials`) — platform-only, excluded from unit coverage by design
- `src/types.ts` — `KeystoreStorage`, `WebAuthnProvider`, `KeystoreConfig`, and related types
- `src/index.ts` — barrel re-export (the only public entry point; no subpath exports)
- `dist/` — build output (generated)

## Coding Conventions
- Use British English spelling in identifiers and prose: `licence`, `colour`, `behaviour`.
- Preserve the zero-runtime-dependency approach and the pure-Web-Crypto boundary (no Node-only crypto APIs) unless the user explicitly asks otherwise.
- Keep changes minimal and consistent with the existing module layout — one concern per file.
- Prefer TDD when changing behaviour: add or update a failing test first, then implement.
- Maintain ESM-compatible imports/exports (`.js` extensions on relative imports, per Node16 module resolution).
- **Security:** never log, print, or otherwise surface key material, passphrases, PRF output, or decrypted secrets — not even in error messages or debug output. Failed unlocks should say *that* they failed, never *why* in a way that helps an attacker (the existing API already collapses "wrong PIN" and "corrupted blob" into the same `null` return — preserve that).
- **Security:** do not weaken the shipped crypto parameters (`PBKDF2_ITERATIONS`, key lengths, non-extractable key flags) without an explicit, reasoned request — these track OWASP guidance and downstream apps depend on them.

## Working Guidelines
- Do not edit generated output in `dist/` by hand unless the user explicitly asks for it.
- Prefer targeted tests for the area being changed before broader validation (e.g. `npx vitest run src/keystore.test.ts`).
- `src/browser.ts` is exercised in a real PWA, not the unit suite — if you change it, ask for or perform manual browser verification rather than assuming Node coverage proves it works.
- Update documentation (`README.md`, `llms.txt`) whenever the public API or security posture changes.
- Keep commits scoped to one logical change; this repo's history favours small, reviewable diffs.

## Release Notes
- Conventional commit prefixes matter for releases: `fix:` for patch, `feat:` for minor, and `BREAKING CHANGE:` for major.
- This repository does not yet have an automated release workflow (unlike some sibling ForgeSworn kits) — `.github/workflows/ci.yml` runs typecheck/test/build/`npm pack --dry-run` on every push and PR, but publishing to npm is manual today.
- Tests should pass before release-related changes are considered complete.
