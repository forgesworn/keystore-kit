# Changelog

## 0.2.1 - 2026-08-20

- Release plumbing only, no code change: `publishConfig.provenance`, the
  anvil release workflow, and RELEASING.md. 0.2.0 was tagged before that
  plumbing existed, so the first published version is this one.

## 0.2.0 - 2026-08-20

- Independent PIN and biometric slots: `setupBiometric`/`enableBiometric` no longer overwrite the PIN wrap, so both methods stay usable at once. Legacy single-slot data still unlocks and migrates on re-enable.
- The non-PRF device-bound fallback now requires explicit opt-in (`{ allowDeviceFallback: true }`); without it, PRF-less authenticators return `ok: false, reason: 'prf-unsupported'` and nothing is written — no more silent downgrade to a storage-derivable wrap.
- `SetupBiometricResult` is now a discriminated union (`prfSupported: true` / `fallback: 'device'` / failure with `reason`), so callers cannot miss which wrap they got.
- 83 tests, coverage gates met; README and llms.txt updated for the new posture.

## 0.1.0 - 2026-07-18

- Extract keystore-kit — curve-agnostic browser key-at-rest — from signet-app.
- Pin git installs to reproducible commit references.
