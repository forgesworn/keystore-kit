import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // Core runs on Node's Web Crypto. The browser adapter (localStorage/IndexedDB/WebAuthn)
    // is platform-only and exercised in a real browser, not here.
    include: ['src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      exclude: ['dist/**', 'src/index.ts', 'src/types.ts', 'src/browser.ts'],
      thresholds: {
        'src/aes.ts': { lines: 95, branches: 90, functions: 100, statements: 95 },
        'src/secret.ts': { lines: 95, branches: 90, functions: 100, statements: 95 },
        'src/keystore.ts': { lines: 90, branches: 80, functions: 95, statements: 90 },
        'src/memory-storage.ts': { lines: 95, branches: 85, functions: 100, statements: 95 }
      }
    }
  }
})
