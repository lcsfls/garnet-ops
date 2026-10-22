import { defineConfig, devices } from "@playwright/test";
import { E2E } from "./e2e/env.ts";

/**
 * End-to-end tests against the production build (`vite preview`, which sends
 * the real Content Security Policy) and a real API on a throw-away database.
 * Requires the embedded development PostgreSQL to be running (`pnpm dev`).
 */
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: "list",
  use: {
    baseURL: E2E.publicUrl,
    trace: "retain-on-failure",
  },
  projects: [
    // The full sign-in flow runs once (first-run setup only works on an empty database) and stores a session.
    {
      name: "auth-flow",
      testMatch: /auth\.spec\.ts/,
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1920, height: 1080 },
        locale: "en-US",
        timezoneId: "Europe/Berlin",
      },
    },
    // Signed-in screens on seeded fixture data.
    {
      name: "app",
      testMatch: /app\.spec\.ts/,
      dependencies: ["auth-flow"],
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1920, height: 1080 },
        locale: "en-US",
        timezoneId: "Europe/Berlin",
      },
    },
    // In-app updates against the fake sidecar (ADR 0007).
    {
      name: "updates",
      testMatch: /updates\.spec\.ts/,
      dependencies: ["app"],
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1920, height: 1080 },
        locale: "en-US",
        timezoneId: "Europe/Berlin",
      },
    },
    // The account page with its own member: password, second factor, passkeys (virtual authenticator), sessions, recovery.
    {
      name: "account",
      testMatch: /account\.spec\.ts/,
      dependencies: ["updates"],
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1920, height: 1080 },
        locale: "en-US",
        timezoneId: "Europe/Berlin",
      },
    },
    // Personal notifications (ADR 0019): the bell, the stream, toasts and the matrix on the account page.
    {
      name: "notifications",
      testMatch: /notifications\.spec\.ts/,
      dependencies: ["account"],
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1920, height: 1080 },
        locale: "en-US",
        timezoneId: "Europe/Berlin",
      },
    },
    // Directory sign-in (ADR 0020): the settings, directory accounts, mandatory second factor, linking, pinning.
    {
      name: "directory",
      testMatch: /directory\.spec\.ts/,
      dependencies: ["notifications"],
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1920, height: 1080 },
        locale: "en-US",
        timezoneId: "Europe/Berlin",
      },
    },
    // Layout baseline (AGENTS.md rule 5): 1080p at 100 %, 125 % and 150 % Windows scaling,
    // a small 1100 px window, and 1440p, where the xwide step (more columns and panes) starts.
    ...[
      { width: 1920, height: 1080 },
      { width: 1536, height: 864 },
      { width: 1280, height: 720 },
      // A small window next to the wider sidebar: the help moves below the form here.
      { width: 1100, height: 800 },
      { width: 2560, height: 1440 },
    ].map((viewport) => ({
      name: `layout-${viewport.width}x${viewport.height}`,
      testMatch: /layout\.spec\.ts/,
      dependencies: ["directory"],
      use: { ...devices["Desktop Chrome"], viewport, locale: "en-US", timezoneId: "Europe/Berlin" },
    })),
  ],
  webServer: [
    // The update sidecar's API, faked; it writes the token file the API reads (ADR 0007).
    {
      command: "node e2e/fake-updater.ts",
      url: `http://127.0.0.1:${E2E.updaterPort}/public/v1/status`,
      reuseExistingServer: false,
      timeout: 30_000,
    },
    {
      command: "node e2e/reset-db.ts && corepack pnpm --filter @garnetops/api start",
      url: `http://127.0.0.1:${E2E.apiPort}/api/health`,
      reuseExistingServer: false,
      timeout: 60_000,
      env: {
        ...E2E.dev,
        NODE_ENV: "test",
        PORT: String(E2E.apiPort),
        PUBLIC_URL: E2E.publicUrl,
        DATABASE_URL: E2E.databaseUrl,
        GARNETOPS_SETUP_TOKEN: E2E.setupToken,
        UPDATER_URL: `http://127.0.0.1:${E2E.updaterPort}`,
        UPDATER_TOKEN_FILE: E2E.updaterTokenFile,
      },
    },
    // The AI part of the worker with a fake model server (ADR 0013). The real worker stays off: it
    // would also pick up the scans the other tests queue.
    {
      command: "corepack pnpm --filter @garnetops/worker exec tsx test/e2e-ai-worker.ts",
      url: `http://127.0.0.1:${E2E.modelPort}/v1/models`,
      reuseExistingServer: false,
      timeout: 60_000,
      env: {
        ...E2E.dev,
        NODE_ENV: "test",
        DATABASE_URL: E2E.databaseUrl,
        E2E_MODEL_PORT: String(E2E.modelPort),
      },
    },
    // The fix pull request part of the worker with a fake forge (ADR 0014).
    {
      command: "corepack pnpm --filter @garnetops/worker exec tsx test/e2e-forge-worker.ts",
      url: `http://127.0.0.1:${E2E.forgeControlPort}/state`,
      reuseExistingServer: false,
      timeout: 60_000,
      env: {
        ...E2E.dev,
        NODE_ENV: "test",
        DATABASE_URL: E2E.databaseUrl,
        E2E_FORGE_PORT: String(E2E.forgePort),
        E2E_FORGE_CONTROL_PORT: String(E2E.forgeControlPort),
      },
    },
    // The directory part of the worker with a fake Active Directory (ADR 0020).
    {
      command: "corepack pnpm --filter @garnetops/worker exec tsx test/e2e-directory-worker.ts",
      url: `http://127.0.0.1:${E2E.directoryControlPort}/state`,
      reuseExistingServer: false,
      timeout: 60_000,
      env: {
        ...E2E.dev,
        NODE_ENV: "test",
        DATABASE_URL: E2E.databaseUrl,
        E2E_DIRECTORY_PORT: String(E2E.directoryPort),
        E2E_DIRECTORY_CONTROL_PORT: String(E2E.directoryControlPort),
      },
    },
    {
      command: `corepack pnpm exec vite build && corepack pnpm exec vite preview --port ${E2E.webPort}`,
      url: E2E.publicUrl,
      reuseExistingServer: false,
      timeout: 120_000,
      env: { GARNETOPS_API_URL: `http://127.0.0.1:${E2E.apiPort}` },
    },
  ],
});
