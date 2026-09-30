import { defineConfig, devices } from "@playwright/test";

/**
 * End-to-end verification for the review surface.
 *
 * Two servers, no Docker and no mocking. The browser talks to a real Next
 * server, which talks to a real FastAPI server, which runs the real engine over
 * the real fixtures. That is the whole point: the thing worth verifying is that
 * a finding produced by a Python rule arrives on a screen unchanged, and a
 * mocked API would verify the mock instead.
 *
 * `workers: 1` and `retries: 0`. Determinism is the goal, and a retry turns an
 * intermittent failure -- the kind that matters here, where a page might render
 * a stale finding -- into a pass.
 */

const FRONTEND = "http://localhost:3000";
const BACKEND = "http://127.0.0.1:8000";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: !!process.env.CI,
  reporter: [["list"]],

  use: {
    baseURL: FRONTEND,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },

  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],

  webServer: [
    {
      // The engine's own truth. Started from `backend/` so `data/` resolves to
      // the repository's fixture directory rather than to the frontend's.
      command: "uv run uvicorn app.main:app --host 127.0.0.1 --port 8000",
      cwd: "../backend",
      url: `${BACKEND}/api/health`,
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
      stdout: "ignore",
      stderr: "pipe",
    },
    {
      // Probed at `/`, which exists in both the Phase 1 and Phase 3 layouts, so
      // readiness never depends on a route that is itself under construction.
      command: "npm run dev -- --port 3000",
      cwd: ".",
      url: FRONTEND,
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
      stdout: "ignore",
      stderr: "pipe",
    },
  ],
});
