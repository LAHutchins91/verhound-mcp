import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    fileParallelism: false,
    hookTimeout: 120000,
    testTimeout: 120000,
    env: {
      AUTH_SECRET: "test-signing-secret-not-for-production",
      NODE_ENV: "test",
      WEBHOOK_ENC_KEY: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="
    }
  }
});
