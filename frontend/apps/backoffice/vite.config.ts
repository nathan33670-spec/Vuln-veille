/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const api = "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: { "/api": api, "/healthz": api, "/readyz": api },
  },
  build: {
    // The polyfill injects inline code, which the production CSP forbids.
    modulePreload: { polyfill: false },
    sourcemap: false,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
  },
});
