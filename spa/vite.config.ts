import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// Base path constant: a project repo at github.com/<user>/equilibrium publishes
// to https://<user>.github.io/equilibrium/, so all asset URLs need this prefix.
const GITHUB_PAGES_BASE = "/equilibrium/";

export default defineConfig({
  base: GITHUB_PAGES_BASE,
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    host: "0.0.0.0",
    port: 5173,
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
