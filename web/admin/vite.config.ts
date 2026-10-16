import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Served by Warden at /.warden/admin/ from the embedded dist/ (go:embed).
// The CSP allows only same-origin script and style files, so the build must
// not emit anything inline: no module-preload polyfill, no inlined assets.
export default defineConfig({
  base: "/.warden/admin/",
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    sourcemap: false,
  },
});
