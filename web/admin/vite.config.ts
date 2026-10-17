import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Two builds of one app (docs/DECISIONS.md D24, D31):
// - default: served by Warden at /.warden/admin/ from the embedded dist/
//   (go:embed), talking to the real admin API;
// - --mode showcase: a static site in dist-showcase/ for Vercel, with the
//   API transport swapped for sample data at build time, so none of it
//   reaches the embedded build.
// Both are served under a CSP that allows only same-origin script and style
// files, so the build must not emit anything inline: no module-preload
// polyfill, no inlined assets.
export default defineConfig(({ mode }) => {
  const showcase = mode === "showcase";
  return {
    base: showcase ? "/" : "/.warden/admin/",
    plugins: [react()],
    resolve: {
      alias: showcase
        ? [{ find: /^\.\/backend$/, replacement: fileURLToPath(new URL("./src/showcase/backend.ts", import.meta.url)) }]
        : [],
    },
    build: {
      outDir: showcase ? "dist-showcase" : "dist",
      emptyOutDir: true,
      modulePreload: { polyfill: false },
      assetsInlineLimit: 0,
      sourcemap: false,
    },
  };
});
