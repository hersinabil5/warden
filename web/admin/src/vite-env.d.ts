/// <reference types="vite/client" />

interface ImportMetaEnv {
  // Showcase build only: link to a live Warden demo, shown in the banner.
  readonly VITE_LIVE_DEMO_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
