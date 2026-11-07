/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Backend origin, e.g. https://logjack-1.onrender.com. Leave unset for same-origin (local dev proxy). */
  readonly VITE_API_BASE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
