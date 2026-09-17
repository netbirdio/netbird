import path from "path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import wails from "@wailsio/runtime/plugins/vite";

// https://vitejs.dev/config/
export default defineConfig({
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
      "@bindings": path.resolve(
        __dirname,
        "./bindings/github.com/netbirdio/netbird/client/ui",
      ),
    },
  },
  plugins: [react(), wails("./bindings")],
  server: {
    host: "127.0.0.1",
    port: 9245,
    strictPort: true,
    fs: {
      // The i18n bundles live at ../i18n/locales (shared with the Go tray).
      // Whitelist the parent dir so Vite's dev server serves them.
      allow: [path.resolve(__dirname, ".."), __dirname],
    },
  },
});
