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
        "./bindings/github.com/netbirdio/netbird/client/ui-wails",
      ),
    },
  },
  plugins: [react(), wails("./bindings")],
  server: {
    port: 9245,
    strictPort: true,
  },
});
