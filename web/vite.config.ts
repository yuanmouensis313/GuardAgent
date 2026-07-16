import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: "/ui/",
  plugins: [react()],
  build: {
    outDir: "../guardd/ui/static",
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        manualChunks: {
          editor: ["@uiw/react-codemirror", "@codemirror/lang-yaml"],
          react: ["react", "react-dom", "react-router-dom", "@tanstack/react-query"]
        }
      }
    }
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/v1": "http://127.0.0.1:8787"
    }
  }
});
