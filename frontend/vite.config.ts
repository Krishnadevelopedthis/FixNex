import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"
import path from "node:path"

const rootDir = import.meta.dirname

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": path.resolve(rootDir, "./src") } },
  server: {
    port: 5173,
    proxy: {
      // The API and its scan-progress WebSocket are proxied in development so
      // the browser only ever talks to one origin.
      "/api": { target: "http://localhost:8000", changeOrigin: true, ws: true },
    },
  },
  build: {
    // Charting and the Radix primitives dominate the bundle; splitting them
    // keeps the app shell small and cacheable across deploys.
    rollupOptions: {
      output: {
        manualChunks(id: string) {
          if (!id.includes("node_modules")) return
          // Checked before the React rule: the package path "@xyflow/react"
          // would otherwise be swept into the React chunk.
          if (id.includes("@xyflow")) return "flow"
          if (id.includes("recharts") || id.includes("d3-")) return "charts"
          if (id.includes("react-router") || id.includes("/react-dom/") || id.includes("/react/")) return "react"
          if (id.includes("@tanstack") || id.includes("axios")) return "query"
          if (id.includes("@radix-ui")) return "radix"
        },
      },
    },
    chunkSizeWarningLimit: 700,
  },
})
