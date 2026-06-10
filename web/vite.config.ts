import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import fs from "node:fs";

const DIST_DATA_FILES: Record<string, string> = {
  "/data/knowledge-bundle.json": "knowledge-bundle.json",
  "/data/promoted-edges.json": "promoted-edges.json",
};

/**
 * Dev-only middleware that serves data/dist/*.json directly so the 30MB
 * bundle never has to be copied into web/public during local development.
 * `make web-build` copies these files into public/data/ for production.
 */
function devBundlePlugin(): Plugin {
  const distDir = path.resolve(__dirname, "..", "data", "dist");
  return {
    name: "cvezd3fend-dev-bundle",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = req.url?.split("?")[0];
        const fileName = url ? DIST_DATA_FILES[url] : undefined;
        if (!fileName) return next();
        const filePath = path.join(distDir, fileName);
        if (!fs.existsSync(filePath)) return next();
        res.setHeader("Content-Type", "application/json");
        fs.createReadStream(filePath).pipe(res);
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), devBundlePlugin()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  server: {
    port: 5173,
    fs: {
      allow: [".."],
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
