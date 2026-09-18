import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// In development, /api calls are forwarded to the FastAPI backend.
export default defineConfig({
  build: { chunkSizeWarningLimit: 1000 },
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: { "/api": process.env.VITE_API_PROXY || "http://127.0.0.1:8000" },
  },
});
