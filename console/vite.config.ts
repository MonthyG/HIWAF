import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The build lands in the manager's embed directory; `npm run dev` proxies the
// API to a manager on https://localhost:9443 (override with HIWAF_API).
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../manager/console/dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 2000,
  },
  server: {
    proxy: {
      '/api': { target: process.env.HIWAF_API || 'https://localhost:9443', secure: false, changeOrigin: true },
    },
  },
})
