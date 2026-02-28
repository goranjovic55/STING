import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 8701,
    proxy: {
      '/api': {
        target: 'http://localhost:8700',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:8700',
        ws: true,
      },
    },
  },
})
