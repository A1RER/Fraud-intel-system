import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // 开发时把 /api 请求转发到 FastAPI，避免跨域问题
    proxy: {
      '/api': 'http://localhost:8000',
    },
  },
})
