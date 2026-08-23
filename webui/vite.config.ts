import path from 'node:path';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { '@': path.resolve(__dirname, 'src') } },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined;
          if (/[/\\](react(?:-dom)?|scheduler|react-is)[/\\]/.test(id))
            return 'vendor-react';
          if (/react-markdown|remark-|rehype-|micromark|mdast|hast/.test(id))
            return 'vendor-markdown';
          if (/lucide-react|@radix-ui|sonner/.test(id)) return 'vendor-ui';
          return undefined;
        },
      },
    },
  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8080',
      '/agentscope': 'http://127.0.0.1:8080',
      '/auth': 'http://127.0.0.1:8080',
      '/uploads': 'http://127.0.0.1:8080',
    },
  },
});
