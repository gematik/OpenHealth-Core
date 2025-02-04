import { fileURLToPath, URL } from 'node:url'

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import vueDevTools from 'vite-plugin-vue-devtools'
import { viteStaticCopy } from 'vite-plugin-static-copy'
import tailwindcss from '@tailwindcss/vite'


// https://vite.dev/config/
export default defineConfig({
  plugins: [
    vue(),
    vueDevTools(),
    viteStaticCopy({
      targets: [
        {
          src: 'node_modules/gematik-oh-openssl/lib/openssl.wasm',
          dest: 'assets'
        }
      ]
    }),
    tailwindcss()
  ],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
      'openssl.wasm': fileURLToPath(new URL('assets/openssl.wasm', import.meta.url))
    },
  },
})
