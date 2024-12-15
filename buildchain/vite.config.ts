import {defineConfig} from 'vite';
import {visualizer} from 'rollup-plugin-visualizer';
import viteEslintPlugin from 'vite-plugin-eslint';
import viteCompressionPlugin from 'vite-plugin-compression';
import viteRestartPlugin from 'vite-plugin-restart';
import viteStylelintPlugin from 'vite-plugin-stylelint';
import viteVuePlugin from '@vitejs/plugin-vue'
import * as path from 'path';

// https://vitejs.dev/config/
export default defineConfig(({command}) => ({
  base: command === 'serve' ? '' : '/dist/',
  build: {
    emptyOutDir: true,
    manifest: true,
    outDir: '../src/web/assets/dist',
    rollupOptions: {
      input: {
        strengthIndicator: 'src/js/indicator.ts',
      },
      output: {
        sourcemap: true
      },
    }
  },
  plugins: [
    viteRestartPlugin({
      reload: [
        '../src/templates/**/*',
      ],
    }),
    viteVuePlugin(),
    viteCompressionPlugin({
      filter: /\.(js|mjs|json|css|map)$/i
    }),
    visualizer({
      filename: '../src/web/assets/dist/stats.html',
      template: 'treemap',
      sourcemap: true,
    }),
    viteEslintPlugin({
      cache: false,
      fix: true,
    }),
    viteStylelintPlugin({
      fix: true,
      lintInWorker: true
    })
  ],
  resolve: {
    alias: [
      {find: '~', replacement: path.resolve(__dirname, './src')},
    ],
    preserveSymlinks: true,
  },
  server: {
    fs: {
      strict: false
    },
    host: '0.0.0.0',
    origin: 'http://localhost:' + process.env.DEV_PORT,
    port: parseInt(process.env.DEV_PORT),
    strictPort: true,
  }
}));
