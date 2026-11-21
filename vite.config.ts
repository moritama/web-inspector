/// <reference types="vitest" />
import { resolve } from 'node:path';
import { build, defineConfig, type InlineConfig, type Plugin } from 'vite';

/** content-script を IIFE で出す 2 段目のビルドの設定（v1.8.2 T02 / H6）。outDir は 1 段目と同じ出力先 */
export function contentScriptBuildConfig(outDir: string): InlineConfig {
  return {
    configFile: false, // vite.config.ts を読み直さない（プラグインの再帰と、1 段目の入力の混入を防ぐ）
    root: __dirname,
    publicDir: false, // public/ は 1 段目が写す
    logLevel: 'warn',
    build: {
      outDir,
      emptyOutDir: false,
      target: 'esnext',
      rollupOptions: {
        input: resolve(__dirname, 'src/content/content-script.ts'),
        output: {
          format: 'iife',
          inlineDynamicImports: true,
          entryFileNames: 'content/content-script.js',
        },
      },
    },
  };
}

/** 1 段目の書き出しの後に、2 段目（content-script の IIFE）をビルドする */
function contentScriptIifePlugin(): Plugin {
  let outDir = resolve(__dirname, 'dist');
  return {
    name: 'web-inspector-content-script-iife',
    apply: 'build',
    configResolved(config) {
      outDir = resolve(config.root, config.build.outDir);
    },
    async closeBundle() {
      await build(contentScriptBuildConfig(outDir));
    },
  };
}

export default defineConfig({
  plugins: [contentScriptIifePlugin()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'esnext',
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'popup.html'),
        dashboard: resolve(__dirname, 'dashboard.html'),
        'service-worker': resolve(__dirname, 'src/background/service-worker.ts'),
      },
      output: {
        entryFileNames: (chunkInfo) => {
          if (chunkInfo.name === 'service-worker') {
            return 'background/service-worker.js';
          }
          return 'assets/[name]-[hash].js';
        },
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]',
      },
    },
  },
  test: {
    setupFiles: ['tests/setup/advisory-db.ts'],
  },
});
