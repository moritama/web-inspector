/**
 * content-script の IIFE 化（v1.8.2 T02 / B / H6、指示書 §5.1）
 *
 * dist/content/content-script.js は、今は先頭がトップレベルの const の ES モジュールの形で出ている。
 * chrome.scripting.executeScript({ files }) で同じフレームへ 2 回目を注入すると、パースの段階で
 * 「Identifier '...' has already been declared」の SyntaxError になり、二重注入の印に届かない。
 *
 * ここでは、
 *   - vite.config.ts のメインのビルドの入力から content-script が外れていること
 *   - 2 段目のビルドの設定 contentScriptBuildConfig(outDir) が IIFE・inlineDynamicImports・emptyOutDir: false であること
 *   - 実際にビルドした出力を、同じグローバル（node:vm の 1 つのコンテキスト）で 2 回実行しても
 *     SyntaxError にならず、メッセージリスナーが 1 回だけ登録されること
 *     （executeScript({ files }) は同じフレームの isolated world に classic script として評価するので、
 *       同じ vm コンテキストで 2 回 runInContext するのと同じく、トップレベルの const / let は 2 回目で重複宣言になる）
 *   - リポジトリの vite.config.ts で build すると（npm run build の vite build と同じ）、上の出力が dist の位置にでき、
 *     他の入口（popup・dashboard・service-worker）が消えず、サイズの上限（check-size）を超えないこと
 * を確かめる。ビルドの出力先は os.tmpdir() の一時ディレクトリで、リポジトリの dist には触らない。
 */
import { afterAll, describe, expect, it } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as vm from 'vm';
import { build, type InlineConfig, type UserConfig } from 'vite';
import { REPO_ROOT } from './helpers/release-version';
// @ts-expect-error scripts/ci/check-size.mjs は型定義を持たない .mjs モジュール
import { checkSizes } from '../scripts/ci/check-size.mjs';

const CONTENT_SCRIPT_SRC = fs.realpathSync(path.join(REPO_ROOT, 'src', 'content', 'content-script.ts'));
const GUARD_KEY = '__WEB_INSPECTOR_CONTENT_SCRIPT_INJECTED__';
const FIXTURE_DB = path.join(REPO_ROOT, 'tests', 'fixtures', 'advisory-db.fixture.json');

const tempDirs: string[] = [];
function makeTemp(prefix: string): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  tempDirs.push(dir);
  return dir;
}
afterAll(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  }
});

/** ディレクトリ以下のファイルの相対パス（区切りは /） */
function listFiles(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string): void => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else out.push(path.relative(dir, p).split(path.sep).join('/'));
    }
  };
  if (fs.existsSync(dir)) walk(dir);
  return out.sort();
}

async function loadViteConfigModule(): Promise<Record<string, unknown>> {
  return (await import('../vite.config')) as unknown as Record<string, unknown>;
}

/** vite.config.ts の既定のエクスポート（関数の形でも build の設定として解決する） */
async function loadMainConfig(): Promise<UserConfig> {
  const mod = await loadViteConfigModule();
  const def = mod.default as UserConfig | ((env: { command: 'build'; mode: string }) => UserConfig | Promise<UserConfig>);
  return typeof def === 'function' ? await def({ command: 'build', mode: 'production' }) : def;
}

async function loadContentScriptBuildConfig(): Promise<(outDir: string) => InlineConfig> {
  const mod = await loadViteConfigModule();
  const fn = mod.contentScriptBuildConfig;
  expect(typeof fn, 'vite.config.ts が contentScriptBuildConfig(outDir) を export していません').toBe('function');
  return fn as (outDir: string) => InlineConfig;
}

/** rollup の input（文字列・配列・オブジェクト）を絶対パスの一覧にする */
function inputPaths(input: unknown): string[] {
  const values: unknown[] =
    typeof input === 'string' ? [input] : Array.isArray(input) ? input : input && typeof input === 'object' ? Object.values(input) : [];
  return values
    .filter((v): v is string => typeof v === 'string')
    .map((v) => {
      const abs = path.resolve(REPO_ROOT, v);
      return fs.existsSync(abs) ? fs.realpathSync(abs) : abs;
    });
}

/** rollup の output（オブジェクトか配列）のうち最初のもの */
function firstOutput(output: unknown): Record<string, unknown> {
  const o = Array.isArray(output) ? output[0] : output;
  return (o && typeof o === 'object' ? o : {}) as Record<string, unknown>;
}

/** 先頭のコメントと 'use strict' を除いた本文が、トップレベルの宣言で始まらず、関数式の即時実行で始まるか（テスト側の簡易版） */
function looksLikeIife(text: string): boolean {
  const body = text
    .replace(/^(?:\s|\/\*[\s\S]*?\*\/|\/\/[^\n]*\n)*/, '')
    .replace(/^(['"])use strict\1;?\s*/, '');
  if (/^(const|let|class|var)\s/.test(body) || /^(import|export)\b/m.test(body)) return false;
  return /^(\(\s*(function\b|\(\s*\)\s*=>|async\b)|!function\b)/.test(body);
}

interface DoubleRunResult {
  error: unknown;
  addListenerCalls: number;
  guard: unknown;
}

/**
 * 出力を、同じ vm コンテキストで 2 回実行する（同じフレームへの 2 回の executeScript({ files }) に当たる）。
 * chrome.runtime.onMessage.addListener の呼び出し回数を数える。
 */
function runTwiceInSameContext(code: string): DoubleRunResult {
  let addListenerCalls = 0;
  const sandbox: Record<string, unknown> = {
    console: { log: () => {}, warn: () => {}, error: () => {}, info: () => {}, debug: () => {} },
    chrome: {
      runtime: {
        onMessage: {
          addListener: () => {
            addListenerCalls += 1;
          },
        },
      },
    },
  };
  const ctx = vm.createContext(sandbox);
  let error: unknown = null;
  try {
    new vm.Script(code, { filename: 'content/content-script.js' }).runInContext(ctx);
    new vm.Script(code, { filename: 'content/content-script.js' }).runInContext(ctx);
  } catch (e) {
    error = e;
  }
  const guard = vm.runInContext(`globalThis[${JSON.stringify(GUARD_KEY)}]`, ctx);
  return { error, addListenerCalls, guard };
}

describe('T02 §5.1: vite.config.ts のメインのビルド', () => {
  it('メインのビルドの入力に content-script が含まれないこと（2 段目のビルドで出す）', async () => {
    const cfg = await loadMainConfig();
    const inputs = inputPaths(cfg.build?.rollupOptions?.input);
    expect(inputs.length, 'メインのビルドの入力が読めません').toBeGreaterThan(0);
    expect(inputs).not.toContain(CONTENT_SCRIPT_SRC);
  });

  it('メインのビルドの入力に popup・dashboard・service-worker は残ること（陰性: 他の入口を外さない）', async () => {
    const cfg = await loadMainConfig();
    const inputs = inputPaths(cfg.build?.rollupOptions?.input);
    for (const rel of ['popup.html', 'dashboard.html', path.join('src', 'background', 'service-worker.ts')]) {
      expect(inputs, `${rel} がメインのビルドの入力にありません`).toContain(fs.realpathSync(path.join(REPO_ROOT, rel)));
    }
  });
});

describe('T02 §5.1: 2 段目のビルドの設定 contentScriptBuildConfig(outDir)', () => {
  it('入力は content-script だけ、出力は iife・inlineDynamicImports: true、emptyOutDir: false、出力先は渡した outDir', async () => {
    const contentScriptBuildConfig = await loadContentScriptBuildConfig();
    const outDir = makeTemp('cs-iife-config-');
    const cfg = contentScriptBuildConfig(outDir);
    expect(inputPaths(cfg.build?.rollupOptions?.input)).toEqual([CONTENT_SCRIPT_SRC]);
    const output = firstOutput(cfg.build?.rollupOptions?.output);
    expect(output.format).toBe('iife');
    expect(output.inlineDynamicImports).toBe(true);
    expect(cfg.build?.emptyOutDir).toBe(false);
    expect(path.resolve(REPO_ROOT, String(cfg.build?.outDir))).toBe(outDir);
  });

  it('ビルドすると <outDir>/content/content-script.js だけができ、別のチャンク（assets/ など）を出さないこと', async () => {
    const contentScriptBuildConfig = await loadContentScriptBuildConfig();
    const outDir = makeTemp('cs-iife-build-');
    await build({ ...contentScriptBuildConfig(outDir), logLevel: 'silent' });
    expect(listFiles(outDir).filter((f) => f.endsWith('.js'))).toEqual(['content/content-script.js']);
  }, 60_000);

  it('emptyOutDir: false なので、出力先に先にあるファイル（1 段目の出力）を消さないこと', async () => {
    const contentScriptBuildConfig = await loadContentScriptBuildConfig();
    const outDir = makeTemp('cs-iife-keep-');
    const sentinel = path.join(outDir, 'background', 'service-worker.js');
    fs.mkdirSync(path.dirname(sentinel), { recursive: true });
    fs.writeFileSync(sentinel, '// 1 段目の出力の代わり\n');
    await build({ ...contentScriptBuildConfig(outDir), logLevel: 'silent' });
    expect(fs.existsSync(sentinel)).toBe(true);
    expect(fs.existsSync(path.join(outDir, 'content', 'content-script.js'))).toBe(true);
  }, 60_000);

  it('出力は IIFE に包まれ、トップレベルの const / let / class / import / export で始まらないこと', async () => {
    const contentScriptBuildConfig = await loadContentScriptBuildConfig();
    const outDir = makeTemp('cs-iife-shape-');
    await build({ ...contentScriptBuildConfig(outDir), logLevel: 'silent' });
    const code = fs.readFileSync(path.join(outDir, 'content', 'content-script.js'), 'utf-8');
    expect(looksLikeIife(code), code.slice(0, 120)).toBe(true);
    expect(/^\s*(import|export)\b/m.test(code)).toBe(false);
  }, 60_000);

  it('出力を同じグローバルで 2 回実行しても SyntaxError にならず、リスナーは 1 回だけ登録され、二重注入の印が立つこと', async () => {
    const contentScriptBuildConfig = await loadContentScriptBuildConfig();
    const outDir = makeTemp('cs-iife-twice-');
    await build({ ...contentScriptBuildConfig(outDir), logLevel: 'silent' });
    const code = fs.readFileSync(path.join(outDir, 'content', 'content-script.js'), 'utf-8');
    const r = runTwiceInSameContext(code);
    expect(r.error, String(r.error)).toBeNull();
    expect(r.addListenerCalls).toBe(1);
    expect(r.guard).toBe(true);
  }, 60_000);
});

describe('T02 §5.1: テストの前提の自己確認（陰性）', () => {
  it('トップレベルの const の出力（ES モジュールの形）は、同じグローバルで 2 回目に重複宣言の SyntaxError になること', async () => {
    const outDir = makeTemp('cs-esm-');
    await build({
      configFile: false,
      root: REPO_ROOT,
      publicDir: false,
      logLevel: 'silent',
      build: {
        outDir,
        emptyOutDir: false,
        target: 'esnext',
        rollupOptions: {
          input: CONTENT_SCRIPT_SRC,
          output: { format: 'es', entryFileNames: 'content/content-script.js' },
        },
      },
    });
    const code = fs.readFileSync(path.join(outDir, 'content', 'content-script.js'), 'utf-8');
    expect(looksLikeIife(code)).toBe(false);
    const r = runTwiceInSameContext(code);
    // vm のコンテキストの中の SyntaxError は別の realm のものなので、instanceof ではなく name で見る
    expect(r.error).not.toBeNull();
    expect((r.error as Error).name).toBe('SyntaxError');
    expect((r.error as Error).message).toMatch(/already been declared/);
  }, 60_000);
});

describe('T02 §5.1: リポジトリの vite.config.ts での build（npm run build の vite build と同じ設定）', () => {
  let outDir = '';
  let built: Promise<void> | null = null;
  /** 1 回だけビルドし、各テストで共有する（出力先は一時ディレクトリ。設定ファイルの outDir を上書きする） */
  function buildOnce(): Promise<void> {
    if (!built) {
      outDir = makeTemp('cs-iife-full-');
      built = build({
        configFile: path.join(REPO_ROOT, 'vite.config.ts'),
        root: REPO_ROOT,
        logLevel: 'silent',
        build: { outDir },
      }).then(() => undefined);
    }
    return built;
  }

  it('content/content-script.js が IIFE で、同じグローバルで 2 回実行してもエラーにならず、リスナーは 1 回だけ', async () => {
    await buildOnce();
    const file = path.join(outDir, 'content', 'content-script.js');
    expect(fs.existsSync(file), 'content/content-script.js がビルドの出力にありません').toBe(true);
    const code = fs.readFileSync(file, 'utf-8');
    expect(looksLikeIife(code), code.slice(0, 120)).toBe(true);
    const r = runTwiceInSameContext(code);
    expect(r.error, String(r.error)).toBeNull();
    expect(r.addListenerCalls).toBe(1);
    expect(r.guard).toBe(true);
  }, 180_000);

  it('他の入口（popup.html・dashboard.html・background/service-worker.js）と manifest.json が出力に残ること（2 段目で消さない）', async () => {
    await buildOnce();
    const files = listFiles(outDir);
    for (const f of ['popup.html', 'dashboard.html', 'background/service-worker.js', 'manifest.json']) {
      expect(files, `${f} がビルドの出力にありません`).toContain(f);
    }
  }, 180_000);

  it('content-script のチャンクを assets/ に出さないこと（content/content-script.js の 1 ファイルだけ）', async () => {
    await buildOnce();
    const files = listFiles(outDir);
    expect(files.filter((f) => /content-script/.test(f))).toEqual(['content/content-script.js']);
  }, 180_000);

  it('出力の dist の合計がサイズの上限（check-size）を超えないこと', async () => {
    await buildOnce();
    const report = checkSizes({ advisoryDbPath: FIXTURE_DB, distDir: outDir }) as {
      results: Array<{ target: string; level: string; bytes: number | null }>;
    };
    const dist = report.results.find((r) => r.target === 'dist');
    expect(dist?.bytes).toBeGreaterThan(0);
    expect(dist?.level).not.toBe('fail');
  }, 180_000);
});

describe('T02 §5.1: service-worker.ts の注入のコメント', () => {
  it('content/content-script.js を注入する箇所のコメントが、IIFE で出していることに触れていること', () => {
    const src = fs.readFileSync(path.join(REPO_ROOT, 'src', 'background', 'service-worker.ts'), 'utf-8');
    const lines = src.split(/\r?\n/);
    const idx = lines.findIndex((l) => /files:\s*\[\s*['"]content\/content-script\.js['"]\s*\]/.test(l));
    expect(idx, 'content/content-script.js を注入する箇所が見つかりません').toBeGreaterThanOrEqual(0);
    const around = lines.slice(Math.max(0, idx - 8), idx + 1).join('\n');
    expect(around).toMatch(/IIFE/);
  });
});
