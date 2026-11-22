/**
 * CI のチェック: content-script の出力が IIFE か（v1.8.2 T02 / B / H6、指示書 §5.1）
 *
 * scripts/ci/check-content-script-iife.mjs を足し、build の後に CI（.github/workflows/ci.yml）で実行する。
 *   - checkIifeSource(text) … 先頭のコメントと 'use strict' を除いた本文が、トップレベルの const / let / class / var / import / export で
 *     始まらず、関数式の即時実行（`(function`、`(() =>`、`(async`、`!function`）で始まれば ok
 *   - checkContentScriptIife({ file }) … ファイルを読んで checkIifeSource する。ファイルが無ければ不合格
 *   - CLI: `node scripts/ci/check-content-script-iife.mjs [--file <path>]`。合格なら終了コード 0、不合格なら 0 以外
 * 一時ファイルは os.tmpdir() に作る。
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { build } from 'vite';
import { REPO_ROOT } from './helpers/release-version';

const SCRIPT = path.join(REPO_ROOT, 'scripts', 'ci', 'check-content-script-iife.mjs');
const CI_YML_PATH = path.join(REPO_ROOT, '.github', 'workflows', 'ci.yml');
const CONTENT_SCRIPT_SRC = path.join(REPO_ROOT, 'src', 'content', 'content-script.ts');

interface CheckResult {
  ok: boolean;
  reason: string;
}
interface FileCheckResult extends CheckResult {
  path: string;
}
interface IifeModule {
  checkIifeSource: (text: string) => CheckResult;
  checkContentScriptIife: (options?: { file?: string }) => FileCheckResult;
}

async function loadModule(): Promise<IifeModule> {
  expect(fs.existsSync(SCRIPT), 'scripts/ci/check-content-script-iife.mjs がありません').toBe(true);
  const mod = (await import(/* @vite-ignore */ SCRIPT)) as Partial<IifeModule>;
  expect(typeof mod.checkIifeSource, 'checkIifeSource が export されていません').toBe('function');
  expect(typeof mod.checkContentScriptIife, 'checkContentScriptIife が export されていません').toBe('function');
  return mod as IifeModule;
}

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

function writeTemp(name: string, text: string): string {
  const dir = makeTemp('cs-iife-ci-');
  const file = path.join(dir, name);
  fs.writeFileSync(file, text);
  return file;
}

const IIFE_SAMPLES: Array<[string, string]> = [
  ['圧縮された IIFE（rollup の iife の出力の形）', '(function(){"use strict";const D=["#a"];function f(){}f();})();\n'],
  ['整形された IIFE', "(function () {\n  'use strict';\n\n  const D = ['#a'];\n  let n = 0;\n})();\n"],
  ['アロー関数の IIFE', '(()=>{const D=1;let n=2;})();\n'],
  ['先頭にブロックコメントと行コメントがある IIFE', '/* license */\n// built\n(function(){const a=1;})();\n'],
  ['! で始まる IIFE', '!function(){const a=1;}();\n'],
];

const NON_IIFE_SAMPLES: Array<[string, string]> = [
  ['トップレベルの const（v1.8.1 の出力の形）', 'const W=["#__nuxt"];function x(){}x();\n'],
  ['トップレベルの let', 'let a=1;(function(){})();\n'],
  ['トップレベルの class', 'class A{}new A();\n'],
  ['トップレベルの var', 'var a=1;\n'],
  ["'use strict' の後にトップレベルの const", '"use strict";const a=1;\n'],
  ['コメントの後にトップレベルの const', '/* c */\nconst a=1;\n'],
  ['import で始まる（ES モジュール）', 'import{a as b}from"./x.js";(function(){b()})();\n'],
  ['IIFE の後の行に export がある（ES モジュール）', '(function(){})();\nexport{a};\n'],
  ['関数宣言だけ（即時実行でない）', 'function main(){}main();\n'],
  ['空のファイル', ''],
  ['コメントだけ', '/* only comment */\n'],
];

describe('T02 §5.1: checkIifeSource', () => {
  it.each(IIFE_SAMPLES)('合格（陽性）: %s', async (_label, text) => {
    const { checkIifeSource } = await loadModule();
    const r = checkIifeSource(text);
    expect(r.ok, r.reason).toBe(true);
  });

  it.each(NON_IIFE_SAMPLES)('不合格（陰性）: %s', async (_label, text) => {
    const { checkIifeSource } = await loadModule();
    const r = checkIifeSource(text);
    expect(r.ok).toBe(false);
    expect(typeof r.reason).toBe('string');
    expect(r.reason.length, '不合格の理由が空です').toBeGreaterThan(0);
  });
});

describe('T02 §5.1: 実際のビルドの出力で確かめる', () => {
  let esmCode = '';
  let iifeCode = '';
  beforeAll(async () => {
    for (const format of ['es', 'iife'] as const) {
      const outDir = makeTemp(`cs-iife-ci-${format}-`);
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
            output: { format, inlineDynamicImports: true, entryFileNames: 'content/content-script.js' },
          },
        },
      });
      const code = fs.readFileSync(path.join(outDir, 'content', 'content-script.js'), 'utf-8');
      if (format === 'es') esmCode = code;
      else iifeCode = code;
    }
  }, 120_000);

  it('ES モジュールの形で出した content-script（IIFE でない出力）を不合格にすること（陰性）', async () => {
    const { checkIifeSource } = await loadModule();
    expect(checkIifeSource(esmCode).ok).toBe(false);
  });

  it('iife の形で出した content-script を合格にすること（陽性）', async () => {
    const { checkIifeSource } = await loadModule();
    const r = checkIifeSource(iifeCode);
    expect(r.ok, r.reason).toBe(true);
  });
});

describe('T02 §5.1: checkContentScriptIife（ファイル）', () => {
  it('IIFE のファイルは合格し、path に渡したファイルを返すこと', async () => {
    const { checkContentScriptIife } = await loadModule();
    const file = writeTemp('content-script.js', IIFE_SAMPLES[0][1]);
    const r = checkContentScriptIife({ file });
    expect(r.ok, r.reason).toBe(true);
    expect(fs.realpathSync(path.resolve(r.path))).toBe(file);
  });

  it('トップレベルの const のファイルは不合格（陰性）', async () => {
    const { checkContentScriptIife } = await loadModule();
    const file = writeTemp('content-script.js', NON_IIFE_SAMPLES[0][1]);
    const r = checkContentScriptIife({ file });
    expect(r.ok).toBe(false);
    expect(r.reason.length).toBeGreaterThan(0);
  });

  it('ファイルが無ければ不合格（陰性: 黙って通さない）', async () => {
    const { checkContentScriptIife } = await loadModule();
    const dir = makeTemp('cs-iife-ci-missing-');
    const r = checkContentScriptIife({ file: path.join(dir, 'content', 'content-script.js') });
    expect(r.ok).toBe(false);
    expect(r.reason.length).toBeGreaterThan(0);
  });
});

describe('T02 §5.1: CLI', () => {
  function runCli(args: string[]): { status: number | null; output: string } {
    const r = spawnSync(process.execPath, [SCRIPT, ...args], { cwd: REPO_ROOT, encoding: 'utf-8' });
    return { status: r.status, output: `${r.stdout ?? ''}\n${r.stderr ?? ''}` };
  }

  it('IIFE のファイルを渡すと終了コード 0', () => {
    expect(fs.existsSync(SCRIPT), 'scripts/ci/check-content-script-iife.mjs がありません').toBe(true);
    const file = writeTemp('content-script.js', IIFE_SAMPLES[0][1]);
    const r = runCli(['--file', file]);
    expect(r.status, r.output).toBe(0);
  });

  it('IIFE でないファイルを渡すと終了コード 0 以外で、出力にファイルのパスが出ること（陰性）', () => {
    expect(fs.existsSync(SCRIPT), 'scripts/ci/check-content-script-iife.mjs がありません').toBe(true);
    const file = writeTemp('content-script.js', NON_IIFE_SAMPLES[0][1]);
    const r = runCli(['--file', file]);
    expect(r.status).not.toBe(0);
    expect(r.status).not.toBeNull();
    expect(r.output).toContain('content-script.js');
  });

  it('ファイルが無いと終了コード 0 以外（陰性）', () => {
    expect(fs.existsSync(SCRIPT), 'scripts/ci/check-content-script-iife.mjs がありません').toBe(true);
    const dir = makeTemp('cs-iife-ci-cli-missing-');
    const r = runCli(['--file', path.join(dir, 'nothing.js')]);
    expect(r.status).not.toBe(0);
    expect(r.status).not.toBeNull();
  });
});

/** コメント行と行末のコメントを除いた行（tests/ci-workflow.test.ts と同じ簡易版） */
function stripComments(yml: string): string[] {
  return yml.split(/\r?\n/).map((line) => {
    if (/^\s*#/.test(line)) return '';
    const idx = line.search(/\s#\s/);
    return idx >= 0 ? line.slice(0, idx) : line;
  });
}

/** jobs: の直下のジョブ ID と、その範囲の行 */
function jobBlocks(yml: string): Map<string, string[]> {
  const lines = stripComments(yml);
  const jobsIdx = lines.findIndex((l) => /^jobs:\s*$/.test(l));
  const blocks = new Map<string, string[]>();
  if (jobsIdx < 0) return blocks;
  let current: string | null = null;
  for (const line of lines.slice(jobsIdx + 1)) {
    if (/^\S/.test(line)) break;
    const m = line.match(/^ {2}([A-Za-z_][A-Za-z0-9_-]*):\s*$/);
    if (m) {
      current = m[1];
      blocks.set(current, []);
      continue;
    }
    if (current) blocks.get(current)?.push(line);
  }
  return blocks;
}

describe('T02 §5.1: ci.yml', () => {
  const CHECK_RE = /\bnode\s+scripts\/ci\/check-content-script-iife\.mjs\b/;
  const BUILD_RE = /\bnpm run build\b/;

  it('同じジョブの中で、npm run build の後に scripts/ci/check-content-script-iife.mjs を実行すること', () => {
    const blocks = jobBlocks(fs.readFileSync(CI_YML_PATH, 'utf-8'));
    const found = [...blocks.entries()].filter(([, lines]) => {
      const buildIdx = lines.findIndex((l) => BUILD_RE.test(l));
      const checkIdx = lines.findIndex((l) => CHECK_RE.test(l));
      return buildIdx >= 0 && checkIdx > buildIdx;
    });
    expect(found.map(([id]) => id), 'build の後に check-content-script-iife.mjs を実行するジョブがありません').not.toEqual([]);
  });

  it('check-content-script-iife.mjs を build より前に実行するジョブが無いこと（陰性: dist が無い状態で見ない）', () => {
    const blocks = jobBlocks(fs.readFileSync(CI_YML_PATH, 'utf-8'));
    for (const [id, lines] of blocks) {
      const checkIdx = lines.findIndex((l) => CHECK_RE.test(l));
      if (checkIdx < 0) continue;
      const buildIdx = lines.findIndex((l) => BUILD_RE.test(l));
      expect(buildIdx, `${id}: check-content-script-iife.mjs の前に npm run build がありません`).toBeGreaterThanOrEqual(0);
      expect(buildIdx, `${id}: check-content-script-iife.mjs が npm run build より前にあります`).toBeLessThan(checkIdx);
    }
  });

  it('check-content-script-iife.mjs の手順に continue-on-error を付けないこと（陰性: 不合格で CI を落とす）', () => {
    const lines = stripComments(fs.readFileSync(CI_YML_PATH, 'utf-8'));
    const idx = lines.findIndex((l) => CHECK_RE.test(l));
    expect(idx, 'check-content-script-iife.mjs を実行する手順がありません').toBeGreaterThanOrEqual(0);
    // 手順の始まり（`- name:` / `- run:`）から次の手順の前まで
    let start = idx;
    while (start > 0 && !/^\s*-\s/.test(lines[start])) start--;
    let end = idx + 1;
    while (end < lines.length && !/^\s*-\s/.test(lines[end]) && !/^ {2}\S/.test(lines[end])) end++;
    expect(lines.slice(start, end).join('\n')).not.toMatch(/continue-on-error:\s*true/);
  });
});
