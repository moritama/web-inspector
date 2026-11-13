/**
 * サイズの上限（v1.8.0 T02 / G7）
 *
 * scripts/ci/check-size.mjs は build の後に実行し、
 *   - 脆弱性 DB（src/detection/ の同梱 DB）: 上限 2 MB
 *   - dist の合計: 上限 3 MB
 * を確かめる。上限の 80% を超えたら警告（終了コード 0）、上限を超えたら失敗（終了コード 1）。
 * MB は 1024 × 1024 バイト（既存の scripts/validate-advisories.mjs の MAX_FILE_SIZE_BYTES と同じ数え方）。
 *
 * 大きさの確認は一時ディレクトリの合成ファイルで行い、同梱 DB や実際の dist の大きさには依存しない。
 */
import { afterEach, describe, expect, it } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { REPO_ROOT } from './helpers/release-version';
// @ts-expect-error scripts/ci/check-size.mjs は型定義を持たない .mjs モジュール
import { checkSizes, classifySize, measureDirBytes, SIZE_LIMITS, WARN_RATIO } from '../scripts/ci/check-size.mjs';
// @ts-expect-error scripts/validate-advisories.mjs は型定義を持たない .mjs モジュール
import { MAX_FILE_SIZE_BYTES } from '../scripts/validate-advisories.mjs';

interface SizeResult {
  target: 'advisoryDb' | 'dist';
  bytes: number | null;
  limit: number;
  level: 'ok' | 'warn' | 'fail';
}
interface SizeReport {
  ok: boolean;
  results: SizeResult[];
}

const MiB = 1024 * 1024;
const SCRIPT = path.join(REPO_ROOT, 'scripts', 'ci', 'check-size.mjs');
const tempDirs: string[] = [];

function makeTemp(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'check-size-'));
  tempDirs.push(dir);
  return dir;
}

function writeBytes(abs: string, size: number): void {
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, Buffer.alloc(size, 0x61));
}

/** 合成の DB（db.json）と dist を作る。dist は入れ子のディレクトリに分けて置く */
function makeTree(dbBytes: number | null, distFiles: number[] | null): { dbPath: string; distDir: string } {
  const root = makeTemp();
  const dbPath = path.join(root, 'db.json');
  const distDir = path.join(root, 'dist');
  if (dbBytes !== null) writeBytes(dbPath, dbBytes);
  if (distFiles !== null) {
    fs.mkdirSync(distDir, { recursive: true });
    distFiles.forEach((size, i) => writeBytes(path.join(distDir, i % 2 === 0 ? 'assets' : 'background', `f${i}.js`), size));
  }
  return { dbPath, distDir };
}

function result(report: SizeReport, target: SizeResult['target']): SizeResult {
  const r = report.results.find((x) => x.target === target);
  if (!r) throw new Error(`${target} の結果がありません`);
  return r;
}

function runCli(dbPath: string, distDir: string): { status: number | null; output: string } {
  const r = spawnSync(process.execPath, [SCRIPT, '--db', dbPath, '--dist', distDir], { cwd: REPO_ROOT, encoding: 'utf-8' });
  return { status: r.status, output: `${r.stdout ?? ''}\n${r.stderr ?? ''}` };
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('T02: サイズの上限の値（G7）', () => {
  it('DB の上限は 2 MB（validate-advisories.mjs の上限と同じ）、dist の合計の上限は 3 MB、警告は 80%', () => {
    expect(SIZE_LIMITS.advisoryDb).toBe(2 * MiB);
    expect(SIZE_LIMITS.advisoryDb).toBe(MAX_FILE_SIZE_BYTES);
    expect(SIZE_LIMITS.dist).toBe(3 * MiB);
    expect(WARN_RATIO).toBe(0.8);
  });
});

describe('T02: classifySize（境界）', () => {
  const limit = 1000;
  it.each([
    [0, 'ok'],
    [800, 'ok'], // ちょうど 80% は「超えた」ではない
    [801, 'warn'],
    [1000, 'warn'], // ちょうど上限は「超えた」ではない
    [1001, 'fail'],
  ])('%i バイト（上限 1000）は %s', (bytes, level) => {
    expect(classifySize(bytes, limit)).toBe(level);
  });

  it('実際の上限でも、80% と上限の前後で区分が変わること', () => {
    const l = SIZE_LIMITS.dist as number;
    expect(classifySize(Math.floor(l * 0.8), l)).toBe('ok');
    expect(classifySize(Math.floor(l * 0.8) + 1, l)).toBe('warn');
    expect(classifySize(l, l)).toBe('warn');
    expect(classifySize(l + 1, l)).toBe('fail');
  });
});

describe('T02: measureDirBytes', () => {
  it('入れ子のディレクトリも含めた、ファイルの大きさの合計を返すこと', () => {
    const { distDir } = makeTree(null, [100, 250, 3000, 7]);
    expect(measureDirBytes(distDir)).toBe(100 + 250 + 3000 + 7);
  });
});

describe('T02: checkSizes', () => {
  it('どちらも 80% 以下なら ok（陰性: 警告も失敗も出さない）', () => {
    const { dbPath, distDir } = makeTree(1 * MiB, [MiB, MiB / 2]);
    const report = checkSizes({ advisoryDbPath: dbPath, distDir }) as SizeReport;
    expect(report.ok).toBe(true);
    expect(result(report, 'advisoryDb')).toMatchObject({ bytes: 1 * MiB, limit: 2 * MiB, level: 'ok' });
    expect(result(report, 'dist')).toMatchObject({ bytes: MiB + MiB / 2, limit: 3 * MiB, level: 'ok' });
  });

  it('DB が上限の 80% を超え、上限以下なら warn で、全体は ok（失敗にしない）', () => {
    const { dbPath, distDir } = makeTree(Math.floor(1.8 * MiB), [MiB]);
    const report = checkSizes({ advisoryDbPath: dbPath, distDir }) as SizeReport;
    expect(result(report, 'advisoryDb').level).toBe('warn');
    expect(report.ok).toBe(true);
  });

  it('dist の合計が上限を超えたら fail で、全体も失敗（個々のファイルは小さくても合計で数える）', () => {
    const { dbPath, distDir } = makeTree(1024, [MiB, MiB, MiB, 1]);
    const report = checkSizes({ advisoryDbPath: dbPath, distDir }) as SizeReport;
    expect(result(report, 'dist')).toMatchObject({ bytes: 3 * MiB + 1, level: 'fail' });
    expect(result(report, 'advisoryDb').level).toBe('ok');
    expect(report.ok).toBe(false);
  });

  it('DB が上限を超えたら fail', () => {
    const { dbPath, distDir } = makeTree(2 * MiB + 1, [1024]);
    const report = checkSizes({ advisoryDbPath: dbPath, distDir }) as SizeReport;
    expect(result(report, 'advisoryDb').level).toBe('fail');
    expect(report.ok).toBe(false);
  });

  it('dist が無い（build の前に実行した）ときは、合格にせず fail にすること', () => {
    const { dbPath, distDir } = makeTree(1024, null);
    const report = checkSizes({ advisoryDbPath: dbPath, distDir }) as SizeReport;
    expect(result(report, 'dist').level).toBe('fail');
    expect(report.ok).toBe(false);
  });

  it('DB のファイルが無いときも fail にすること', () => {
    const { dbPath, distDir } = makeTree(null, [1024]);
    const report = checkSizes({ advisoryDbPath: dbPath, distDir }) as SizeReport;
    expect(result(report, 'advisoryDb').level).toBe('fail');
    expect(report.ok).toBe(false);
  });
});

describe('T02: check-size.mjs のコマンド', () => {
  it('上限の 80% 以下: 終了コード 0、警告も失敗の注記も出さない', () => {
    const { dbPath, distDir } = makeTree(1024, [1024]);
    const r = runCli(dbPath, distDir);
    expect(r.status, r.output).toBe(0);
    expect(r.output).not.toContain('::warning');
    expect(r.output).not.toContain('::error');
  });

  it('80% を超えた: 終了コード 0 で、GitHub Actions の警告（::warning）を出す', () => {
    const { dbPath, distDir } = makeTree(1024, [Math.floor(2.5 * MiB)]);
    const r = runCli(dbPath, distDir);
    expect(r.status, r.output).toBe(0);
    expect(r.output).toContain('::warning');
    expect(r.output).not.toContain('::error');
  });

  it('上限を超えた: 終了コード 1 で、GitHub Actions のエラー（::error）を出す', () => {
    const { dbPath, distDir } = makeTree(2 * MiB + 1, [1024]);
    const r = runCli(dbPath, distDir);
    expect(r.status, r.output).toBe(1);
    expect(r.output).toContain('::error');
  });

  it('dist が無い: 終了コード 1', () => {
    const { dbPath, distDir } = makeTree(1024, null);
    const r = runCli(dbPath, distDir);
    expect(r.status, r.output).toBe(1);
  });
});
