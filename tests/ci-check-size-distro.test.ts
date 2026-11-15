/**
 * T05: check-size に distro 節の上限（800 KB。H8・§5.3）
 *
 * - distro 節の大きさは、DB の distro を JSON.stringify（空白なし）にしたバイト数で数える（総合チェック C17 と同じ数え方）。
 *   KB は 1024 バイト（既存の上限 2 MB・3 MB と同じ数え方）。
 * - 上限の 80% を超えたら警告（終了コード 0）、上限を超えたら失敗（終了コード 1）。
 * - DB 全体の上限（2 MB）と dist の上限（3 MB）はそのまま（tests/ci-check-size.test.ts）。
 * - 大きさの確認は一時ディレクトリの合成ファイルで行い、同梱 DB の大きさには依存しない。
 */
import { afterEach, describe, expect, it } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { REPO_ROOT } from './helpers/release-version';
// @ts-expect-error scripts/ci/check-size.mjs は型定義を持たない .mjs モジュール
import { checkSizes, SIZE_LIMITS, WARN_RATIO } from '../scripts/ci/check-size.mjs';

interface SizeResult {
  target: string;
  bytes: number | null;
  limit: number;
  level: 'ok' | 'warn' | 'fail';
}
interface SizeReport {
  ok: boolean;
  results: SizeResult[];
}

const KiB = 1024;
const DISTRO_LIMIT = 800 * KiB;
const SCRIPT = path.join(REPO_ROOT, 'scripts', 'ci', 'check-size.mjs');
const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  }
});

/** distro 節の JSON がちょうど distroBytes バイトになる合成の DB と、小さな dist を作る */
function makeTree(distroBytes: number | null): { dbPath: string; distDir: string } {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'check-size-distro-')));
  tempDirs.push(root);
  const db: Record<string, unknown> = { schemaVersion: '2.3', libraries: {} };
  if (distroBytes !== null) {
    const base = { releases: [], map: [], advisories: {}, _source: [], filler: '' };
    const overhead = Buffer.byteLength(JSON.stringify(base));
    const distro = { ...base, filler: 'x'.repeat(distroBytes - overhead) };
    expect(Buffer.byteLength(JSON.stringify(distro))).toBe(distroBytes);
    db.distro = distro;
  }
  const dbPath = path.join(root, 'db.json');
  fs.writeFileSync(dbPath, JSON.stringify(db));
  const distDir = path.join(root, 'dist');
  fs.mkdirSync(distDir, { recursive: true });
  fs.writeFileSync(path.join(distDir, 'a.js'), 'x'.repeat(1024));
  return { dbPath, distDir };
}

const distroResult = (report: SizeReport): SizeResult | undefined => report.results.find((r) => r.target === 'distro');

function runCli(dbPath: string, distDir: string): { status: number | null; output: string } {
  const r = spawnSync(process.execPath, [SCRIPT, '--db', dbPath, '--dist', distDir], { cwd: REPO_ROOT, encoding: 'utf-8' });
  return { status: r.status, output: `${r.stdout ?? ''}\n${r.stderr ?? ''}` };
}

describe('T05: distro 節の上限の値', () => {
  it('distro 節の上限は 800 KB、警告は 80%。DB 全体と dist の上限は変わらない', () => {
    expect(SIZE_LIMITS.distro).toBe(DISTRO_LIMIT);
    expect(WARN_RATIO).toBe(0.8);
    expect(SIZE_LIMITS.advisoryDb).toBe(2 * 1024 * KiB);
    expect(SIZE_LIMITS.dist).toBe(3 * 1024 * KiB);
  });
});

describe('T05: checkSizes の distro 節', () => {
  it('80% 以下なら ok（陰性）', () => {
    const { dbPath, distDir } = makeTree(Math.floor(DISTRO_LIMIT * 0.8));
    const report = checkSizes({ advisoryDbPath: dbPath, distDir }) as SizeReport;
    expect(distroResult(report)).toMatchObject({ bytes: Math.floor(DISTRO_LIMIT * 0.8), limit: DISTRO_LIMIT, level: 'ok' });
    expect(report.ok).toBe(true);
  });

  it('80% を超え上限以下なら warn で、全体は ok（失敗にしない）', () => {
    const { dbPath, distDir } = makeTree(Math.floor(DISTRO_LIMIT * 0.8) + 1);
    const report = checkSizes({ advisoryDbPath: dbPath, distDir }) as SizeReport;
    expect(distroResult(report)?.level).toBe('warn');
    expect(report.ok).toBe(true);
    // ちょうど上限は「超えた」ではない
    const atLimit = makeTree(DISTRO_LIMIT);
    const reportAtLimit = checkSizes({ advisoryDbPath: atLimit.dbPath, distDir: atLimit.distDir }) as SizeReport;
    expect(distroResult(reportAtLimit)?.level).toBe('warn');
    expect(reportAtLimit.ok).toBe(true);
  });

  it('上限を超えたら fail で、全体も失敗（DB 全体は 2 MB 未満でも distro 節だけで失敗する）', () => {
    const { dbPath, distDir } = makeTree(DISTRO_LIMIT + 1);
    const report = checkSizes({ advisoryDbPath: dbPath, distDir }) as SizeReport;
    expect(distroResult(report)).toMatchObject({ bytes: DISTRO_LIMIT + 1, level: 'fail' });
    expect(report.results.find((r) => r.target === 'advisoryDb')?.level).toBe('ok');
    expect(report.ok).toBe(false);
  });

  it('distro 節の無い DB（旧 DB）では distro 節の検査で失敗しないこと（陰性）', () => {
    const { dbPath, distDir } = makeTree(null);
    const report = checkSizes({ advisoryDbPath: dbPath, distDir }) as SizeReport;
    expect(report.ok).toBe(true);
    const r = distroResult(report);
    expect(r === undefined || r.level === 'ok').toBe(true);
  });
});

describe('T05: check-size.mjs のコマンド（distro 節）', () => {
  it('上限を超えた: 終了コード 1 で、distro 節のエラー（::error）を出す', () => {
    const { dbPath, distDir } = makeTree(DISTRO_LIMIT + 1);
    const r = runCli(dbPath, distDir);
    expect(r.status, r.output).toBe(1);
    expect(r.output).toMatch(/::error[^\n]*distro/);
  });

  it('80% を超えた: 終了コード 0 で、distro 節の警告（::warning）を出す', () => {
    const { dbPath, distDir } = makeTree(Math.floor(DISTRO_LIMIT * 0.8) + 1);
    const r = runCli(dbPath, distDir);
    expect(r.status, r.output).toBe(0);
    expect(r.output).toMatch(/::warning[^\n]*distro/);
    expect(r.output).not.toContain('::error');
  });

  it('80% 以下: 終了コード 0 で、警告も失敗も出さない（陰性）', () => {
    const { dbPath, distDir } = makeTree(100 * KiB);
    const r = runCli(dbPath, distDir);
    expect(r.status, r.output).toBe(0);
    expect(r.output).not.toContain('::warning');
    expect(r.output).not.toContain('::error');
  });
});
