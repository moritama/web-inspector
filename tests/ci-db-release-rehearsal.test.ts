/**
 * DB だけのリリースの予行（v1.8.0 T02）
 *
 * scripts/ci/rehearse-db-release.mjs は、作業ツリーの一時コピーで
 *   1. scripts/advisories/bump-db-revision.mjs を実行し（manifest の版に 4 つ目の番号を付ける）
 *   2. DB の dataVersion を進め、integrity を再計算し
 *   3. テスト（既定は npm test）を走らせる
 * ものです。元の作業ツリーは変更しません。
 *
 * 全体の npm test をテストの中で走らせると時間がかかり、入れ子にもなるため、ここでは
 * - 合成の作業ツリー（一時ディレクトリ）と、テストの代わりの小さな検査スクリプトで予行の仕組みを確かめる
 * - 現在のツリーでは、テストの代わりに DB の検証スクリプト（scripts/validate-advisories.mjs）を走らせる
 * 合成の作業ツリーの版（3.4.5）と dataVersion（20990101）は合成データで、同梱 DB や package.json の値ではありません。
 */
import { afterEach, describe, expect, it } from 'vitest';
import { execFileSync } from 'child_process';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { isSameRelease, readPackageVersion, REPO_ROOT } from './helpers/release-version';
// @ts-expect-error scripts/ci/rehearse-db-release.mjs は型定義を持たない .mjs モジュール
import { bumpAdvisoryDb, DEFAULT_TEST_COMMAND, nextDataVersion, rehearseDbRelease } from '../scripts/ci/rehearse-db-release.mjs';
// @ts-expect-error scripts/advisories/bump-db-revision.mjs は型定義を持たない .mjs モジュール
import { nextDbRevision } from '../scripts/advisories/bump-db-revision.mjs';

interface RehearsalResult {
  ok: boolean;
  exitCode: number | null;
  workDir: string;
  previousManifestVersion: string;
  manifestVersion: string;
  previousDataVersion: string;
  dataVersion: string;
}

const SYNTHETIC_PKG_VERSION = '3.4.5';
const SYNTHETIC_DATA_VERSION = '20990101';
// 合成の作業ツリーでの DB の置き場所（同梱 DB の場所とは別にして、元の作業ツリーの DB と取り違えないようにする）
const SYNTHETIC_DB_PATH = 'data/synthetic-advisory-db.json';

const tempDirs: string[] = [];

function sha256(text: string): string {
  return crypto.createHash('sha256').update(text).digest('hex');
}

function isValidYmd(s: string): boolean {
  if (!/^\d{8}$/.test(s)) return false;
  const y = Number(s.slice(0, 4));
  const m = Number(s.slice(4, 6));
  const d = Number(s.slice(6, 8));
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
}

function writeFile(root: string, rel: string, content: string): void {
  const abs = path.join(root, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, content, 'utf-8');
}

/** ディレクトリ以下の全ファイルの「相対パス → 内容のハッシュ」（元の作業ツリーが変わらないことの確認用） */
function snapshotTree(root: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (dir: string): void => {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const abs = path.join(dir, ent.name);
      if (ent.isDirectory()) walk(abs);
      else out[path.relative(root, abs).split(path.sep).join('/')] = sha256(fs.readFileSync(abs, 'utf-8'));
    }
  };
  walk(root);
  return out;
}

/**
 * 合成の作業ツリーを作る。
 * - package.json / public/manifest.json（版は 3.4.5）
 * - 合成の DB（SYNTHETIC_DB_PATH。integrity は libraries と一致）
 * - scripts/advisories/bump-db-revision.mjs と lib/util.mjs（リポジトリのものをそのままコピー）
 * - コピーしてはいけない dist/ と reports/
 * - テストの代わりに走らせる検査スクリプト check.mjs
 */
function makeSourceTree(checker: string, overrides: { manifestVersion?: string; integrityDigest?: string } = {}): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rehearsal-src-'));
  tempDirs.push(root);
  writeFile(root, 'package.json', `${JSON.stringify({ name: 'synthetic-extension', version: SYNTHETIC_PKG_VERSION, type: 'module' }, null, 2)}\n`);
  writeFile(
    root,
    'public/manifest.json',
    `${JSON.stringify({ manifest_version: 3, name: 'Synthetic', version: overrides.manifestVersion ?? SYNTHETIC_PKG_VERSION }, null, 2)}\n`
  );
  const libraries = { examplelib: { name: 'Example Lib', versions: [] } };
  const db = {
    schemaVersion: '2.2',
    dataVersion: SYNTHETIC_DATA_VERSION,
    libraries,
    integrity: { algorithm: 'sha256', target: 'libraries', digest: overrides.integrityDigest ?? sha256(JSON.stringify(libraries)) },
  };
  writeFile(root, SYNTHETIC_DB_PATH, `${JSON.stringify(db, null, 2)}\n`);
  for (const rel of ['scripts/advisories/bump-db-revision.mjs', 'scripts/advisories/lib/util.mjs']) {
    writeFile(root, rel, fs.readFileSync(path.join(REPO_ROOT, rel), 'utf-8'));
  }
  writeFile(root, 'src/app.ts', 'export const app = 1;\n');
  writeFile(root, 'tests/sample.test.ts', "// 合成のテスト\nexport {};\n");
  writeFile(root, 'dist/stale-build.js', '// 古いビルド\n');
  writeFile(root, 'reports/site.example.test/report.md', '# 合成のレポート\n');
  writeFile(root, 'check.mjs', checker);
  return root;
}

// 旧来の書き方: manifest の版を package.json の版と完全一致で比べる（DB だけのリリースで 4 つ目の番号が付くと落ちる）
const OLD_STYLE_EXACT_CHECK = `import fs from 'node:fs';
const manifest = JSON.parse(fs.readFileSync('public/manifest.json', 'utf-8'));
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf-8'));
if (manifest.version !== pkg.version) {
  console.error('manifest の版が package.json の版と完全一致しません: ' + manifest.version);
  process.exit(1);
}
`;

// 今の書き方: 3 要素が一致し、4 つ目は無いか数字だけ（tests/helpers/release-version.ts の isSameRelease と同じ判定）
const SAME_RELEASE_CHECK = `import fs from 'node:fs';
const manifest = JSON.parse(fs.readFileSync('public/manifest.json', 'utf-8'));
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf-8'));
const parts = manifest.version.split('.');
const ok = (parts.length === 3 || parts.length === 4) && parts.every((p) => /^\\d+$/.test(p)) && parts.slice(0, 3).join('.') === pkg.version;
process.exit(ok ? 0 : 1);
`;

// テストが「DB だけのリリースの後の状態」のコピーで走ることを確かめる検査
const BUMPED_STATE_CHECK = `import crypto from 'node:crypto';
import fs from 'node:fs';
const manifest = JSON.parse(fs.readFileSync('public/manifest.json', 'utf-8'));
const db = JSON.parse(fs.readFileSync('${SYNTHETIC_DB_PATH}', 'utf-8'));
const digest = crypto.createHash('sha256').update(JSON.stringify(db.libraries)).digest('hex');
const errors = [];
if (manifest.version.split('.').length !== 4) errors.push('manifest の版に 4 つ目の番号がありません: ' + manifest.version);
if (!(typeof db.dataVersion === 'string' && /^\\d{8}$/.test(db.dataVersion) && db.dataVersion > '${SYNTHETIC_DATA_VERSION}')) errors.push('dataVersion が進んでいません: ' + db.dataVersion);
if (!db.integrity || db.integrity.digest !== digest) errors.push('integrity が libraries と一致しません');
if (fs.existsSync('dist')) errors.push('dist がコピーされています');
if (fs.existsSync('reports')) errors.push('reports がコピーされています');
if (!fs.existsSync('src/app.ts') || !fs.existsSync('tests/sample.test.ts')) errors.push('ソースかテストがコピーされていません');
if (errors.length > 0) { console.error(errors.join('\\n')); process.exit(1); }
`;

const ALWAYS_PASS_CHECK = 'process.exit(0);\n';
const ALWAYS_FAIL_CHECK = "console.error('合成のテストの失敗');\nprocess.exit(3);\n";

async function rehearse(sourceDir: string, extra: Record<string, unknown> = {}): Promise<RehearsalResult> {
  return (await rehearseDbRelease({
    sourceDir,
    advisoryDbPath: SYNTHETIC_DB_PATH,
    testCommand: [process.execPath, 'check.mjs'],
    ...extra,
  })) as RehearsalResult;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('T02: nextDataVersion（dataVersion を進める）', () => {
  it.each([['20990101'], ['20990131'], ['20991231'], ['20990228']])('%s より後の、YYYYMMDD 形式の正しい日付を返すこと', (current) => {
    const next = nextDataVersion(current) as string;
    expect(typeof next).toBe('string');
    expect(isValidYmd(next), `${next} は YYYYMMDD の正しい日付ではありません`).toBe(true);
    expect(next > current).toBe(true);
  });

  it.each([[''], ['abcdefgh'], ['2099-01-01'], ['209901011']])('YYYYMMDD でない値 %j では例外を投げること（陰性）', (bad) => {
    expect(() => nextDataVersion(bad)).toThrow();
  });
});

describe('T02: bumpAdvisoryDb（dataVersion を進め、integrity を再計算する）', () => {
  const fixture = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'tests', 'fixtures', 'advisory-db.fixture.json'), 'utf-8')) as {
    dataVersion: string;
    libraries: unknown;
    integrity?: { digest?: string };
    [key: string]: unknown;
  };

  it('固定 DB の dataVersion を進め、integrity が libraries の sha256 と一致し、libraries とほかの項目は変えないこと', () => {
    const input = structuredClone(fixture);
    const bumped = bumpAdvisoryDb(input) as typeof fixture;
    expect(isValidYmd(bumped.dataVersion)).toBe(true);
    expect(bumped.dataVersion > fixture.dataVersion).toBe(true);
    expect(bumped.libraries).toEqual(fixture.libraries);
    expect(bumped.integrity).toMatchObject({ algorithm: 'sha256', target: 'libraries', digest: sha256(JSON.stringify(bumped.libraries)) });
    expect(bumped.schemaVersion).toBe(fixture.schemaVersion);
    expect(bumped.minExtensionVersion).toBe(fixture.minExtensionVersion);
    // 入力は変更しない
    expect(input).toEqual(fixture);
  });

  it('入力の integrity が古くても、libraries から計算し直すこと（値を写すだけではない）', () => {
    const input = { ...structuredClone(fixture), integrity: { algorithm: 'sha256', target: 'libraries', digest: '0'.repeat(64) } };
    const bumped = bumpAdvisoryDb(input) as typeof fixture;
    expect(bumped.integrity?.digest).toBe(sha256(JSON.stringify(fixture.libraries)));
  });
});

describe('T02: rehearseDbRelease（合成の作業ツリー）', () => {
  it('既定のテストのコマンドは npm test であること', () => {
    expect(DEFAULT_TEST_COMMAND).toEqual(['npm', 'test']);
  });

  it('テストは、版と dataVersion が進み integrity が正しいコピーで走り、dist と reports はコピーしないこと（陽性）', async () => {
    const src = makeSourceTree(BUMPED_STATE_CHECK);
    const r = await rehearse(src);
    expect(r.ok, '予行が失敗しました').toBe(true);
    expect(r.exitCode).toBe(0);
    expect(r.previousManifestVersion).toBe(SYNTHETIC_PKG_VERSION);
    expect(r.manifestVersion).toBe(nextDbRevision(SYNTHETIC_PKG_VERSION));
    expect(r.previousDataVersion).toBe(SYNTHETIC_DATA_VERSION);
    expect(isValidYmd(r.dataVersion)).toBe(true);
    expect(r.dataVersion > r.previousDataVersion).toBe(true);
  });

  it('元の作業ツリーは変更しない（ファイルの追加・変更・削除が無い）こと', async () => {
    const src = makeSourceTree(BUMPED_STATE_CHECK);
    const before = snapshotTree(src);
    const r = await rehearse(src);
    expect(r.ok).toBe(true);
    expect(snapshotTree(src)).toEqual(before);
  });

  it('一時コピーは元の作業ツリーの外に作り、既定では終了後に消すこと', async () => {
    const src = makeSourceTree(ALWAYS_PASS_CHECK);
    const r = await rehearse(src);
    expect(r.ok).toBe(true);
    expect(path.relative(src, r.workDir).startsWith('..')).toBe(true);
    expect(fs.existsSync(r.workDir)).toBe(false);
  });

  it('keepWorkDir: true なら一時コピーを残し、その中で manifest と DB が進んでいること', async () => {
    const src = makeSourceTree(ALWAYS_PASS_CHECK);
    const r = await rehearse(src, { keepWorkDir: true });
    tempDirs.push(r.workDir);
    expect(r.ok).toBe(true);
    const manifest = JSON.parse(fs.readFileSync(path.join(r.workDir, 'public', 'manifest.json'), 'utf-8'));
    expect(manifest.version).toBe(r.manifestVersion);
    const db = JSON.parse(fs.readFileSync(path.join(r.workDir, SYNTHETIC_DB_PATH), 'utf-8'));
    expect(db.dataVersion).toBe(r.dataVersion);
    expect(db.integrity.digest).toBe(sha256(JSON.stringify(db.libraries)));
  });

  it('入力の integrity が古くても、コピーの DB では再計算されていること', async () => {
    const src = makeSourceTree(BUMPED_STATE_CHECK, { integrityDigest: 'f'.repeat(64) });
    const r = await rehearse(src);
    expect(r.ok).toBe(true);
  });

  it('受け入れ条件 2: 旧来の書き方（manifest の版を完全一致で比べる）のテストがあると、予行が失敗すること', async () => {
    const src = makeSourceTree(OLD_STYLE_EXACT_CHECK);
    // 予行の前（元の作業ツリー）では、旧来の書き方でも通ってしまう
    expect(() => execFileSync(process.execPath, ['check.mjs'], { cwd: src, stdio: 'pipe' })).not.toThrow();
    const r = await rehearse(src);
    expect(r.ok).toBe(false);
    expect(r.exitCode).not.toBe(0);
  });

  it('受け入れ条件 2 の対照: 同じ確認を「同じリリースか」で書けば、予行が通ること', async () => {
    const src = makeSourceTree(SAME_RELEASE_CHECK);
    const r = await rehearse(src);
    expect(r.ok).toBe(true);
  });

  it('テストが失敗したら ok: false と 0 以外の終了コードを返し、一時コピーは消すこと（陰性）', async () => {
    const src = makeSourceTree(ALWAYS_FAIL_CHECK);
    const r = await rehearse(src);
    expect(r.ok).toBe(false);
    expect(r.exitCode).toBe(3);
    expect(fs.existsSync(r.workDir)).toBe(false);
  });

  it('版の採番（bump-db-revision.mjs）が失敗したら、テストが通っても予行は失敗すること（陰性）', async () => {
    const src = makeSourceTree(ALWAYS_PASS_CHECK, { manifestVersion: 'not-a-version' });
    const before = snapshotTree(src);
    const r = await rehearse(src).catch(() => ({ ok: false }) as RehearsalResult);
    expect(r.ok).toBe(false);
    expect(snapshotTree(src)).toEqual(before);
  });
});

describe('T02: rehearseDbRelease（現在のツリー）', () => {
  // 予行のコピーの中（Git の作業ツリーではない）でこのテストが走ることもあるので、git が使えないときは空文字にする
  const gitStatus = (): string => {
    try {
      const top = execFileSync('git', ['rev-parse', '--show-toplevel'], { cwd: REPO_ROOT, encoding: 'utf-8', stdio: 'pipe' }).trim();
      if (fs.realpathSync(top) !== fs.realpathSync(REPO_ROOT)) return '';
      return execFileSync('git', ['status', '--porcelain', '--untracked-files=all'], { cwd: REPO_ROOT, encoding: 'utf-8', stdio: 'pipe' });
    } catch {
      return '';
    }
  };

  it('現在のツリーのコピーで、版が DB リビジョン付きに進み、dataVersion が進んだ DB が検証を通り、元の作業ツリーは変わらないこと', async () => {
    const manifestPath = path.join(REPO_ROOT, 'public', 'manifest.json');
    const manifestText = fs.readFileSync(manifestPath, 'utf-8');
    const manifestVersion = (JSON.parse(manifestText) as { version: string }).version;
    const statusBefore = gitStatus();

    const r = (await rehearseDbRelease({
      sourceDir: REPO_ROOT,
      // 全体の npm test の代わりに、DB の検証（スキーマ・dataVersion の書式・integrity）を走らせる
      testCommand: [process.execPath, 'scripts/validate-advisories.mjs'],
      keepWorkDir: true,
    })) as RehearsalResult;
    try {
      expect(r.ok, '現在のツリーの予行（DB の検証）が失敗しました').toBe(true);
      expect(r.previousManifestVersion).toBe(manifestVersion);
      expect(r.manifestVersion).toBe(nextDbRevision(manifestVersion));
      expect(isSameRelease(r.manifestVersion, readPackageVersion())).toBe(true);
      expect(isValidYmd(r.dataVersion)).toBe(true);
      expect(r.dataVersion > r.previousDataVersion).toBe(true);
      expect(path.relative(REPO_ROOT, r.workDir).startsWith('..')).toBe(true);
      // .gitignore で除外されるビルドの出力と実サイトの取得結果はコピーしない
      expect(fs.existsSync(path.join(r.workDir, 'dist'))).toBe(false);
      expect(fs.existsSync(path.join(r.workDir, 'reports'))).toBe(false);
      expect(fs.existsSync(path.join(r.workDir, 'package.json'))).toBe(true);
    } finally {
      if (r?.workDir) fs.rmSync(r.workDir, { recursive: true, force: true });
    }

    expect(fs.readFileSync(manifestPath, 'utf-8')).toBe(manifestText);
    expect(gitStatus()).toBe(statusBefore);
  }, 120_000);
});
