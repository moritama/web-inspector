/**
 * テストの衛生検査（v1.8.0 T01）
 *
 * DB だけの自動リリース（manifest の版に 4 つ目の番号が付く・同梱 DB の中身が変わる）でテストが落ちないよう、
 * (1) 許可リスト外のテストが同梱 DB（src/detection/advisory-db.json）を読まないこと
 * (2) 許可リスト外のテストに、現在の package.json の版の文字列が直接書かれていないこと
 * を検査する。検査が機能すること（違反を置くと落ちること）も、一時ディレクトリに違反を置いて確かめる。
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { readPackageVersion, REPO_ROOT } from './helpers/release-version';
import {
  BUNDLED_DB_READ_ALLOWLIST,
  findBundledAdvisoryDbReads,
  findVersionLiterals,
  formatViolations,
  listTestSourceFiles,
  scanTestHygiene,
  VERSION_LITERAL_ALLOWLIST,
} from './helpers/test-hygiene';

// この検査ファイル自身が検査に引っかからないよう、同梱 DB のファイル名は組み立てて使う
const BUNDLED_DB_FILE = ['advisory-db', 'json'].join('.');
const FIXTURE_DB_FILE = ['advisory-db', 'fixture', 'json'].join('.');

const version = readPackageVersion();

describe('test-hygiene: リポジトリのテストの検査', () => {
  it('検査の対象に tests/ の .ts と .mjs が含まれ、人が取得したスナップショットは含まれないこと', () => {
    const files = listTestSourceFiles(REPO_ROOT);
    expect(files).toContain('tests/test-hygiene.test.ts');
    expect(files).toContain('tests/advisory-pipeline.test.mjs');
    expect(files.some((f) => f.startsWith('tests/fixtures/snapshots/'))).toBe(false);
  });

  it('許可リストのファイルは実在し、同梱 DB を読んでよいのは advisory-db-invariants.test.ts を含む許可リストだけであること', () => {
    expect(BUNDLED_DB_READ_ALLOWLIST).toContain('tests/advisory-db-invariants.test.ts');
    for (const rel of [...BUNDLED_DB_READ_ALLOWLIST, ...VERSION_LITERAL_ALLOWLIST]) {
      expect(fs.existsSync(path.join(REPO_ROOT, rel)), `${rel} が存在しません`).toBe(true);
    }
  });

  it('(1) 許可リスト外のテストが、同梱 DB（src/detection/advisory-db.json）を読んでいないこと', () => {
    const violations = scanTestHygiene({ rootDir: REPO_ROOT, version }).filter((v) => v.rule === 'bundled-advisory-db');
    expect(violations, formatViolations(violations)).toEqual([]);
  });

  it('(2) 許可リスト外のテストに、現在の package.json の版の文字列が直接書かれていないこと', () => {
    const violations = scanTestHygiene({ rootDir: REPO_ROOT, version }).filter((v) => v.rule === 'current-version-literal');
    expect(violations, formatViolations(violations)).toEqual([]);
  });
});

describe('test-hygiene: 検査が機能すること（違反を置いた一時ディレクトリ）', () => {
  let tmpRoot = '';

  const writeTestFile = (rel: string, content: string): void => {
    const abs = path.join(tmpRoot, ...rel.split('/'));
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, 'utf-8');
  };

  beforeAll(() => {
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'test-hygiene-'));
  });

  afterAll(() => {
    if (tmpRoot) fs.rmSync(tmpRoot, { recursive: true, force: true });
  });

  it('違反の無い一時ディレクトリでは、違反が 0 件であること（陰性）', () => {
    writeTestFile(
      'tests/clean.test.ts',
      [
        `import fixtureDb from './fixtures/${FIXTURE_DB_FILE}';`,
        `import { readPackageVersion } from './helpers/release-version';`,
        `describe('v${version} T01: 題名の中の版の言及は対象にしない', () => {`,
        `  // コメントの中の版の言及（例: ${version}.1）も対象にしない`,
        `  it('x', () => { expect(readPackageVersion()).toBe(pkg.version); });`,
        `});`,
        `const changedFiles = ['src/detection/${BUNDLED_DB_FILE}', 'public/manifest.json'];`,
        '',
      ].join('\n')
    );
    const violations = scanTestHygiene({ rootDir: tmpRoot, version });
    expect(violations, formatViolations(violations)).toEqual([]);
  });

  it('(1) 許可リスト外に同梱 DB を import するテストを置くと、違反として検出されること（陽性）', () => {
    writeTestFile('tests/bad-db-import.test.ts', `import db from '../src/detection/${BUNDLED_DB_FILE}';\n`);
    const violations = scanTestHygiene({ rootDir: tmpRoot, version });
    expect(violations.some((v) => v.file === 'tests/bad-db-import.test.ts' && v.rule === 'bundled-advisory-db')).toBe(true);
  });

  it('(1) fs.readFileSync と path.join で同梱 DB を読むテスト（引数が複数行）も、違反として検出されること（陽性）', () => {
    writeTestFile(
      'tests/nested/bad-db-read.test.mjs',
      [
        `const db = JSON.parse(`,
        `  fs.readFileSync(path.join(rootDir, 'src', 'detection', '${BUNDLED_DB_FILE}'), 'utf-8')`,
        `);`,
        `const db2 = JSON.parse(fs.readFileSync(`,
        `  'src/detection/${BUNDLED_DB_FILE}',`,
        `  'utf-8'));`,
        `const db3 = await import('../../src/detection/${BUNDLED_DB_FILE}');`,
        '',
      ].join('\n')
    );
    const violations = scanTestHygiene({ rootDir: tmpRoot, version }).filter(
      (v) => v.file === 'tests/nested/bad-db-read.test.mjs' && v.rule === 'bundled-advisory-db'
    );
    // 3 か所（path.join の部品・readFileSync の引数・動的 import）すべてが検出されること
    expect(violations.map((v) => v.line)).toEqual(expect.arrayContaining([2, 5, 7]));
  });

  it('(1) 同じ内容でも、許可リストのファイルなら違反にならないこと（陰性）', () => {
    const allowed = BUNDLED_DB_READ_ALLOWLIST[0];
    writeTestFile(allowed, `import db from '../src/detection/${BUNDLED_DB_FILE}';\n`);
    const violations = scanTestHygiene({ rootDir: tmpRoot, version });
    expect(violations.some((v) => v.file === allowed)).toBe(false);
  });

  it('(2) 許可リスト外に現在の版を直接書いたテストを置くと、違反として検出されること（陽性）', () => {
    const [major, minor, patch] = version.split('.');
    writeTestFile(
      'tests/bad-version.test.ts',
      [
        `expect(pkg.version).toBe('${version}');`,
        `expect(manifest.version).toBe("${version}.1");`,
        `expect(tag).toBe(\`v${version}\`);`,
        `expect(manifest.version).toMatch(/^${major}\\.${minor}\\.${patch}(\\.\\d+)?$/);`,
        '',
      ].join('\n')
    );
    const violations = scanTestHygiene({ rootDir: tmpRoot, version }).filter(
      (v) => v.file === 'tests/bad-version.test.ts' && v.rule === 'current-version-literal'
    );
    expect(violations.map((v) => v.line).sort()).toEqual([1, 2, 3, 4]);
  });

  it('(2) 許可リストに入れたファイルは、版の文字列があっても違反にならないこと（陰性）', () => {
    writeTestFile('tests/allowed-version.test.ts', `expect(x).toBe('${version}');\n`);
    const violations = scanTestHygiene({
      rootDir: tmpRoot,
      version,
      versionAllowlist: ['tests/allowed-version.test.ts'],
    });
    expect(violations.some((v) => v.file === 'tests/allowed-version.test.ts')).toBe(false);
  });

  it('スナップショットのディレクトリ（tests/fixtures/snapshots/）に置いたものは、検査の対象外であること（陰性）', () => {
    writeTestFile('tests/fixtures/snapshots/site.example.test/data.mjs', `export const v = '${version}';\nimport db from '../src/detection/${BUNDLED_DB_FILE}';\n`);
    const violations = scanTestHygiene({ rootDir: tmpRoot, version });
    expect(violations.some((v) => v.file.startsWith('tests/fixtures/snapshots/'))).toBe(false);
  });
});

describe('test-hygiene: 判定の境界', () => {
  it('版の文字列の検出は、別の版（先頭・末尾に数字が続くもの）を誤検出しないこと', () => {
    const [major, minor, patch] = version.split('.').map(Number);
    const longer = `${major}.${minor}.${patch}0`;
    const prefixed = `1${major}.${minor}.${patch}`;
    const other = `${major}.${minor}.${patch + 1}`;
    expect(findVersionLiterals(`x('${longer}'); y('${prefixed}'); z('${other}');`, version)).toEqual([]);
    expect(findVersionLiterals(`x('${version}');`, version)).toHaveLength(1);
  });

  it('同梱 DB の検出は、固定 DB（advisory-db.fixture.json）の読み込みを誤検出しないこと', () => {
    expect(findBundledAdvisoryDbReads(`import f from './fixtures/${FIXTURE_DB_FILE}';`)).toEqual([]);
    expect(findBundledAdvisoryDbReads(`fs.readFileSync(path.join(__dirname, 'fixtures', '${FIXTURE_DB_FILE}'))`)).toEqual([]);
    expect(findBundledAdvisoryDbReads(`import f from '../src/detection/${BUNDLED_DB_FILE}';`)).toHaveLength(1);
  });
});
