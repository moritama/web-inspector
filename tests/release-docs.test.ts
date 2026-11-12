/**
 * 版上げと文書の受け入れテスト（v1.8.0 T09）
 *
 * - 版の表記（予備の文字列・画面のバッジ・README の見出し）が package.json の版と一致すること
 * - PRIVACY_POLICY に、取得するヘッダーの追加（G5）と、SRI のために integrity 属性の「有無」だけを見ることが書かれていること
 * - MAINTENANCE_GUIDE に、テストの書き方のルール、DB だけのリリースの予行、サイズ上限（G7）が書かれていること
 *
 * 版の期待値は package.json から取る（テストに版を直接書かない）。
 * 目標の版そのもの（package.json が実際に上がったか）は総合チェックの C12 が見る。
 * 既存の spec-integrity.test.ts（バッジ・lock・RULES_VERSION・仕様書の対象バージョン）と重ならない部分を足す。
 */
import { describe, expect, it } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { ALLOWED_RESPONSE_HEADERS } from '../src/background/service-worker';
import { readPackageVersion, REPO_ROOT } from './helpers/release-version';

const version = readPackageVersion();
const read = (rel: string): string => fs.readFileSync(path.join(REPO_ROOT, rel), 'utf-8');

/** G5 で取得に加えるレスポンスヘッダー（決定事項 G5） */
const G5_HEADERS = [
  'x-xss-protection',
  'cache-control',
  'server-timing',
  'x-aspnetmvc-version',
  'reporting-endpoints',
  'report-to',
  'cf-mitigated',
  'x-amzn-waf-action',
];

/** 文字列リテラルの中の「版らしい値」（3 つか 4 つの数字の並び）を拾う。日付の予備の値（2026-10-23・2026.10）は拾わない */
const findVersionLikeLiterals = (text: string): string[] =>
  [...text.matchAll(/'(\d+\.\d+\.\d+(?:\.\d+)?)'/g)].map((m) => m[1]);

describe('T09: 版の表記が package.json の版と一致すること', () => {
  it('package.json の版は 3 つの数字（DB だけのリリースの 4 つ目は manifest にだけ付く）', () => {
    expect(version).toMatch(/^\d+\.\d+\.\d+$/);
  });

  const fallbackFiles = [
    'src/background/service-worker.ts',
    'src/popup/popup.ts',
    'src/dashboard/dashboard.ts',
    'src/export/markdown.ts',
    'src/export/csv.ts',
  ];

  it.each(fallbackFiles)('%s の版の予備の文字列は、すべて package.json の版であること', (rel) => {
    const literals = findVersionLikeLiterals(read(rel));
    // 予備の文字列が 1 つ以上あり（陽性）、ほかの版が 1 つも残っていない（陰性）
    expect(literals.length, `${rel} に版の予備の文字列がありません`).toBeGreaterThan(0);
    expect(literals.filter((v) => v !== version), `${rel} に古い版の文字列が残っています`).toEqual([]);
  });

  it('版らしい値を拾う関数は、日付の予備の値を拾わず、別の版を拾うこと（検査自身の確認）', () => {
    expect(findVersionLikeLiterals(`a || '2026-10-23'; b || '2026.10'`)).toEqual([]);
    expect(findVersionLikeLiterals(`x || '0.0.1'; y || '0.0.1.2'`)).toEqual(['0.0.1', '0.0.1.2']);
  });

  it.each([
    ['popup.html', 'brandVersion'],
    ['dashboard.html', 'dashboardVersion'],
  ])('%s のバッジ（id="%s"）の中身が v + package.json の版であること', (rel, id) => {
    const html = read(rel);
    const m = html.match(new RegExp(`id="${id}"[^>]*>([^<]*)<`));
    expect(m, `${rel} に id="${id}" の要素がありません`).not.toBeNull();
    expect(m![1].trim()).toBe(`v${version}`);
  });

  it('README の「機能一覧」の見出しが package.json の版であり、ほかの版の見出しが無いこと', () => {
    const headings = read('README.md')
      .split('\n')
      .filter((line) => /^#+\s*機能一覧/.test(line));
    expect(headings.length).toBeGreaterThan(0);
    for (const h of headings) {
      expect(h, `README の見出し「${h}」`).toContain(`(v${version})`);
    }
  });
});

describe('T09: PRIVACY_POLICY（G5 のヘッダーと SRI）', () => {
  const pp = read('PRIVACY_POLICY.md');
  const ppLower = pp.toLowerCase();

  it.each(G5_HEADERS)('取得に加えたヘッダー %s が、許可リストにあり、PRIVACY_POLICY に書かれていること', (header) => {
    expect(ALLOWED_RESPONSE_HEADERS.has(header), `${header} が ALLOWED_RESPONSE_HEADERS にありません`).toBe(true);
    expect(ppLower, `PRIVACY_POLICY.md に ${header} がありません`).toContain(header);
  });

  it('認証情報を含みうる Set-Cookie は、許可リストに無く、PRIVACY_POLICY でも保持しないと書かれたままであること（陰性）', () => {
    expect(ALLOWED_RESPONSE_HEADERS.has('set-cookie')).toBe(false);
    expect(pp).toMatch(/Set-Cookie[^\n]*(excluded|never cached)/);
    expect(pp).toMatch(/Set-Cookie[^\n]*保持しません/);
  });

  it('SRI のために integrity 属性の「有無」だけを見て、値は取得・保持しないことが英語と日本語の両方で書かれていること', () => {
    expect(pp).toMatch(/presence of integrity attributes[^\n]*without capturing integrity values/i);
    expect(pp).toMatch(/integrity属性の有無[^\n]*値そのものは[^\n]*(取得|保持)しません/);
  });
});

describe('T09: MAINTENANCE_GUIDE（テストの書き方・予行・サイズ上限）', () => {
  const guide = read('docs/MAINTENANCE_GUIDE.md');

  it('テストの書き方のルール（版を直接書かない・固定 DB を使う・test-hygiene の検査）が書かれていること', () => {
    expect(guide).toContain('tests/test-hygiene.test.ts');
    expect(guide).toContain('tests/fixtures/advisory-db.fixture.json');
    expect(guide).toContain('readPackageVersion');
  });

  it('DB だけのリリースの予行（scripts/ci/rehearse-db-release.mjs）の使い方が書かれていること', () => {
    expect(guide).toContain('scripts/ci/rehearse-db-release.mjs');
  });

  it('サイズ上限（scripts/ci/check-size.mjs、advisory-db.json 2 MB・dist 合計 3 MB）が書かれていること（G7）', () => {
    expect(guide).toContain('scripts/ci/check-size.mjs');
    expect(guide).toMatch(/2\s*(MB|MiB)/);
    expect(guide).toMatch(/3\s*(MB|MiB)/);
  });
});
