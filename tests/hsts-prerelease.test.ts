/**
 * Web Technology & Security Inspector
 * v1.8.0 T03: HSTS の 1 行化とプレリリース表記の受け入れテスト (tests/hsts-prerelease.test.ts)
 *
 * 設計メモ: docs/dev/v1.8.0/design/T03.md
 */

import { describe, expect, it, vi } from 'vitest';
import { executeInspection } from '../src/background/service-worker';
import { AdvisoryDatabase, matchOfflineAdvisories, setTestAdvisoryDatabase } from '../src/detection/advisory';
import { generateMarkdownReport } from '../src/export/markdown';
import { checkHttpHeaders } from '../src/security/headers';
import { compareVersions, parseVersion, satisfiesVersionRange } from '../src/security/version-matcher';
import { SecurityCheckResult } from '../src/shared/types';
import rawFixtureDb from './fixtures/advisory-db.fixture.json';
// @ts-expect-error -- Node ESM スクリプト (.mjs) の直接インポート
import { lintReportPair as rawLintReportPair } from '../scripts/report-lint.mjs';
// @ts-expect-error scripts/validate-advisories.mjs は型定義を持たない .mjs モジュール
import { isValidRange as rawIsValidRange } from '../scripts/validate-advisories.mjs';

const fixtureDb = rawFixtureDb as unknown as AdvisoryDatabase;
const lintReportPair = rawLintReportPair as (
  report: unknown,
  markdown: string,
  options?: { includePending?: boolean }
) => { ok: boolean; violations: unknown[] };
const isValidRange = rawIsValidRange as (spec: string) => boolean;

/** 指示書が指定した、SEC-HSTS-02 の説明に付け加える文言 */
const PRELOAD_PHRASE = 'preload の登録条件も満たしていない';
const HSTS_NAME = 'HSTS (Strict-Transport-Security)';
const ONE_YEAR = 31536000;

const hstsChecksOf = (header: string): SecurityCheckResult[] =>
  checkHttpHeaders({ 'strict-transport-security': [header] }, 'https://hsts.example.test/', true).filter((c) =>
    c.checkId.startsWith('SEC-HSTS-')
  );

describe('v1.8.0 T03: HSTS — preload があり max-age が 1 年未満なら SEC-HSTS-02 の 1 行だけ', () => {
  it.each([
    { header: 'max-age=2592000; preload', severity: 'low' },
    { header: 'max-age=15552000; includeSubDomains; preload', severity: 'low' },
    { header: `max-age=${ONE_YEAR - 1}; preload`, severity: 'low' },
    { header: 'max-age=86400; preload', severity: 'low' },
    { header: 'max-age=3600; preload', severity: 'medium' },
    { header: 'max-age=3600; includeSubDomains; preload', severity: 'medium' },
  ])('$header → SEC-HSTS-02 ($severity) の 1 行だけで、説明に preload の登録条件の注記が付く', ({ header, severity }) => {
    const checks = hstsChecksOf(header);
    expect(checks).toHaveLength(1);
    const [main] = checks;
    expect(main.checkId).toBe('SEC-HSTS-02');
    expect(main.name).toBe(HSTS_NAME);
    expect(main.status).toBe('warning');
    expect(main.severity).toBe(severity);
    expect(main.description).toContain(PRELOAD_PHRASE);
    expect(checks.some((c) => c.checkId === 'SEC-HSTS-03')).toBe(false);
  });

  it.each(['max-age=2592000', 'max-age=15552000; includeSubDomains', 'max-age=3600', 'max-age=86400'])(
    '重大度は max-age の区分のまま（preload の有無で変わらない）: %s',
    (base) => {
      const without = hstsChecksOf(base);
      const withPreload = hstsChecksOf(`${base}; preload`);
      expect(without).toHaveLength(1);
      expect(withPreload).toHaveLength(1);
      expect(withPreload[0].checkId).toBe(without[0].checkId);
      expect(withPreload[0].status).toBe(without[0].status);
      expect(withPreload[0].severity).toBe(without[0].severity);
    }
  );

  it.each(['max-age=2592000', 'max-age=3600', 'max-age=15552000; includeSubDomains'])(
    '陰性: preload が無ければ説明に preload の登録条件の注記は付かない: %s',
    (header) => {
      const checks = hstsChecksOf(header);
      expect(checks).toHaveLength(1);
      expect(checks[0].checkId).toBe('SEC-HSTS-02');
      expect(checks[0].description).not.toContain(PRELOAD_PHRASE);
      expect(checks[0].description).not.toContain('preload の登録条件');
    }
  );

  it.each(['max-age=0; preload', 'max-age=0; includeSubDomains; preload', 'includeSubDomains; preload', 'preload'])(
    'max-age が 0 または未指定で preload がある場合も SEC-HSTS-03 は出ず、SEC-HSTS-02 (medium) の 1 行だけ: %s',
    (header) => {
      const checks = hstsChecksOf(header);
      expect(checks).toHaveLength(1);
      expect(checks[0].checkId).toBe('SEC-HSTS-02');
      expect(checks[0].status).toBe('warning');
      expect(checks[0].severity).toBe('medium');
    }
  );
});

describe('v1.8.0 T03: HSTS — SEC-HSTS-03 は max-age が 1 年以上で includeSubDomains だけが無いときに限る', () => {
  it.each([`max-age=${ONE_YEAR}; preload`, 'max-age=63072000; preload', `preload; max-age=${ONE_YEAR}`])(
    '陽性: %s → SEC-HSTS-00 (pass) と SEC-HSTS-03 (info) が出る',
    (header) => {
      const checks = hstsChecksOf(header);
      const pass = checks.find((c) => c.checkId === 'SEC-HSTS-00');
      const info = checks.find((c) => c.checkId === 'SEC-HSTS-03');
      expect(pass?.status).toBe('pass');
      expect(info).toBeDefined();
      expect(info?.name).toBe(HSTS_NAME);
      expect(info?.status).toBe('info');
      expect(info?.severity).toBe('info');
      expect(info?.description).toContain('includeSubDomains');
      expect(checks.some((c) => c.checkId === 'SEC-HSTS-02')).toBe(false);
    }
  );

  it.each([
    `max-age=${ONE_YEAR}; includeSubDomains; preload`,
    'max-age=63072000; includeSubDomains; preload',
    `max-age=${ONE_YEAR}`,
    `max-age=${ONE_YEAR}; includeSubDomains`,
    'max-age=2592000; preload',
    'max-age=15552000; includeSubDomains; preload',
    'max-age=2592000',
    'max-age=0; preload',
  ])('陰性: %s → SEC-HSTS-03 は出ない', (header) => {
    expect(hstsChecksOf(header).some((c) => c.checkId === 'SEC-HSTS-03')).toBe(false);
  });
});

describe('v1.8.0 T03: HSTS — レポートで HSTS の行が 1 行だけになり、整合性チェッカーが通る', () => {
  it('max-age=2592000; preload のレポートで HSTS の指摘・Markdown の表の行がそれぞれ 1 つで、lintReportPair が合格する', async () => {
    setTestAdvisoryDatabase(fixtureDb);
    const url = 'https://hsts-preload.example.test/';
    const report = await executeInspection({
      tab: { id: 301, url },
      fetchDomSignals: vi.fn().mockResolvedValue({
        url,
        title: 'HSTS preload test',
        metaTags: [],
        scriptUrls: ['https://hsts-preload.example.test/app.js'],
        linkUrls: [],
        domMarkers: [],
        htmlSnippets: [],
        mixedContent: [],
        cookiesFromDocument: [],
        cssAssets: [],
      }),
      fetchRuntimeVersions: vi.fn().mockResolvedValue({ versions: {}, frameworkMarkers: [] }),
      getCachedHeaders: vi.fn().mockResolvedValue({
        url,
        headers: {
          'strict-transport-security': ['max-age=2592000; preload'],
          'x-frame-options': ['SAMEORIGIN'],
          'x-content-type-options': ['nosniff'],
          'referrer-policy': ['strict-origin-when-cross-origin'],
          'permissions-policy': ['geolocation=()'],
          'content-security-policy': ["default-src 'self'"],
        },
      }),
      getInspectedCookies: vi.fn().mockResolvedValue([]),
      getAllFindingExceptions: vi.fn().mockResolvedValue([]),
      saveReport: vi.fn().mockResolvedValue(undefined),
    });

    const hsts = report.securityChecks.filter((c) => c.checkId.startsWith('SEC-HSTS-'));
    expect(hsts).toHaveLength(1);
    expect(hsts[0].checkId).toBe('SEC-HSTS-02');
    expect(hsts[0].severity).toBe('low');
    expect(hsts[0].description).toContain(PRELOAD_PHRASE);

    const md = generateMarkdownReport(report);
    const hstsRows = md.split('\n').filter((line) => line.startsWith(`| ${HSTS_NAME} |`));
    expect(hstsRows).toHaveLength(1);

    const lint = lintReportPair(report, md, { includePending: true });
    expect(lint.violations).toEqual([]);
    expect(lint.ok).toBe(true);
  });
});

/** SemVer 2.0.0 §11 の例の順序（https://semver.org/spec/v2.0.0.html） */
const SEMVER_PRECEDENCE_CHAIN = [
  '1.0.0-alpha',
  '1.0.0-alpha.1',
  '1.0.0-alpha.beta',
  '1.0.0-beta',
  '1.0.0-beta.2',
  '1.0.0-beta.11',
  '1.0.0-rc.1',
  '1.0.0',
];

describe('v1.8.0 T03: version-matcher — SemVer 2.0 の順序', () => {
  it('SemVer 仕様の例の順序が成り立つ（すべての組で compareVersions が前後関係と一致する）', () => {
    for (let i = 0; i < SEMVER_PRECEDENCE_CHAIN.length; i++) {
      for (let j = 0; j < SEMVER_PRECEDENCE_CHAIN.length; j++) {
        const a = SEMVER_PRECEDENCE_CHAIN[i];
        const b = SEMVER_PRECEDENCE_CHAIN[j];
        const expected = i < j ? -1 : i > j ? 1 : 0;
        expect(compareVersions(a, b), `${a} vs ${b}`).toBe(expected);
      }
    }
  });

  it('同じ順序の例にビルドメタデータを付けても順序は変わらない', () => {
    const withBuild = SEMVER_PRECEDENCE_CHAIN.map((v, i) => `${v}+sha-${i}abc`);
    for (let i = 0; i + 1 < withBuild.length; i++) {
      expect(compareVersions(withBuild[i], withBuild[i + 1]), `${withBuild[i]} < ${withBuild[i + 1]}`).toBe(-1);
      expect(compareVersions(withBuild[i], SEMVER_PRECEDENCE_CHAIN[i])).toBe(0);
    }
  });
});

describe('v1.8.0 T03: version-matcher — プレリリース識別子を SemVer 2.0 の書式全般で受け付ける', () => {
  it.each([
    // SemVer 2.0.0 §9 の例
    '1.0.0-alpha',
    '1.0.0-alpha.1',
    '1.0.0-0.3.7',
    '1.0.0-x.7.z.92',
    '1.0.0-x-y-z.--',
    // 固定の語に無い識別子
    '2.1.0-SNAPSHOT',
    '5.0.0-M1',
    '4.0.0-ga.2',
    '3.0.0-1',
  ])('%s を解析でき、プレリリースとして扱う', (v) => {
    const parsed = parseVersion(v);
    expect(parsed).not.toBeNull();
    expect(parsed?.pre).not.toBeNull();
  });

  it('固定の語に無いプレリリースも、同じ版の正式版より小さく、前の版より大きい', () => {
    for (const v of ['1.0.0-0.3.7', '1.0.0-x.7.z.92', '1.0.0-x-y-z.--', '1.0.0-SNAPSHOT', '1.0.0-M1']) {
      expect(compareVersions(v, '1.0.0'), `${v} < 1.0.0`).toBe(-1);
      expect(compareVersions('1.0.0', v), `1.0.0 > ${v}`).toBe(1);
      expect(compareVersions(v, '0.9.9'), `${v} > 0.9.9`).toBe(1);
      expect(compareVersions(v, v)).toBe(0);
    }
  });

  it('SemVer 2.0 §11 の識別子の規則: 数字だけの識別子は数値で比べ、英数字の識別子より小さく、識別子が多いほうが大きい', () => {
    expect(compareVersions('1.0.0-0.3.7', '1.0.0-x.7.z.92')).toBe(-1);
    expect(compareVersions('1.0.0-1', '1.0.0-x')).toBe(-1);
    expect(compareVersions('1.0.0-x.2', '1.0.0-x.10')).toBe(-1);
    expect(compareVersions('1.0.0-x.7.z', '1.0.0-x.7.z.92')).toBe(-1);
    expect(compareVersions('1.0.0-x.7.z.92', '1.0.0-x.7.z.92')).toBe(0);
    expect(compareVersions('1.0.0-x.7.z.92', '1.0.0-x.7.z.93')).toBe(-1);
  });

  it('観測した版が固定の語に無いプレリリースでも、範囲の照合ができる', () => {
    expect(satisfiesVersionRange('1.0.0-x.7.z.92', '< 1.0.0')).toBe(true);
    expect(satisfiesVersionRange('1.0.0-x.7.z.92', '>= 1.0.0')).toBe(false);
    expect(satisfiesVersionRange('2.1.0-SNAPSHOT', '>= 2.0.0, < 2.1.0')).toBe(false);
    expect(satisfiesVersionRange('2.1.0-SNAPSHOT', '>= 2.0.0, < 2.1.1')).toBe(true);
  });
});

describe('v1.8.0 T03: version-matcher — ビルドメタデータは比較で無視する', () => {
  it.each([
    // SemVer 2.0.0 §10 の例
    ['1.0.0-alpha+001', '1.0.0-alpha'],
    ['1.0.0+20130313144700', '1.0.0'],
    ['1.0.0-beta+exp.sha.5114f85', '1.0.0-beta'],
    ['1.0.0+21AF26D3----117B344092BD', '1.0.0'],
    // +sha-… の形
    ['3.2.1+sha-abc1234', '3.2.1'],
    ['3.2.1+sha-abc1234', '3.2.1+sha-def5678'],
    ['1.0.0-x.7.z.92+sha-abc1234', '1.0.0-x.7.z.92'],
  ])('%s と %s は同じ順位', (a, b) => {
    expect(compareVersions(a, b)).toBe(0);
    expect(compareVersions(b, a)).toBe(0);
  });

  it('ビルドメタデータ付きの版も範囲の照合ができる', () => {
    expect(compareVersions('3.2.1-rc.1+sha-abc1234', '3.2.1')).toBe(-1);
    expect(satisfiesVersionRange('3.2.1+sha-abc1234', '< 3.2.2')).toBe(true);
    expect(satisfiesVersionRange('3.2.2+sha-abc1234', '< 3.2.2')).toBe(false);
    expect(satisfiesVersionRange('3.2.2+sha-abc1234', '= 3.2.2')).toBe(true);
  });
});

describe('v1.8.0 T03: version-matcher — 今受け付けている表記はそのまま', () => {
  it('rc1・-next.0・-next.0.0.0・-rc.4 などの表記を従来どおり解析・比較できる', () => {
    for (const v of ['3.5.0-rc1', '22.0.0-next.0', '20.0.0-next.0.0.0', '22.0.0-rc.4', '1.0.0-beta.2', '1.0.0-alpha.1']) {
      expect(parseVersion(v), v).not.toBeNull();
    }
    expect(compareVersions('3.5.0-rc1', '3.5.0')).toBe(-1);
    expect(compareVersions('1.0.0-rc2', '1.0.0-rc10')).toBe(-1);
    expect(compareVersions('22.0.0-next.3', '22.0.0-rc.1')).toBe(-1);
    expect(satisfiesVersionRange('22.0.0-next.1', '>= 22.0.0-next.0, < 22.0.0-next.3')).toBe(true);
    expect(satisfiesVersionRange('3.5.0-rc1', '< 3.5.0')).toBe(true);
  });
});

describe('v1.8.0 T03: version-matcher — 解析できない文字列は従来どおり Unknown Version (SPEC-06)', () => {
  it.each([
    '1.0.0-',
    '1.0.0-alpha..1',
    '1.0.0-.alpha',
    '1.0.0-alpha.',
    '1.0.0-al_pha',
    '1.0.0-al pha',
    '1.0.0-αβ',
    '1.0.0-alpha!',
    '1.0.0+',
    '1.0.0+build+x',
    'custom-build',
    'abc',
  ])('%s は解析できない（parseVersion が null、範囲にも一致しない）', (v) => {
    expect(parseVersion(v)).toBeNull();
    expect(satisfiesVersionRange(v, '< 99.0.0')).toBe(false);
    expect(satisfiesVersionRange(v, '>= 0.0.0')).toBe(false);
  });

  it('照合: 書式の誤ったプレリリースは Unknown Version、SemVer 2.0 の書式のプレリリースは Unknown Version にならない', () => {
    const broken = matchOfflineAdvisories('jQuery', '3.5.0-al_pha', fixtureDb);
    expect(broken.offlineMatchStatus).toBe('Unknown Version');
    expect(broken.advisories).toHaveLength(0);

    const generic = matchOfflineAdvisories('jQuery', '3.5.0-x.7.z.92', fixtureDb);
    expect(generic.offlineMatchStatus).not.toBe('Unknown Version');
  });
});

describe('v1.8.0 T03: version-matcher — DB の range の検証（isValidRange）と照合の一致', () => {
  // DB の range の書式は v1.8.0 では変えない（scripts/validate-advisories.mjs は変更しない）。
  // 検証が拒否する range の比較節には、照合も一致させない（壊れた DB の値で CVE を該当させない）。
  it.each(['>= 1.0.0-nxt', '>= 1.0.0-nxt, < 2.0.0', '< 2.0.0-x.7.z.92', '>= 1.0.0-SNAPSHOT', '< 2.0.0-0.3.7'])(
    '検証が拒否する range (%s) には、どの版も一致しない',
    (range) => {
      expect(isValidRange(range)).toBe(false);
      for (const v of ['0.1.0', '1.0.0', '1.5.0', '2.0.0-alpha', '1.5.0-x.7.z.92', '3.0.0']) {
        expect(satisfiesVersionRange(v, range), `${v} in ${range}`).toBe(false);
      }
    }
  );

  it.each([
    ['>= 1.0.0-rc.1, < 2.0.0', '1.5.0', true],
    ['>= 1.0.0-rc.1, < 2.0.0', '1.0.0-beta.11', false],
    ['< 22.0.0-next.3', '22.0.0-next.2', true],
    ['< 3.5.0', '3.5.0-rc1', true],
  ])('検証が受け付ける range (%s) は従来どおり照合できる: %s → %s', (range, v, expected) => {
    expect(isValidRange(range)).toBe(true);
    expect(satisfiesVersionRange(v, range)).toBe(expected);
  });
});
