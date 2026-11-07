/**
 * Web Technology & Security Inspector
 * レポート整合性チェッカー & collect-reports 拡張 単体テスト (tests/report-lint.test.ts) - v1.7.1 T03
 */

import path from 'node:path';
import fs from 'node:fs';
import { describe, expect, it, vi } from 'vitest';
import { executeInspection } from '../src/background/service-worker';
import { AdvisoryDatabase, setTestAdvisoryDatabase } from '../src/detection/advisory';
import { generateMarkdownReport } from '../src/export/markdown';
import { summarizeSecurityChecks } from '../src/shared/security-status';
import { InspectionReport } from '../src/shared/types';
import rawFixtureDb from './fixtures/advisory-db.fixture.json';
import {
  CHECK_DEFINITIONS as rawCheckDefinitions,
  getPendingChecks as rawGetPendingChecks,
  lintDirectory as rawLintDirectory,
  lintReportPair as rawLintReportPair,
  main as rawRunLintCli,
  // @ts-expect-error -- Node ESM スクリプト (.mjs) の直接インポート
} from '../scripts/report-lint.mjs';
import {
  buildSummary as rawBuildSummary,
  maskSetCookieValue as rawMaskSetCookieValue,
  parseArgs as rawParseArgs,
  sanitizeSnapshotCookies as rawSanitizeSnapshotCookies,
  sanitizeSnapshotHeaders as rawSanitizeSnapshotHeaders,
  // @ts-expect-error -- Node ESM スクリプト (.mjs) の直接インポート
} from '../scripts/collect-reports.mjs';

interface LintCheckDefinition {
  id: string;
  number: number;
  title: string;
  pending: boolean;
  pendingUntil: string | null;
}

interface LintViolationItem {
  id: string;
  number: number;
  title: string;
  pending?: boolean;
  message: string;
}

interface LintCheckResultItem {
  id: string;
  number: number;
  title: string;
  pending: boolean;
  pendingUntil: string | null;
  passed: boolean;
  violations: string[];
}

interface LintReportResult {
  ok: boolean;
  results: LintCheckResultItem[];
  violations: LintViolationItem[];
  pendingViolations: LintViolationItem[];
  passedChecks: number;
  failedChecks: number;
  pendingChecks: number;
}

interface LintFileResult extends LintReportResult {
  name: string;
  jsonPath: string;
  mdPath: string;
}

interface LintDirectoryResult {
  ok: boolean;
  dirPath: string;
  totalFiles: number;
  passedFiles: number;
  failedFiles: number;
  pendingCount: number;
  pendingDefs: LintCheckDefinition[];
  fileResults: LintFileResult[];
}

interface LintOptions {
  includePending?: boolean;
  pendingIds?: string[];
}

const CHECK_DEFINITIONS = rawCheckDefinitions as LintCheckDefinition[];
const getPendingChecks = rawGetPendingChecks as (options?: LintOptions) => LintCheckDefinition[];
const lintReportPair = rawLintReportPair as (
  report: InspectionReport,
  markdown: string,
  options?: LintOptions
) => LintReportResult;
const lintDirectory = rawLintDirectory as (
  dirPath: string,
  options?: LintOptions
) => LintDirectoryResult;
const runLintCli = rawRunLintCli as (argv?: string[]) => number;
const parseArgs = rawParseArgs as (argv: string[]) => {
  sites: string | null;
  out: string | null;
  headless: boolean;
  executable: string | null;
  waitMs: number;
  timeoutMs: number;
  inspectTimeoutMs: number;
  strictTls: boolean;
  snapshot: boolean;
  urls: string[];
};
const maskSetCookieValue = rawMaskSetCookieValue as (rawSetCookie: string) => string;
const sanitizeSnapshotHeaders = rawSanitizeSnapshotHeaders as (
  rawHeaders: Array<{ name: string; value: string }> | Record<string, string | string[]>
) => Record<string, string[]>;
const sanitizeSnapshotCookies = rawSanitizeSnapshotCookies as (
  rawCookies: Array<Record<string, unknown>>
) => Array<Record<string, unknown>>;
const buildSummary = rawBuildSummary as (
  results: Array<Record<string, unknown>>,
  meta?: Record<string, unknown>
) => string;

const FIXTURES_DIR = path.resolve(__dirname, 'fixtures', 'reports');

/**
 * テスト用の最小限の正常なレポート（JSON）を生成するヘルパー
 */
function createValidBaseReport(): InspectionReport {
  return {
    id: 'rep_lint_base',
    url: 'https://valid.example.test/',
    hostname: 'valid.example.test',
    inspectedAt: '2026-11-01T00:00:00.000Z',
    extensionVersion: '1.7.0',
    rulesVersion: '1.7.0',
    advisoryDatabaseVersion: '2026-10-31',
    coverage: {
      dom: 'complete',
      headers: 'complete',
      cookies: 'complete',
      iframes: 'not-applicable',
      network: 'complete',
      overallStatus: 'complete',
    },
    summary: {
      totalTechnologies: 1,
      requiresAttentionCount: 1,
      securityFindings: {
        critical: 0,
        high: 0,
        medium: 1,
        low: 0,
        info: 2,
        unknown: 0,
      },
      librarySecurity: {
        eolCount: 0,
        vulnerableLibraryCount: 0,
        mismatchCount: 0,
      },
      isHttps: true,
      mixedContentCount: 0,
    },
    technologies: [
      {
        technology: 'jQuery',
        category: 'js-css-library',
        detected: true,
        version: '3.7.1',
        confidence: 90,
        confidenceLevel: 'high',
        supportStatus: 'Supported',
        advisoryMatchStatus: 'Not Affected',
        offlineMatchStatus: 'No Match',
        productAdvisoryCount: 4,
        productSources: ['curated', 'OSV', 'NVD'],
        advisoryDataVersion: '20261031',
        advisories: [],
        evidence: [
          {
            type: 'script-url',
            name: 'script[src]',
            value: 'https://valid.example.test/js/jquery-3.7.1.min.js',
            source: 'https://valid.example.test/',
            weight: 90,
          },
        ],
      },
    ],
    securityChecks: [
      {
        checkId: 'SEC-HTTPS-01',
        category: 'https-communication',
        name: 'HTTPS暗号化通信',
        status: 'pass',
        severity: 'info',
        observed: 'HTTPSで接続（証明書の有効性は対象外）',
        description: 'HTTPSで通信されています。',
        recommendation: '現状の設定を維持してください。',
        referenceUrls: [],
        scope: 'https://valid.example.test/',
      },
      {
        checkId: 'SEC-REF-01',
        category: 'http-headers',
        name: 'Referrer-Policy',
        status: 'info',
        severity: 'info',
        observed: 'ヘッダー未設定（ブラウザ既定: strict-origin-when-cross-origin 相当）',
        description: 'ブラウザ既定値により保護されます。',
        recommendation: '明示的な設定を検討してください。',
        referenceUrls: [],
        scope: 'https://valid.example.test/',
      },
      {
        checkId: 'SEC-HSTS-01',
        category: 'http-headers',
        name: 'HSTS (Strict-Transport-Security)',
        status: 'warning',
        severity: 'medium',
        observed: 'ヘッダー未設定',
        description: 'HSTSヘッダーが未設定です。',
        recommendation: 'Strict-Transport-Securityヘッダーを付与してください。',
        referenceUrls: [],
        scope: 'https://valid.example.test/',
      },
    ],
    cookies: [
      {
        name: 'SERVER_ID',
        domain: 'valid.example.test',
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'lax',
        category: 'general',
      },
    ],
    cspPolicies: [],
    mixedContent: [],
    externalConnections: {
      totalConnections: 1,
      firstPartyCount: 1,
      thirdPartyCount: 0,
      categoryBreakdown: {
        cdn: 0,
        analytics: 0,
        advertising: 0,
        fonts: 0,
        social: 0,
        api: 0,
        other: 1,
      },
      connections: [
        {
          hostname: 'valid.example.test',
          registrableDomain: 'example.test',
          publicSuffix: 'test',
          partyType: 'first-party',
          category: 'other',
          resourceCount: 2,
          sampleUrls: [
            'https://valid.example.test/',
            'https://valid.example.test/js/jquery-3.7.1.min.js',
          ],
        },
      ],
    },
  };
}

describe('v1.7.1 T03: レポート整合性チェッカー (scripts/report-lint.mjs)', () => {
  it('正常なレポート（JSON と Markdown の組）では保留項目を含めて全 9 項目が合格すること', () => {
    const report = createValidBaseReport();
    const md = generateMarkdownReport(report);
    const result = lintReportPair(report, md, { includePending: true });

    expect(result.ok).toBe(true);
    expect(result.violations).toEqual([]);
    expect(result.results.length).toBe(9);
    expect(result.results.every((r) => r.passed)).toBe(true);
  });

  it('T05・T10 で全 9 項目が既定で有効（保留 0 件）になっていること', () => {
    const pending = getPendingChecks();
    expect(pending.map((p) => p.id)).toEqual([]);
    expect(CHECK_DEFINITIONS.length).toBe(9);
    expect(CHECK_DEFINITIONS.every((d) => !d.pending)).toBe(true);
  });

  describe('各検査項目 (1)〜(9) の違反検出検証', () => {
    it('(1) R01: 要確認件数と重大度内訳（CRITICAL〜LOW の合計）が一致しない場合に不合格になること', () => {
      const report = createValidBaseReport();
      // info 項目の Referrer-Policy が誤って low にカウントされている不整合を模擬
      report.summary.securityFindings.low = 1;
      const md = generateMarkdownReport(report);

      const res = lintReportPair(report, md);
      expect(res.ok).toBe(false);
      const r01 = res.results.find((r) => r.id === 'R01');
      expect(r01?.passed).toBe(false);
      expect(res.violations.some((v) => v.id === 'R01')).toBe(true);
    });

    it('(2) R02: JSON の status が info なのに Markdown 表のステータスが **WARN** の場合に不合格になること', () => {
      const report = createValidBaseReport();
      const md = generateMarkdownReport(report).replace(
        '| Referrer-Policy | INFO | INFO |',
        '| Referrer-Policy | **WARN** | INFO |'
      );

      const res = lintReportPair(report, md);
      expect(res.ok).toBe(false);
      const r02 = res.results.find((r) => r.id === 'R02');
      expect(r02?.passed).toBe(false);
      expect(r02?.violations[0]).toContain('Referrer-Policy');
    });

    it('(3) R03: ロードマップに要確認の指摘と対応しない固定文がある場合に不合格になること', () => {
      const report = createValidBaseReport();
      const md = generateMarkdownReport(report).replace(
        '- **HSTS (Strict-Transport-Security)**: Strict-Transport-Securityヘッダーを付与してください。',
        '- **暗号化通信（HTTPS）および混在コンテンツの完全解消**: 平文通信を廃止してください。'
      );

      const res = lintReportPair(report, md);
      expect(res.ok).toBe(false);
      const r03 = res.results.find((r) => r.id === 'R03');
      expect(r03?.passed).toBe(false);
      expect(r03?.violations.some((m) => m.includes('暗号化通信（HTTPS）'))).toBe(true);
    });

    it('(4) R04: 根拠のホストが通信先に含まれない場合、または alternate / form の送信先だけのホストが通信先にある場合に不合格になること', () => {
      // ケースA: 根拠のホスト (cdn.example.test) が externalConnections にない
      const reportMissingHost = createValidBaseReport();
      reportMissingHost.technologies[0].evidence = [
        {
          type: 'script-url',
          name: 'script[src]',
          value: 'https://cdn.example.test/jquery-3.7.1.min.js',
          source: 'https://valid.example.test/',
          weight: 90,
        },
      ];
      const mdA = generateMarkdownReport(reportMissingHost);
      const resA = lintReportPair(reportMissingHost, mdA);
      expect(resA.ok).toBe(false);
      const r04A = resA.results.find((r) => r.id === 'R04');
      expect(r04A?.passed).toBe(false);
      expect(r04A?.violations[0]).toContain('cdn.example.test');

      // ケースB: form の送信先だけのホスト (form-only.example.test) が通信先に入っている
      const reportFormHost = createValidBaseReport();
      reportFormHost.mixedContent = [
        {
          resourceType: 'form',
          url: 'http://form-only.example.test/submit',
        },
      ];
      reportFormHost.externalConnections!.connections.push({
        hostname: 'form-only.example.test',
        registrableDomain: 'example.test',
        publicSuffix: 'test',
        partyType: 'first-party',
        category: 'other',
        resourceCount: 1,
        sampleUrls: ['http://form-only.example.test/submit'],
      });
      const mdB = generateMarkdownReport(reportFormHost);
      const resB = lintReportPair(reportFormHost, mdB);
      expect(resB.ok).toBe(false);
      const r04B = resB.results.find((r) => r.id === 'R04');
      expect(r04B?.passed).toBe(false);
      expect(r04B?.violations[0]).toContain('form-only.example.test');
    });

    it('(5) R05: X-Frame-Options などの同じ項目名が status によって変わっている場合に不合格になること', () => {
      const report = createValidBaseReport();
      report.securityChecks.push({
        checkId: 'SEC-XFO-01',
        category: 'http-headers',
        name: 'X-Frame-Options / frame-ancestors', // v1.7.0 の旧名称
        status: 'pass',
        severity: 'info',
        observed: 'SAMEORIGIN',
        description: '保護されています。',
        recommendation: '維持してください。',
        referenceUrls: [],
        scope: 'https://valid.example.test/',
      });
      const { requiresAttentionCount, securityFindings } = summarizeSecurityChecks(
        report.securityChecks
      );
      report.summary.requiresAttentionCount = requiresAttentionCount;
      report.summary.securityFindings = securityFindings;
      const md = generateMarkdownReport(report);

      const res = lintReportPair(report, md);
      expect(res.ok).toBe(false);
      const r05 = res.results.find((r) => r.id === 'R05');
      expect(r05?.passed).toBe(false);
      expect(r05?.violations[0]).toContain('X-Frame-Options');
    });

    it('(6) R06: コードスパン内にバックスラッシュ (\\) がある場合に不合格になること', () => {
      const report = createValidBaseReport();
      const md = generateMarkdownReport(report).replace('`SERVER_ID`', '`SERVER\\_ID`');

      const res = lintReportPair(report, md);
      expect(res.ok).toBe(false);
      const r06 = res.results.find((r) => r.id === 'R06');
      expect(r06?.passed).toBe(false);
      expect(r06?.violations[0]).toContain('SERVER\\_ID');
    });

    it('(7) R07: 同じ技術に同じ根拠が重複している場合に不合格になること', () => {
      const report = createValidBaseReport();
      const dupEv = report.technologies[0].evidence[0];
      report.technologies[0].evidence.push({ ...dupEv });
      const md = generateMarkdownReport(report);

      const res = lintReportPair(report, md);
      expect(res.ok).toBe(false);
      const r07 = res.results.find((r) => r.id === 'R07');
      expect(r07?.passed).toBe(false);
      expect(r07?.violations.length).toBeGreaterThanOrEqual(1);
    });

    it('(8) R08: 完全性が「完全 (complete)」なのに通信先が 0 件の場合に不合格になること', () => {
      const report = createValidBaseReport();
      report.externalConnections = {
        totalConnections: 0,
        firstPartyCount: 0,
        thirdPartyCount: 0,
        categoryBreakdown: {
          cdn: 0,
          analytics: 0,
          advertising: 0,
          fonts: 0,
          social: 0,
          api: 0,
          other: 0,
        },
        connections: [],
      };
      const md = generateMarkdownReport(report);

      const res = lintReportPair(report, md);
      expect(res.ok).toBe(false);
      const r08 = res.results.find((r) => r.id === 'R08');
      expect(r08?.passed).toBe(false);
    });

    it('(9) R09: CSP があるページの CSP の重大度が「CSP なし」(medium) を上回る場合に不合格になり、medium 以下なら合格すること', () => {
      const report = createValidBaseReport();
      report.cspPolicies = [
        {
          id: 'csp_header_01',
          source: 'response-header',
          mode: 'enforce',
          directives: { 'frame-ancestors': ["'self'"] },
          rawValue: "frame-ancestors 'self'",
          warnings: [],
          observedAt: '2026-11-01T00:00:00.000Z',
        },
      ];
      report.securityChecks.push({
        checkId: 'SEC-CSP-03',
        category: 'http-headers',
        name: 'CSP (Content-Security-Policy)',
        status: 'warning',
        severity: 'high',
        observed: 'script-src 未指定 / object-src 未指定 / base-uri 未指定',
        description: 'CSPポリシーに改善点があります。',
        recommendation: '信頼できるオリジンを指定した script-src または default-src を設定してください。',
        referenceUrls: [],
        scope: 'https://valid.example.test/',
      });
      const badSummary = summarizeSecurityChecks(report.securityChecks);
      report.summary.requiresAttentionCount = badSummary.requiresAttentionCount;
      report.summary.securityFindings = badSummary.securityFindings;

      const badMd = generateMarkdownReport(report);
      const badRes = lintReportPair(report, badMd);
      expect(badRes.ok).toBe(false);
      const r09Bad = badRes.results.find((r) => r.id === 'R09');
      expect(r09Bad?.passed).toBe(false);

      // 重大度を上限の medium に修正すると全 9 項目が合格すること
      const cspCheck = report.securityChecks.find((c) => c.checkId === 'SEC-CSP-03')!;
      cspCheck.severity = 'medium';
      const goodSummary = summarizeSecurityChecks(report.securityChecks);
      report.summary.requiresAttentionCount = goodSummary.requiresAttentionCount;
      report.summary.securityFindings = goodSummary.securityFindings;

      const goodMd = generateMarkdownReport(report);
      const goodRes = lintReportPair(report, goodMd);
      expect(goodRes.ok).toBe(true);
      const r09Good = goodRes.results.find((r) => r.id === 'R09');
      expect(r09Good?.passed).toBe(true);
    });
  });

  describe('v1.7.0 のレポート（修正前の形）と T01・T02 後の出力の比較検証', () => {
    it('1.7.0 のレポート（修正前の形）を与えると (1)(2)(3)(6) が不合格になり、T01・T02 後の出力では合格すること', () => {
      // 1. v1.7.0 修正前の JSON: Referrer-Policy が status: 'info', severity: 'low' で securityFindings.low に加算されていた
      const v170Report: InspectionReport = createValidBaseReport();
      v170Report.securityChecks = [
        {
          checkId: 'SEC-HTTPS-01',
          category: 'https-communication',
          name: 'HTTPS暗号化通信',
          status: 'pass',
          severity: 'info',
          observed: 'HTTPS使用中',
          description: 'HTTPSで通信されています。',
          recommendation: '現状の設定を維持してください。',
          referenceUrls: [],
          scope: 'https://valid.example.test/',
        },
        {
          checkId: 'SEC-REF-01',
          category: 'http-headers',
          name: 'Referrer-Policy',
          status: 'info',
          severity: 'low', // v1.7.0 では low だった
          observed: 'ヘッダー未設定',
          description: '未設定です。',
          recommendation: '設定を検討してください。',
          referenceUrls: [],
          scope: 'https://valid.example.test/',
        },
        {
          checkId: 'SEC-HSTS-01',
          category: 'http-headers',
          name: 'HSTS (Strict-Transport-Security)',
          status: 'warning',
          severity: 'medium',
          observed: 'ヘッダー未設定',
          description: 'HSTS未設定',
          recommendation: 'Strict-Transport-Securityヘッダーを付与してください。',
          referenceUrls: [],
          scope: 'https://valid.example.test/',
        },
      ];
      // v1.7.0 では requiresAttentionCount は warning/fail のみ (1件) だが、securityFindings は low: 1, medium: 1 (計2件) になっていた
      v170Report.summary.requiresAttentionCount = 1;
      v170Report.summary.securityFindings = {
        critical: 0,
        high: 0,
        medium: 1,
        low: 1,
        info: 1,
        unknown: 0,
      };

      // v1.7.0 修正前の Markdown:
      // - (1) 要確認項目数 1 件に対し MEDIUM 1 + LOW 1 = 2 件
      // - (2) status: 'info' の Referrer-Policy が **WARN** と表示
      // - (3) セクション 13 が固定文のロードマップ
      // - (6) コードスパン内の SERVER_ID や script[src] にバックスラッシュ (\) が入っている
      const v170Markdown = generateMarkdownReport(v170Report)
        .replace('| Referrer-Policy | INFO | LOW |', '| Referrer-Policy | **WARN** | LOW |')
        .replace(
          '1. **計画的対応 (MEDIUM):**\n   - **HSTS (Strict-Transport-Security)**: Strict-Transport-Securityヘッダーを付与してください。',
          [
            '1. **至急対応 (CRITICAL / HIGH):**',
            '   - **暗号化通信（HTTPS）および混在コンテンツの完全解消**: 平文通信やHTTPサブリソースの読み込みを廃止してください。',
            '   - **悪用確認済み脆弱性（CISA KEV）および HIGH リスク CVE の解消**: 該当ライブラリを修正済みバージョンへ更新してください。',
            '2. **計画的対応 (MEDIUM):**',
            '   - **CSP（Content-Security-Policy）および HSTS の段階的導入**: Report-Only モードで影響範囲を確認した上で本番適用してください。',
            '3. **継続的改善 (LOW / INFO):**',
            '   - **外部サードパーティスクリプトの棚卸しと整合性検証（SRI導入）**: 不要な外部タグを削除してください。',
          ].join('\n')
        )
        .replace('`SERVER_ID`', '`SERVER\\_ID`')
        .replace('`script[src]`', '`script\\[src\\]`');

      const v170LintResult = lintReportPair(v170Report, v170Markdown);
      expect(v170LintResult.ok).toBe(false);

      const failedIds = v170LintResult.results
        .filter((r) => !r.pending && !r.passed)
        .map((r) => r.id);
      expect(failedIds).toEqual(['R01', 'R02', 'R03', 'R06']);

      // 2. T01・T02 修正後の出力ではすべて合格する
      const v171Report: InspectionReport = createValidBaseReport();
      const { requiresAttentionCount, securityFindings } = summarizeSecurityChecks(
        v171Report.securityChecks
      );
      v171Report.summary.requiresAttentionCount = requiresAttentionCount;
      v171Report.summary.securityFindings = securityFindings;
      const v171Markdown = generateMarkdownReport(v171Report);

      const v171LintResult = lintReportPair(v171Report, v171Markdown);
      expect(v171LintResult.ok).toBe(true);
      expect(v171LintResult.violations).toEqual([]);
    });
  });

  describe('回帰用フィクスチャ (tests/fixtures/reports/) の全件検査', () => {
    it('tests/fixtures/reports/ に 4 件の合成フィクスチャが存在し、全件がチェッカーで合格すること', () => {
      const dirResult = lintDirectory(FIXTURES_DIR);
      expect(dirResult.totalFiles).toBe(4);
      expect(dirResult.failedFiles).toBe(0);
      expect(dirResult.ok).toBe(true);

      const names = dirResult.fileResults.map((r) => r.name);
      expect(names).toEqual([
        'app-insights-cookies',
        'csp-frame-ancestors',
        'relative-urls-only',
        'wordpress-legacy-ga',
      ]);

      // 保留項目 (R04, R08) を含めて検査しても全 4 件が合格すること
      const fullResult = lintDirectory(FIXTURES_DIR, { includePending: true });
      expect(fullResult.ok).toBe(true);
      expect(fullResult.failedFiles).toBe(0);
    });

    it('各フィクスチャの JSON から生成した Markdown が保存済み .md と整合していること', () => {
      for (const name of [
        'app-insights-cookies',
        'csp-frame-ancestors',
        'relative-urls-only',
        'wordpress-legacy-ga',
      ]) {
        const jsonPath = path.join(FIXTURES_DIR, `${name}.json`);
        const mdPath = path.join(FIXTURES_DIR, `${name}.md`);
        const report = JSON.parse(fs.readFileSync(jsonPath, 'utf8')) as InspectionReport;
        const savedMd = fs.readFileSync(mdPath, 'utf8');
        const generatedMd = generateMarkdownReport(report);

        const lintGen = lintReportPair(report, generatedMd, { includePending: true });
        expect(lintGen.ok).toBe(true);
        expect(savedMd.trim()).toBe(generatedMd.trim());
      }
    });

    it('CLI エントリポイント main() が終了コード 0 を返すこと', () => {
      const code = runLintCli([FIXTURES_DIR]);
      expect(code).toBe(0);
    });
  });

  describe('scripts/collect-reports.mjs の拡張機能（チェッカー統合・--snapshot）', () => {
    it('parseArgs が --snapshot オプションを解釈できること', () => {
      const opts = parseArgs(['--snapshot', '--timeout', '90000', 'https://example.test/']);
      expect(opts.snapshot).toBe(true);
      expect(opts.timeoutMs).toBe(90000);
      expect(opts.urls).toEqual(['https://example.test/']);
    });

    it('maskSetCookieValue と sanitizeSnapshotHeaders / sanitizeSnapshotCookies が Cookie の値と機密ヘッダーを除去すること', () => {
      expect(
        maskSetCookieValue('ASPSESSIONIDQCSRDTBS=SECRET_VALUE_123; path=/; HttpOnly')
      ).toBe('ASPSESSIONIDQCSRDTBS=; path=/; HttpOnly');

      const sanitizedHeaders = sanitizeSnapshotHeaders([
        { name: 'Server', value: 'Microsoft-IIS/8.5' },
        { name: 'Set-Cookie', value: 'ASP.NET_SessionId=TOP_SECRET; path=/; HttpOnly; SameSite=Lax' },
        { name: 'Authorization', value: 'Bearer secret_jwt' },
        { name: 'Cookie', value: 'sid=secret' },
      ]);

      expect(sanitizedHeaders['server']).toEqual(['Microsoft-IIS/8.5']);
      expect(sanitizedHeaders['set-cookie']).toEqual(['ASP.NET_SessionId=; path=/; HttpOnly; SameSite=Lax']);
      expect(sanitizedHeaders['authorization']).toBeUndefined();
      expect(sanitizedHeaders['cookie']).toBeUndefined();
      expect(JSON.stringify(sanitizedHeaders)).not.toContain('TOP_SECRET');

      const sanitizedCookies = sanitizeSnapshotCookies([
        {
          name: 'ASP.NET_SessionId',
          value: 'SHOULD_NOT_BE_SAVED',
          domain: 'example.test',
          path: '/',
          secure: true,
          httpOnly: true,
          sameSite: 'lax',
          session: true,
          hostOnly: true,
        },
      ]);
      expect(sanitizedCookies.length).toBe(1);
      expect(sanitizedCookies[0].name).toBe('ASP.NET_SessionId');
      expect(sanitizedCookies[0].value).toBeUndefined();
      expect(JSON.stringify(sanitizedCookies)).not.toContain('SHOULD_NOT_BE_SAVED');
    });

    it('buildSummary が _summary.md に整合性チェッカーの合否と違反詳細を出力すること', () => {
      const summaryMd = buildSummary(
        [
          {
            url: 'https://ok.example.test/',
            ok: true,
            finalUrl: 'https://ok.example.test/',
            attention: 0,
            techCount: 1,
            file: 'web-inspector-report-ok.example.test-2026-11-01.md',
            notes: [],
            lint: { ok: true, violations: [] },
          },
          {
            url: 'https://ng.example.test/',
            ok: true,
            finalUrl: 'https://ng.example.test/',
            attention: 1,
            techCount: 2,
            file: 'web-inspector-report-ng.example.test-2026-11-01.md',
            notes: [],
            lint: {
              ok: false,
              violations: [
                {
                  id: 'R01',
                  number: 1,
                  title: '要確認と内訳の一致',
                  message: 'CRITICAL〜LOWの合計が一致しません',
                },
              ],
            },
          },
        ],
        {
          startedAt: '2026/11/1 9:00:00',
          extensionVersion: '1.7.0',
        }
      );

      expect(summaryMd).toContain('整合性チェック: 合格 1 件 / 不合格 1 件');
      expect(summaryMd).toContain('| 合格 |');
      expect(summaryMd).toContain('| 不合格 (R01) |');
      expect(summaryMd).toContain('## 整合性チェックの違反詳細');
      expect(summaryMd).toContain('CRITICAL〜LOWの合計が一致しません');
    });
  });

  describe('v1.7.1 T11 (R05): http.badssl.com スナップショットおよび CORS が info のレポートでの R05 合格検証', () => {
    const fixtureDb = rawFixtureDb as unknown as AdvisoryDatabase;

    it('http.badssl.com のスナップショットから生成したレポートで SEC-HTTPS-01 が「HTTPS暗号化通信」となり、R05 を含む全整合性チェックが合格すること', async () => {
      setTestAdvisoryDatabase(fixtureDb);
      const snapPath = path.resolve(
        __dirname,
        'fixtures',
        'snapshots',
        'http.badssl.com.json'
      );
      const snap = JSON.parse(fs.readFileSync(snapPath, 'utf-8'));

      const report = await executeInspection({
        tab: { id: 201, url: snap.finalUrl || snap.url },
        fetchDomSignals: vi.fn().mockResolvedValue({
          url: snap.finalUrl || snap.url,
          title: 'http.badssl.com',
          metaTags: [],
          scriptUrls: [],
          linkUrls: [
            { rel: 'stylesheet', href: 'http://http.badssl.com/style.css' },
            { rel: 'shortcut icon', href: 'http://http.badssl.com/icons/favicon-red.ico' },
          ],
          domMarkers: [],
          htmlSnippets: [],
          mixedContent: [],
          cookiesFromDocument: [],
          cssAssets: [],
        }),
        fetchRuntimeVersions: vi.fn().mockResolvedValue({
          versions: {},
          frameworkMarkers: [],
        }),
        getCachedHeaders: vi.fn().mockResolvedValue({
          url: snap.finalUrl || snap.url,
          headers: snap.responseHeaders,
        }),
        getInspectedCookies: vi.fn().mockResolvedValue(snap.cookies || []),
        getAllFindingExceptions: vi.fn().mockResolvedValue([]),
        saveReport: vi.fn().mockResolvedValue(undefined),
      });

      const httpsFail = report.securityChecks.find((c) => c.checkId === 'SEC-HTTPS-01');
      expect(httpsFail).toBeDefined();
      expect(httpsFail?.status).toBe('fail');
      expect(httpsFail?.name).toBe('HTTPS暗号化通信');

      const md = generateMarkdownReport(report);
      const lintResult = lintReportPair(report, md, { includePending: true });
      const r05 = lintResult.results.find((r) => r.id === 'R05');
      expect(r05?.passed).toBe(true);
      expect(lintResult.ok).toBe(true);
      expect(lintResult.violations).toEqual([]);
    });

    it.each([
      {
        label: 'SEC-CORS-01 (Access-Control-Allow-Origin: * + Credentials: true)',
        headers: {
          'strict-transport-security': ['max-age=31536000; includeSubDomains'],
          'x-frame-options': ['SAMEORIGIN'],
          'x-content-type-options': ['nosniff'],
          'referrer-policy': ['unsafe-url'],
          'access-control-allow-origin': ['*'],
          'access-control-allow-credentials': ['true'],
        },
        expectedCorsId: 'SEC-CORS-01',
      },
      {
        label: 'SEC-CORS-02 (Access-Control-Allow-Origin: *)',
        headers: {
          'strict-transport-security': ['max-age=31536000; includeSubDomains'],
          'x-frame-options': ['SAMEORIGIN'],
          'x-content-type-options': ['nosniff'],
          'referrer-policy': ['no-referrer-when-downgrade'],
          'access-control-allow-origin': ['*'],
        },
        expectedCorsId: 'SEC-CORS-02',
      },
    ])('CORS が info のレポート ($label) で R05 を含む全整合性チェックが合格すること', async ({ headers, expectedCorsId }) => {
      setTestAdvisoryDatabase(fixtureDb);
      const url = 'https://cors-api.example.test/';
      const report = await executeInspection({
        tab: { id: 202, url },
        fetchDomSignals: vi.fn().mockResolvedValue({
          url,
          title: 'CORS API Test',
          metaTags: [],
          scriptUrls: ['https://cors-api.example.test/app.js'],
          linkUrls: [],
          domMarkers: [],
          htmlSnippets: [],
          mixedContent: [],
          cookiesFromDocument: [],
          cssAssets: [],
        }),
        fetchRuntimeVersions: vi.fn().mockResolvedValue({
          versions: {},
          frameworkMarkers: [],
        }),
        getCachedHeaders: vi.fn().mockResolvedValue({
          url,
          headers,
        }),
        getInspectedCookies: vi.fn().mockResolvedValue([]),
        getAllFindingExceptions: vi.fn().mockResolvedValue([]),
        saveReport: vi.fn().mockResolvedValue(undefined),
      });

      const corsCheck = report.securityChecks.find((c) => c.checkId === expectedCorsId);
      expect(corsCheck).toBeDefined();
      expect(corsCheck?.status).toBe('info');
      expect(corsCheck?.name).toBe('CORS (Cross-Origin Resource Sharing)');

      const md = generateMarkdownReport(report);
      const lintResult = lintReportPair(report, md, { includePending: true });
      const r05 = lintResult.results.find((r) => r.id === 'R05');
      expect(r05?.passed).toBe(true);
      expect(lintResult.ok).toBe(true);
      expect(lintResult.violations).toEqual([]);
    });
  });
});
