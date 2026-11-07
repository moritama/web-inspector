/**
 * Web Technology & Security Inspector
 * エクスポート機能の単体テスト (tests/export.test.ts)
 */

import { describe, expect, it } from 'vitest';
import { exportReportToCsv } from '../src/export/csv';
import { exportReportToJson } from '../src/export/json';
import { generateMarkdownReport } from '../src/export/markdown';
import { InspectionReport } from '../src/shared/types';

describe('Export Functions', () => {
  const dummyReport: InspectionReport = {
    id: 'rep_123',
    url: 'https://example.com/',
    hostname: 'example.com',
    inspectedAt: '2026-10-22T05:00:00.000Z',
    extensionVersion: '1.0.0',
    rulesVersion: '1.0.0',
    summary: {
      totalTechnologies: 1,
      requiresAttentionCount: 1,
      securityFindings: { high: 0, medium: 1, low: 0, info: 0, unknown: 0 },
      librarySecurity: { eolCount: 0, vulnerableLibraryCount: 0, mismatchCount: 0 },
      isHttps: true,
      mixedContentCount: 0,
    },
    technologies: [
      {
        technology: 'PHP',
        category: 'programming-language',
        detected: true,
        version: '8.2.0',
        confidence: 95,
        confidenceLevel: 'high',
        evidence: [
          {
            type: 'response-header',
            name: 'X-Powered-By',
            value: 'PHP/8.2.0',
            source: 'https://example.com/',
            weight: 95,
          },
        ],
      },
    ],
    securityChecks: [
      {
        checkId: 'SEC-HSTS-01',
        category: 'http-headers',
        name: 'HSTS (Strict-Transport-Security)',
        status: 'warning',
        severity: 'medium',
        observed: 'ヘッダー未設定',
        description: 'HSTSヘッダーが検出されませんでした。',
        recommendation: 'max-ageを設定してください。',
        referenceUrls: [],
        scope: 'https://example.com/',
      },
    ],
    cookies: [],
    mixedContent: [],
  };

  it('JSONエクスポートが完全な構造を出力できること', () => {
    const jsonStr = exportReportToJson(dummyReport);
    const parsed = JSON.parse(jsonStr);
    expect(parsed.id).toBe('rep_123');
    expect(parsed.technologies[0].technology).toBe('PHP');
    expect(parsed.technologies[0].evidence[0].name).toBe('X-Powered-By');
  });

  it('CSVエクスポートがUTF-8 BOMを先頭に含み、Excel互換であること', () => {
    const csvStr = exportReportToCsv(dummyReport);
    // BOM (\uFEFF)
    expect(csvStr.charCodeAt(0)).toBe(0xfeff);
    expect(csvStr).toContain('PHP');
    expect(csvStr).toContain('SEC-HSTS-01');
    expect(csvStr).toContain('ヘッダー未設定');
  });

  it('SPEC-02: distroHint が JSON, CSV, Markdown エクスポートに正確に出力されること', () => {
    const reportWithDistro: InspectionReport = {
      ...dummyReport,
      technologies: [
        {
          ...dummyReport.technologies[0],
          distroHint: 'Ubuntu',
        },
      ],
    };

    const jsonStr = exportReportToJson(reportWithDistro);
    const parsed = JSON.parse(jsonStr);
    expect(parsed.technologies[0].distroHint).toBe('Ubuntu');

    const csvStr = exportReportToCsv(reportWithDistro);
    expect(csvStr).toContain('"Ubuntu"');

    const mdStr = generateMarkdownReport(reportWithDistro);
    expect(mdStr).toContain('`Ubuntu`');
  });

  it('T03 (SPEC-13): JSON・CSV・Markdown の 3 形式すべてに fixStatus と kev が出力され、GHSA のみの ID に GitHub Advisories リンクが使われること', () => {
    const reportWithAdvisories: InspectionReport = {
      ...dummyReport,
      summary: {
        ...dummyReport.summary,
        securityFindings: { critical: 1, high: 0, medium: 1, low: 0, info: 0, unknown: 0 },
        librarySecurity: { eolCount: 0, vulnerableLibraryCount: 1, mismatchCount: 0 },
      },
      technologies: [
        {
          ...dummyReport.technologies[0],
          technology: 'jQuery',
          version: '3.4.1',
          advisoryMatchStatus: 'Potentially Affected',
          offlineMatchStatus: 'Matched',
          maxCvss: 6.1,
          advisories: [
            {
              id: 'CVE-2020-11023',
              title: 'XSS in jQuery.htmlPrefilter',
              severity: 'medium',
              cvssScore: 6.1,
              affectedRange: '>= 1.0.3, < 3.5.0',
              fixedVersion: '3.5.0',
              fixStatus: 'fixed',
              kev: true,
              kevDateAdded: '2025-01-23',
              summary: 'XSS in jQuery.htmlPrefilter',
              referenceUrls: ['https://nvd.nist.gov/vuln/detail/CVE-2020-11023'],
            },
            {
              id: 'GHSA-5cp4-xmrw-59wf',
              title: 'GHSA only vulnerability',
              severity: 'low',
              cvssScore: 3.1,
              affectedRange: '>= 3.0.0, < 3.5.0',
              fixedVersion: null,
              fixStatus: 'unknown',
              kev: false,
              kevDateAdded: null,
              summary: 'GHSA only vulnerability',
              referenceUrls: ['https://github.com/advisories/GHSA-5cp4-xmrw-59wf'],
            },
          ],
        },
      ],
    };

    // 1. JSON
    const jsonStr = exportReportToJson(reportWithAdvisories);
    const parsed = JSON.parse(jsonStr);
    expect(parsed.technologies[0].advisories[0].fixStatus).toBe('fixed');
    expect(parsed.technologies[0].advisories[0].kev).toBe(true);
    expect(parsed.technologies[0].advisories[0].kevDateAdded).toBe('2025-01-23');
    expect(parsed.technologies[0].advisories[1].fixStatus).toBe('unknown');

    // 2. CSV
    const csvStr = exportReportToCsv(reportWithAdvisories);
    expect(csvStr).toContain('"修正状況 (fixStatus)"');
    expect(csvStr).toContain('"CISA KEV"');
    expect(csvStr).toContain('"fixed; unknown"');
    expect(csvStr).toContain('"true (CISA KEV: CVE-2020-11023)"');

    // 3. Markdown
    const mdStr = generateMarkdownReport(reportWithAdvisories);
    expect(mdStr).toContain('**CRITICAL (緊急)**');
    expect(mdStr).toContain('修正状況 (fixStatus)');
    expect(mdStr).toContain('CISA KEV');
    expect(mdStr).toContain('`fixed`');
    expect(mdStr).toContain('`unknown`');
    expect(mdStr).toContain('**CISA KEV: CVE-2020-11023**');
    expect(mdStr).toContain('https://github.com/advisories/GHSA-5cp4-xmrw-59wf');
    expect(mdStr).not.toContain('nvd.nist.gov/vuln/detail/GHSA-');
  });

  // --- T04 (SPEC-03): 「収録 DB 上は該当なし」と収録範囲のエクスポート検証 ---
  it('T04 (SPEC-03): エクスポート 3 形式とも「収録 DB 上は該当なし」の表現になり、Not Affected だけの表記が残っておらず、未収録技術は「収録していません」と出る', () => {
    const reportSpec03: InspectionReport = {
      ...dummyReport,
      technologies: [
        {
          technology: 'Apache',
          category: 'web-server',
          detected: true,
          confidence: 100,
          confidenceLevel: 'high',
          version: '2.4.62',
          evidence: [],
          advisoryMatchStatus: 'Not Affected',
          productAdvisoryCount: 3,
          productSources: ['curated', 'NVD'],
          advisoryDataVersion: '20261031',
          advisories: [],
        },
        {
          technology: 'Tailwind CSS',
          category: 'js-framework',
          detected: true,
          confidence: 95,
          confidenceLevel: 'high',
          version: '3.4.1',
          evidence: [],
          advisoryMatchStatus: 'Not Affected',
          productAdvisoryCount: 0,
          productSources: [],
          advisoryDataVersion: '20261031',
          advisories: [],
        },
        {
          technology: 'Apache',
          category: 'web-server',
          detected: true,
          confidence: 100,
          confidenceLevel: 'high',
          version: '2.4.41 (Ubuntu)',
          evidence: [],
          advisoryMatchStatus: 'Needs Review',
          productAdvisoryCount: 3,
          productSources: ['curated', 'NVD'],
          advisoryDataVersion: '20261031',
          upstreamAdvisoriesCount: 3,
          advisories: [],
        },
      ],
    };

    // 1. JSON
    const jsonStr = exportReportToJson(reportSpec03);
    const parsed = JSON.parse(jsonStr);
    expect(parsed.technologies[0].advisoryStatusLabel).toContain('収録 DB 上は該当なし');
    expect(parsed.technologies[0].advisoryStatusLabel).toContain('収録 3 件');
    expect(parsed.technologies[0].advisoryStatusLabel).toContain('curated / NVD');
    expect(parsed.technologies[0].advisoryStatusLabel).toContain('dataVersion: 20261031');
    expect(parsed.technologies[1].advisoryStatusLabel).toBe('この技術の脆弱性は収録していません');
    expect(parsed.technologies[2].advisoryStatusLabel).toContain('Needs Review');
    expect(parsed.technologies[2].advisoryStatusLabel).toContain('上流版では 3 件');

    // 2. CSV
    const csvStr = exportReportToCsv(reportSpec03);
    expect(csvStr).toContain('収録 DB 上は該当なし（収録 3 件・取得元: curated / NVD・dataVersion: 20261031）');
    expect(csvStr).toContain('この技術の脆弱性は収録していません');
    expect(csvStr).toContain('Needs Review（参考: 上流版では 3 件該当）');
    expect(csvStr).not.toContain('"Not Affected"');

    // 3. Markdown
    const mdStr = generateMarkdownReport(reportSpec03);
    expect(mdStr).toContain('収録 DB 上は該当なし（収録 3 件・取得元: curated / NVD・dataVersion: 20261031）');
    expect(mdStr).toContain('この技術の脆弱性は収録していません');
    expect(mdStr).toContain('Needs Review（参考: 上流版では 3 件該当）');
    expect(mdStr).not.toContain('| Not Affected |');
  });

  it('T14 (D1): eolInfo.label と eolInfo.note がある技術（React 18.3.1）でエクスポート 3 形式に Limited Support (Maintenance) と補足文が出力される', () => {
    const reactNote =
      'React 18 の通常の機能サポートは終了しています。React チームは過去のメジャー版のサポート期間を公表しておらず、重大な脆弱性の修正が提供されるかは個別の判断になります。原則として React 19 への移行を推奨します。';
    const reportD1: InspectionReport = {
      ...dummyReport,
      technologies: [
        {
          technology: 'React',
          category: 'js-framework',
          detected: true,
          confidence: 100,
          confidenceLevel: 'high',
          version: '18.3.1',
          evidence: [],
          supportStatus: 'Maintenance',
          eolDate: null,
          eolInfo: {
            status: 'Maintenance',
            eolDate: null,
            source: 'offline-db (endoflife.date snapshot)',
            sourceUrl: 'https://endoflife.date/react',
            label: 'Limited Support (Maintenance)',
            note: reactNote,
            recommendation: reactNote,
          },
          advisoryMatchStatus: 'Not Affected',
          productAdvisoryCount: 2,
          productSources: ['curated', 'OSV', 'NVD'],
          advisoryDataVersion: '20261031',
          advisories: [],
        },
      ],
    };

    // 1. JSON
    const jsonStr = exportReportToJson(reportD1);
    const parsed = JSON.parse(jsonStr);
    expect(parsed.technologies[0].eolInfo.status).toBe('Maintenance');
    expect(parsed.technologies[0].eolInfo.label).toBe('Limited Support (Maintenance)');
    expect(parsed.technologies[0].eolInfo.recommendation).toBe(reactNote);

    // 2. CSV
    const csvStr = exportReportToCsv(reportD1);
    expect(csvStr).toContain('"Limited Support (Maintenance)"');
    expect(csvStr).toContain(reactNote);

    // 3. Markdown
    const mdStr = generateMarkdownReport(reportD1);
    expect(mdStr).toContain('Limited Support (Maintenance)');
    expect(mdStr).toContain(reactNote);
  });

  it('T08 (SPEC-10): 複数バージョンインスタンスを持つ技術について、JSON は instances をそのまま出力し、CSV はインスタンスごとに 1 行、Markdown は表の行をインスタンスごとに展開すること', () => {
    const multiInstanceReport: InspectionReport = {
      ...dummyReport,
      technologies: [
        {
          technology: 'jQuery',
          category: 'js-css-library',
          detected: true,
          version: '1.12.4',
          versionSource: 'pattern',
          confidence: 95,
          confidenceLevel: 'high',
          supportStatus: 'EOL',
          eolDate: '2016-06',
          advisoryMatchStatus: 'Potentially Affected',
          offlineMatchStatus: 'Matched',
          advisories: [
            {
              id: 'CVE-2020-11022',
              title: 'XSS in jQuery.htmlPrefilter',
              severity: 'medium',
              cvssScore: 6.1,
              affectedRange: '< 3.5.0',
              fixedVersion: '3.5.0',
              fixStatus: 'fixed',
              summary: 'XSS in jQuery.htmlPrefilter',
              referenceUrls: ['https://nvd.nist.gov/vuln/detail/CVE-2020-11022'],
            },
          ],
          evidence: [
            {
              type: 'script-url',
              name: 'Script URL (jQuery)',
              value: '/js/jquery-1.12.4.min.js',
              source: 'https://example.com/',
              weight: 90,
            },
            {
              type: 'script-url',
              name: 'Script URL (jQuery)',
              value: '/js/jquery-3.7.1.min.js',
              source: 'https://example.com/',
              weight: 90,
            },
          ],
          instances: [
            {
              version: '1.12.4',
              versionSource: 'pattern',
              evidence: [
                {
                  type: 'script-url',
                  name: 'Script URL (jQuery)',
                  value: '/js/jquery-1.12.4.min.js',
                  source: 'https://example.com/',
                  weight: 90,
                },
              ],
              advisories: [
                {
                  id: 'CVE-2020-11022',
                  title: 'XSS in jQuery.htmlPrefilter',
                  severity: 'medium',
                  cvssScore: 6.1,
                  affectedRange: '< 3.5.0',
                  fixedVersion: '3.5.0',
                  fixStatus: 'fixed',
                  summary: 'XSS in jQuery.htmlPrefilter',
                  referenceUrls: ['https://nvd.nist.gov/vuln/detail/CVE-2020-11022'],
                },
              ],
              eol: {
                status: 'EOL',
                eolDate: '2016-06',
                source: 'Internal Policy',
                recommendation: '現行バージョンへ更新推奨',
              },
              supportStatus: 'EOL',
              eolDate: '2016-06',
              advisoryMatchStatus: 'Potentially Affected',
              offlineMatchStatus: 'Matched',
              maxCvss: 6.1,
            },
            {
              version: '3.7.1',
              versionSource: 'runtime',
              evidence: [
                {
                  type: 'script-url',
                  name: 'Script URL (jQuery)',
                  value: '/js/jquery-3.7.1.min.js',
                  source: 'https://example.com/',
                  weight: 90,
                },
              ],
              advisories: [],
              eol: {
                status: 'Supported',
                eolDate: null,
                source: 'Internal Policy',
                recommendation: 'サポート継続中',
              },
              supportStatus: 'Supported',
              eolDate: null,
              advisoryMatchStatus: 'Not Affected',
              offlineMatchStatus: 'No Match',
            },
          ],
        },
      ],
    };

    // 1. JSON: instances 配列がそのまま出力されること
    const jsonStr = exportReportToJson(multiInstanceReport);
    const parsed = JSON.parse(jsonStr);
    expect(parsed.technologies[0].instances).toBeDefined();
    expect(parsed.technologies[0].instances.length).toBe(2);
    expect(parsed.technologies[0].instances[0].version).toBe('1.12.4');
    expect(parsed.technologies[0].instances[1].version).toBe('3.7.1');

    // 2. CSV: インスタンスごとに 1 行出力されること
    const csvStr = exportReportToCsv(multiInstanceReport);
    const csvLines = csvStr.split('\r\n');
    const jqLines = csvLines.filter((l) => l.startsWith('"jQuery",'));
    expect(jqLines.length).toBe(2);
    expect(jqLines[0]).toContain('"1.12.4"');
    expect(jqLines[0]).toContain('CVE-2020-11022');
    expect(jqLines[1]).toContain('"3.7.1"');

    // 3. Markdown: 検出技術スタック表・ライブラリセキュリティ表でインスタンスごとに行が展開されること
    const mdStr = generateMarkdownReport(multiInstanceReport);
    expect(mdStr).toContain('| **jQuery** | js-css-library | `v1.12.4` |');
    expect(mdStr).toContain('| **jQuery** | js-css-library | `v3.7.1` |');
    expect(mdStr).toContain('| **jQuery** | `1.12.4` |');
    expect(mdStr).toContain('| **jQuery** | `3.7.1` |');
  });

  it('T10 (IMPL-07): https://example.com/a?token=x#y を調査した JSON・CSV に token=x が含まれないこと', () => {
    const reportWithQuery: InspectionReport = {
      ...dummyReport,
      url: 'https://example.com/a?token=x#y',
      technologies: dummyReport.technologies.map((t) => ({
        ...t,
        evidence: [
          {
            type: 'script-url',
            name: 'Script URL',
            value: 'https://example.com/static/app.js?token=x#y',
            source: 'https://example.com/a?token=x#y',
            weight: 80,
          },
        ],
      })),
      securityChecks: dummyReport.securityChecks.map((c) => ({
        ...c,
        scope: 'https://example.com/a?token=x#y',
      })),
      mixedContent: [
        {
          url: 'http://example.com/img.png?token=x#y',
          resourceType: 'image',
        },
      ],
    };

    const jsonStr = exportReportToJson(reportWithQuery);
    expect(jsonStr).not.toContain('token=x');
    expect(jsonStr).not.toContain('#y');
    const parsed = JSON.parse(jsonStr);
    expect(parsed.url).toBe('https://example.com/a');

    const csvStr = exportReportToCsv(reportWithQuery);
    expect(csvStr).not.toContain('token=x');
    expect(csvStr).not.toContain('#y');
    expect(csvStr).toContain('"https://example.com/a"');
  });
});
