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
    expect(csvStr).toContain('"true (悪用確認済み（CISA KEV）)"');

    // 3. Markdown
    const mdStr = generateMarkdownReport(reportWithAdvisories);
    expect(mdStr).toContain('**CRITICAL (緊急)**');
    expect(mdStr).toContain('修正状況 (fixStatus)');
    expect(mdStr).toContain('CISA KEV');
    expect(mdStr).toContain('`fixed`');
    expect(mdStr).toContain('`unknown`');
    expect(mdStr).toContain('**悪用確認済み（CISA KEV）**');
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
});
