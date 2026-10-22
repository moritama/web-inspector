/**
 * Web Technology & Security Inspector
 * 拡張差分比較・原因分析エンジン 単体テスト (tests/diff.test.ts) - IMP-09
 */

import { describe, expect, it } from 'vitest';
import { compareReportsEnhanced } from '../src/storage/diff';
import { InspectionReport } from '../src/shared/types';

function createDummyReport(overrides: Partial<InspectionReport> = {}): InspectionReport {
  return {
    id: `rep_${Date.now()}`,
    url: 'https://example.com/',
    hostname: 'example.com',
    inspectedAt: new Date().toISOString(),
    coverage: {
      completeness: 'complete',
      score: 100,
      sources: { dom: true, responseHeaders: true, cookies: true, runtime: true },
      unobservedSignals: [],
      notes: [],
    },
    summary: {
      technologiesCount: 1,
      requiresAttentionCount: 0,
      isHttps: true,
      securityFindings: { high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
    },
    technologies: [],
    securityChecks: [],
    cookies: [],
    mixedContent: [],
    ...overrides,
  };
}

describe('拡張差分比較 & 原因分析 (IMP-09)', () => {
  it('バージョン変更を検知し、原因を site-change と判定すること', () => {
    const reportA = createDummyReport({
      technologies: [
        {
          technology: 'Bootstrap',
          category: 'js-css-library',
          detected: true,
          version: '4.3.1',
          confidence: 100,
          confidenceLevel: 'high',
          evidence: [],
        },
      ],
    });

    const reportB = createDummyReport({
      technologies: [
        {
          technology: 'Bootstrap',
          category: 'js-css-library',
          detected: true,
          version: '5.3.3',
          confidence: 100,
          confidenceLevel: 'high',
          evidence: [],
        },
      ],
    });

    const diff = compareReportsEnhanced(reportA, reportB);

    expect(diff.diffItems.length).toBe(1);
    expect(diff.diffItems[0].diffType).toBe('Changed');
    expect(diff.diffItems[0].diffCause).toBe('site-change');
    expect(diff.diffItems[0].before).toBe('4.3.1');
    expect(diff.diffItems[0].after).toBe('5.3.3');
    expect(diff.summary.changedCount).toBe(1);
    expect(diff.summary.causes['site-change']).toBe(1);
  });

  it('同一技術・同一バージョンで脆弱性数が増加した場合、原因を advisory-update と判定すること', () => {
    const reportA = createDummyReport({
      technologies: [
        {
          technology: 'jQuery',
          category: 'js-css-library',
          detected: true,
          version: '3.4.0',
          confidence: 100,
          confidenceLevel: 'high',
          evidence: [],
          advisories: [],
        },
      ],
    });

    const reportB = createDummyReport({
      technologies: [
        {
          technology: 'jQuery',
          category: 'js-css-library',
          detected: true,
          version: '3.4.0',
          confidence: 100,
          confidenceLevel: 'high',
          evidence: [],
          advisories: [
            {
              id: 'CVE-2020-11022',
              title: 'Regex XSS',
              severity: 'MEDIUM',
              affectedRange: '< 3.5.0',
              fixedVersion: '3.5.0',
              summary: 'Regex in jQuery.htmlPrefilter can result in XSS',
              referenceUrls: [],
            },
          ],
        },
      ],
    });

    const diff = compareReportsEnhanced(reportA, reportB);

    expect(diff.diffItems.length).toBe(1);
    expect(diff.diffItems[0].diffType).toBe('Regressed');
    expect(diff.diffItems[0].diffCause).toBe('advisory-update');
    expect(diff.summary.causes['advisory-update']).toBe(1);
  });

  it('調査完全性の違いにより技術が消失した場合、原因を inspection-difference と判定すること', () => {
    const reportA = createDummyReport({
      coverage: {
        completeness: 'complete',
        score: 100,
        sources: { dom: true, responseHeaders: true, cookies: true, runtime: true },
        unobservedSignals: [],
        notes: [],
      },
      technologies: [
        {
          technology: 'React',
          category: 'js-framework',
          detected: true,
          version: '18.2.0',
          confidence: 90,
          confidenceLevel: 'high',
          evidence: [],
        },
      ],
    });

    const reportB = createDummyReport({
      coverage: {
        completeness: 'partial',
        score: 40,
        sources: { dom: false, responseHeaders: true, cookies: false, runtime: false },
        unobservedSignals: ['dom'],
        notes: [],
      },
      technologies: [],
    });

    const diff = compareReportsEnhanced(reportA, reportB);

    expect(diff.diffItems.length).toBe(1);
    expect(diff.diffItems[0].diffType).toBe('Removed');
    expect(diff.diffItems[0].diffCause).toBe('inspection-difference');
    expect(diff.summary.causes['inspection-difference']).toBe(1);
  });

  it('セキュリティ設定の修正により警告が解消された場合、Resolved と判定すること', () => {
    const reportA = createDummyReport({
      securityChecks: [
        {
          checkId: 'SEC-HSTS-MISSING',
          category: 'http-headers',
          name: 'HSTSヘッダー未設定',
          status: 'warning',
          severity: 'medium',
          observed: '未設定',
          description: 'HSTSがありません',
          recommendation: 'Strict-Transport-Securityを設定してください',
          referenceUrls: [],
          scope: 'https://example.com/',
        },
      ],
    });

    const reportB = createDummyReport({
      securityChecks: [
        {
          checkId: 'SEC-HSTS-MISSING',
          category: 'http-headers',
          name: 'HSTSヘッダー未設定',
          status: 'pass',
          severity: 'medium',
          observed: 'max-age=31536000; includeSubDomains',
          description: 'HSTSが設定されています',
          recommendation: '適正です',
          referenceUrls: [],
          scope: 'https://example.com/',
        },
      ],
    });

    const diff = compareReportsEnhanced(reportA, reportB);

    expect(diff.diffItems.length).toBe(1);
    expect(diff.diffItems[0].diffType).toBe('Resolved');
    expect(diff.diffItems[0].diffCause).toBe('site-change');
    expect(diff.summary.resolvedCount).toBe(1);
  });
});
