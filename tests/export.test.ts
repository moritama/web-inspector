/**
 * Web Technology & Security Inspector
 * エクスポート機能の単体テスト (tests/export.test.ts)
 */

import { describe, expect, it } from 'vitest';
import { exportReportToCsv } from '../src/export/csv';
import { exportReportToJson } from '../src/export/json';
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
});
