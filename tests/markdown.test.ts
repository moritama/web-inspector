/**
 * Web Technology & Security Inspector
 * 包括的Markdownレポート生成単体テスト (tests/markdown.test.ts)
 */

import { describe, expect, it } from 'vitest';
import {
  escapeMarkdown,
  generateMarkdownReport,
  sanitizeUrlForReport,
} from '../src/export/markdown';
import {
  FindingException,
  InspectionReport,
} from '../src/shared/types';

describe('Markdown Report Generation (Rev.2.1 IMP-12)', () => {
  const dummyReportA: InspectionReport = {
    id: 'rep_20261023_01',
    url: 'https://app.example.co.jp/dashboard?token=secret12345&user=admin',
    hostname: 'app.example.co.jp',
    inspectedAt: '2026-10-23T01:00:00.000Z',
    extensionVersion: '1.3.3',
    rulesVersion: '1.3.3',
    advisoryDatabaseVersion: '2026-10-22',
    coverage: {
      headersAvailable: true,
      cookiesAvailable: true,
      devtoolsAvailable: false,
      inspectedResourcesCount: 15,
      limitations: ['DevTools未接続のためHTTPボディ未取得'],
    },
    summary: {
      totalTechnologies: 3,
      requiresAttentionCount: 2,
      securityFindings: { high: 1, medium: 1, low: 0, info: 0, unknown: 0 },
      librarySecurity: { eolCount: 1, vulnerableLibraryCount: 1, mismatchCount: 1 },
      isHttps: true,
      mixedContentCount: 0,
    },
    technologies: [
      {
        technology: 'jQuery',
        category: 'javascript-library',
        detected: true,
        version: '1.12.4',
        supportStatus: 'EOL',
        eolDate: '2016-06-30',
        confidence: 90,
        confidenceLevel: 'high',
        advisories: [
          {
            id: 'CVE-2015-9251',
            package: 'jquery',
            title: 'jQuery XSS vulnerability',
            severity: 'medium',
            patchedVersions: '>=3.0.0',
            sourceUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2015-9251',
          },
        ],
        evidence: [
          {
            type: 'script-tag',
            name: 'script.src',
            value: 'https://cdn.example.co.jp/jquery-1.12.4.min.js',
            source: 'https://cdn.example.co.jp/jquery-1.12.4.min.js',
            weight: 90,
          },
        ],
      },
      {
        technology: 'Bootstrap',
        category: 'ui-framework',
        detected: true,
        version: '5.3.0',
        supportStatus: 'supported',
        confidence: 85,
        confidenceLevel: 'high',
        evidence: [],
      },
    ],
    securityChecks: [
      {
        checkId: 'SEC-HSTS-01',
        category: 'http-headers',
        name: 'HSTS (Strict-Transport-Security)',
        status: 'fail',
        severity: 'high',
        observed: 'ヘッダー未設定',
        description: 'HSTSヘッダーが検出されませんでした。',
        recommendation: 'Strict-Transport-Securityヘッダーを付与してください。',
        referenceUrls: [],
        scope: 'https://app.example.co.jp/',
      },
    ],
    cookies: [
      {
        name: 'SESSION_ID',
        value: 'SUPER_SECRET_SESSION_TOKEN_1234567890',
        domain: '.example.co.jp',
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'Lax',
        assessment: {
          category: 'session',
          securityScore: 100,
          findings: [],
        },
      },
    ],
    externalConnections: {
      totalConnections: 2,
      firstPartyCount: 1,
      thirdPartyCount: 1,
      categoryBreakdown: {
        cdn: 0,
        analytics: 1,
        advertising: 0,
        fonts: 0,
        social: 0,
        api: 0,
        other: 0,
      },
      connections: [
        {
          hostname: 'app.example.co.jp',
          registrableDomain: 'example.co.jp',
          publicSuffix: 'co.jp',
          partyType: 'first-party',
          category: 'api',
          resourceCount: 10,
          sampleUrls: ['https://app.example.co.jp/api/v1/user'],
        },
        {
          hostname: 'www.googletagmanager.com',
          registrableDomain: 'googletagmanager.com',
          publicSuffix: 'com',
          partyType: 'third-party',
          category: 'analytics',
          resourceCount: 2,
          sampleUrls: ['https://www.googletagmanager.com/gtm.js?id=GTM-TEST'],
        },
      ],
    },
    mixedContent: [],
  };

  it('仕様書 Rev.2.1 第11項に定義された15セクションの見出しがすべて含まれていること', () => {
    const md = generateMarkdownReport(dummyReportA);

    expect(md).toContain('# Web Technology & Security Inspection Report');
    expect(md).toContain('## 1. 調査概要');
    expect(md).toContain('## 2. 調査範囲・完全性 (Coverage)');
    expect(md).toContain('## 3. 調査結果サマリー');
    expect(md).toContain('## 4. 検出技術スタック');
    expect(md).toContain('## 5. セキュリティ診断結果');
    expect(md).toContain('## 6. EOL・既知脆弱性情報 (ライブラリセキュリティ)');
    expect(md).toContain('## 7. Cookie属性診断');
    expect(md).toContain('## 8. CSP（Content Security Policy）診断');
    expect(md).toContain('## 9. 外部通信先・サードパーティ分析');
    expect(md).toContain('## 10. 前回調査との差分 (Diff)');
    expect(md).toContain('## 11. 差分発生原因の推定分析');
    expect(md).toContain('## 12. 診断項目の許容・除外設定 (Finding Exceptions)');
    expect(md).toContain('## 13. 推奨対応ロードマップ');
    expect(md).toContain('## 14. 検出根拠 (エビデンス詳細)');
    expect(md).toContain('## 15. 調査上の制限事項・免責事項');
  });

  it('Cookie値（Value）や機密トークンがレポートに含まれないこと (受動的・プライバシー保護原則)', () => {
    const md = generateMarkdownReport(dummyReportA);

    // Cookieの名前は出力されるが、値は出力されないこと (特殊文字 _ はエスケープ)
    expect(md).toContain('SESSION\\_ID');
    expect(md).not.toContain('SUPER_SECRET_SESSION_TOKEN_1234567890');

    // URLのクエリパラメータ token=secret12345 がマスクされていること
    expect(md).not.toContain('secret12345');
    expect(md).toContain('***MASKED***');
  });

  it('前回レポートとの差分（IMP-09）および許容設定（IMP-10）が正しく反映されること', () => {
    const dummyReportB: InspectionReport = {
      ...dummyReportA,
      id: 'rep_20261023_02',
      inspectedAt: '2026-10-23T02:00:00.000Z',
      securityChecks: [
        {
          checkId: 'SEC-HSTS-01',
          category: 'http-headers',
          name: 'HSTS (Strict-Transport-Security)',
          status: 'pass',
          severity: 'high',
          observed: 'max-age=31536000; includeSubDomains',
          description: 'HSTSが有効です。',
          recommendation: '',
          referenceUrls: [],
          scope: 'https://app.example.co.jp/',
        },
      ],
    };

    const dummyExceptions: FindingException[] = [
      {
        id: 'ex_001',
        findingId: 'SEC-HSTS-01',
        targetUrl: 'https://app.example.co.jp/',
        status: 'accepted',
        reason: '移行期間中の暫定措置としてリスク許容',
        createdAt: '2026-10-23T00:00:00.000Z',
      },
    ];

    const md = generateMarkdownReport(dummyReportB, dummyReportA, dummyExceptions);

    // セクション10に差分が反映されていること
    expect(md).toContain('SEC-HSTS-01');
    expect(md).toContain('Resolved'); // 警告解消

    // セクション12に許容設定が反映されていること
    expect(md).toContain('SEC-HSTS-01');
    expect(md).toContain('リスク許容');
    expect(md).toContain('移行期間中の暫定措置としてリスク許容');
  });

  describe('sanitizeUrlForReport', () => {
    it('URL内の機密クエリパラメータをマスクすること', () => {
      const masked = sanitizeUrlForReport('https://example.com/api?access_token=xyz987&normal=1');
      expect(masked).toContain('access_token=***MASKED***');
      expect(masked).toContain('normal=1');
      expect(masked).not.toContain('xyz987');
    });

    it('URL内のユーザー名・パスワードをマスク・除去すること', () => {
      const masked = sanitizeUrlForReport('https://admin:mypassword@example.com/data');
      expect(masked).not.toContain('admin');
      expect(masked).not.toContain('mypassword');
    });
  });

  describe('escapeMarkdown', () => {
    it('Markdown特殊記号をエスケープすること', () => {
      expect(escapeMarkdown('text with *asterisk* and [link]')).toBe('text with \\*asterisk\\* and \\[link\\]');
      expect(escapeMarkdown('<div>content</div>')).toBe('&lt;div&gt;content&lt;/div&gt;');
      expect(escapeMarkdown('table|cell\nnewline')).toBe('table\\|cell newline');
      // バックスラッシュとパイプが混在しても二重エスケープが壊れないこと
      expect(escapeMarkdown('path\\to|file')).toBe('path\\\\to\\|file');
    });
  });
});
