/**
 * Web Technology & Security Inspector
 * 包括的Markdownレポート生成単体テスト (tests/markdown.test.ts)
 */

import { describe, expect, it } from 'vitest';
import { renderExternalConnectionsHtml } from '../src/dashboard/render';
import {
  escapeMarkdown,
  escapeMarkdownTableCell,
  formatMarkdownCodeSpan,
  generateMarkdownReport,
  sanitizeUrlForReport,
} from '../src/export/markdown';
import { analyzeCSPPolicies, parseCSPPolicy } from '../src/security/csp-parser';
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
      dom: 'complete',
      headers: 'complete',
      cookies: 'complete',
      iframes: 'not-applicable',
      network: 'complete',
      overallStatus: 'complete',
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
        category: 'js-css-library',
        detected: true,
        version: '1.12.4',
        supportStatus: 'EOL',
        eolDate: '2016-06-30',
        confidence: 90,
        confidenceLevel: 'high',
        advisories: [
          {
            id: 'CVE-2015-9251',
            title: 'jQuery XSS vulnerability',
            severity: 'MEDIUM',
            affectedRange: '< 3.0.0',
            fixedVersion: '3.0.0',
            summary: 'jQuery before 3.0.0 is vulnerable to Cross-site Scripting (XSS).',
            referenceUrls: ['https://nvd.nist.gov/vuln/detail/CVE-2015-9251'],
          },
        ],
        evidence: [
          {
            type: 'script-url',
            name: 'script.src',
            value: 'https://cdn.example.co.jp/jquery-1.12.4.min.js',
            source: 'https://cdn.example.co.jp/jquery-1.12.4.min.js',
            weight: 90,
          },
        ],
      },
      {
        technology: 'Bootstrap',
        category: 'js-css-library',
        detected: true,
        version: '5.3.0',
        supportStatus: 'Supported',
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
        sameSite: 'lax',
        issues: [],
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

    // Cookieの名前はコードスパン内にバックスラッシュなしで出力され、値は出力されないこと (T02 指摘7)
    expect(md).toContain('`SESSION_ID`');
    expect(md).not.toContain('SESSION\\_ID');
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

  describe('v1.7.1 T02: Markdown 出力の整理（ロードマップ、エスケープ、表現）', () => {
    it('E3: HTTPS・CVE なし・認証 Cookie が適切なレポートで、ロードマップに固定文（HTTPS、CVE、セッション Cookie、HSTS、SRI、unsafe-inline）が出ず、要確認 0 件で「対応が必要な項目はありません」になること', () => {
      const cleanReport: InspectionReport = {
        ...dummyReportA,
        url: 'https://secure.example.test/',
        hostname: 'secure.example.test',
        summary: {
          totalTechnologies: 1,
          requiresAttentionCount: 0,
          securityFindings: { critical: 0, high: 0, medium: 0, low: 0, info: 3, unknown: 0 },
          librarySecurity: { eolCount: 0, vulnerableLibraryCount: 0, mismatchCount: 0 },
          isHttps: true,
          mixedContentCount: 0,
        },
        technologies: [
          {
            technology: 'Bootstrap',
            category: 'js-css-library',
            detected: true,
            version: '5.3.3',
            supportStatus: 'Supported',
            confidence: 90,
            confidenceLevel: 'high',
            evidence: [],
            advisories: [],
          },
        ],
        securityChecks: [
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
            scope: 'https://secure.example.test/',
          },
          {
            checkId: 'SEC-COOKIE-00',
            category: 'cookies',
            name: 'Cookie属性セキュリティ',
            status: 'pass',
            severity: 'info',
            observed: '1 件のCookieを検査（全属性が適切）',
            description: '適切です。',
            recommendation: '現在の設定を維持してください。',
            referenceUrls: [],
            scope: 'https://secure.example.test/',
          },
          {
            checkId: 'SEC-REF-01',
            category: 'http-headers',
            name: 'Referrer-Policy',
            status: 'info',
            severity: 'info',
            observed: 'ヘッダー未設定（ブラウザ既定: strict-origin-when-cross-origin 相当）',
            description: '未設定ですが既定値で保護されます。',
            recommendation: '明示的な設定を検討してください。',
            referenceUrls: [],
            scope: 'https://secure.example.test/',
          },
        ],
      };

      const md = generateMarkdownReport(cleanReport);
      const roadmapSection = md.split('## 13. 推奨対応ロードマップ')[1]?.split('## 14.')[0] || '';

      expect(roadmapSection).toContain('対応が必要な項目はありません');
      expect(roadmapSection).not.toContain('HTTPS');
      expect(roadmapSection).not.toContain('CVE');
      expect(roadmapSection).not.toContain('セッションCookie');
      expect(roadmapSection).not.toContain('HSTS');
      expect(roadmapSection).not.toContain('SRI');
      expect(roadmapSection).not.toContain('unsafe-inline');
    });

    it('E3: 要確認の指摘がある場合、ロードマップが CRITICAL/HIGH（至急対応）・MEDIUM（計画的対応）・LOW（継続的改善）に振り分けられ、各行が指摘名と recommendation の 1 文目で構成されること（該当がない段は出さない）', () => {
      const reportWithIssues: InspectionReport = {
        ...dummyReportA,
        url: 'https://issues.example.test/',
        hostname: 'issues.example.test',
        summary: {
          totalTechnologies: 0,
          requiresAttentionCount: 2,
          securityFindings: { critical: 1, high: 0, medium: 0, low: 1, info: 1, unknown: 0 },
          librarySecurity: { eolCount: 0, vulnerableLibraryCount: 1, mismatchCount: 0 },
          isHttps: true,
          mixedContentCount: 0,
        },
        technologies: [],
        securityChecks: [
          {
            checkId: 'SEC-CVE-JQUERY',
            category: 'library-security',
            name: 'jQuery 既知脆弱性 (CVE-2020-11023)',
            status: 'fail',
            severity: 'critical',
            observed: 'バージョン 3.4.1 に該当する既知脆弱性 1 件 (重大度: CRITICAL / 悪用確認済み（CISA KEV）)',
            description: 'XSS vulnerability',
            recommendation:
              '修正済みバージョン（v3.5.0 以上）への速やかなアップデートを推奨します。なお、追加の検証も行ってください。',
            referenceUrls: [],
            scope: 'https://issues.example.test/',
          },
          {
            checkId: 'SEC-XCTO-01',
            category: 'http-headers',
            name: 'X-Content-Type-Options',
            status: 'warning',
            severity: 'low',
            observed: 'ヘッダー未設定',
            description: 'nosniff が未設定です。',
            recommendation: 'Webサーバーで「X-Content-Type-Options: nosniff」を付与してください。補足説明です。',
            referenceUrls: [],
            scope: 'https://issues.example.test/',
          },
          {
            checkId: 'SEC-CSP-01',
            category: 'http-headers',
            name: 'CSP (Content-Security-Policy)',
            status: 'warning',
            severity: 'medium',
            observed: 'ヘッダー未設定',
            description: 'CSP未設定',
            recommendation: 'CSPを設定してください。',
            referenceUrls: [],
            scope: 'https://issues.example.test/',
            exceptionStatus: 'accepted',
          },
        ],
      };

      const md = generateMarkdownReport(reportWithIssues);
      const roadmapSection = md.split('## 13. 推奨対応ロードマップ')[1]?.split('## 14.')[0] || '';

      // CRITICAL と LOW のみ該当し、MEDIUM（許容済み）は出ないこと
      expect(roadmapSection).toContain('**至急対応 (CRITICAL / HIGH):**');
      expect(roadmapSection).not.toContain('**計画的対応 (MEDIUM):**');
      expect(roadmapSection).toContain('**継続的改善 (LOW):**');

      // 各行が要確認の指摘名と recommendation の 1 文目になっていること
      expect(roadmapSection).toContain(
        '- **jQuery 既知脆弱性 (CVE-2020-11023)**: 修正済みバージョン（v3.5.0 以上）への速やかなアップデートを推奨します。'
      );
      expect(roadmapSection).not.toContain('なお、追加の検証も行ってください。');
      expect(roadmapSection).toContain(
        '- **X-Content-Type-Options**: Webサーバーで「X-Content-Type-Options: nosniff」を付与してください。'
      );
      expect(roadmapSection).not.toContain('補足説明です。');
    });

    it('指摘7: SERVER_ID、script[src]、a`b を含む値が、コードスパンの中でバックスラッシュなしに出力され、表セルでは | のみエスケープされること', () => {
      expect(formatMarkdownCodeSpan('SERVER_ID', { inTable: true })).toBe('`SERVER_ID`');
      expect(formatMarkdownCodeSpan('script[src]')).toBe('`script[src]`');
      expect(formatMarkdownCodeSpan('a`b', { inTable: true })).toBe('``a`b``');
      expect(formatMarkdownCodeSpan('a|b', { inTable: true })).toBe('`a\\|b`');
      expect(escapeMarkdownTableCell('SERVER_ID [test] a|b')).toBe('SERVER_ID [test] a\\|b');

      const reportEscape: InspectionReport = {
        ...dummyReportA,
        url: 'https://escape.example.test/',
        hostname: 'escape.example.test',
        technologies: [
          {
            technology: 'CustomTech',
            category: 'js-framework',
            detected: true,
            version: '1.0.0',
            confidence: 90,
            confidenceLevel: 'high',
            evidence: [
              {
                type: 'html',
                name: 'script[src]',
                value: 'a`b',
                source: 'https://escape.example.test/',
                weight: 90,
              },
            ],
          },
        ],
        cookies: [
          {
            name: 'SERVER_ID',
            domain: '.example.test',
            path: '/',
            secure: true,
            httpOnly: true,
            sameSite: 'lax',
          },
        ],
      };

      const md = generateMarkdownReport(reportEscape);
      expect(md).toContain('| `SERVER_ID` |');
      expect(md).not.toContain('SERVER\\_ID');
      expect(md).toContain('- **[html]** `script[src]`: ``a`b``');
      expect(md).not.toContain('script\\[src\\]');
      expect(md).not.toContain('a\\`b');
    });

    it('指摘6: EOL・脆弱性表で「Rev.2.1」「Bootstrap …最新LTS系列」「バージョン不明での現状維持」が出ず、照合ステータスと重複する CVE 列が「-」になること', () => {
      const reportSection6: InspectionReport = {
        ...dummyReportA,
        url: 'https://eol.example.test/',
        hostname: 'eol.example.test',
        advisoryDatabaseVersion: '20261031',
        technologies: [
          {
            technology: 'Bootstrap',
            category: 'js-css-library',
            detected: true,
            version: '4.6.2',
            supportStatus: 'EOL',
            eolDate: '2023-01-01',
            confidence: 90,
            confidenceLevel: 'high',
            evidence: [],
            advisories: [],
            productAdvisoryCount: 5,
            productSources: ['curated', 'OSV'],
            advisoryDataVersion: '20261031',
          },
          {
            technology: 'Node.js',
            category: 'programming-language',
            detected: true,
            version: '16.20.2',
            supportStatus: 'EOL',
            eolDate: '2023-09-11',
            confidence: 90,
            confidenceLevel: 'high',
            evidence: [],
            advisories: [],
            productAdvisoryCount: 4,
            productSources: ['NVD'],
            advisoryDataVersion: '20261031',
          },
          {
            technology: 'jQuery',
            category: 'js-css-library',
            detected: true,
            version: null,
            supportStatus: 'Unknown',
            advisoryMatchStatus: 'Needs Review',
            offlineMatchStatus: 'Unknown Version',
            confidence: 80,
            confidenceLevel: 'high',
            evidence: [],
            advisories: [],
            productAdvisoryCount: 6,
            productSources: ['curated'],
            advisoryDataVersion: '20261031',
          },
          {
            technology: 'Tailwind CSS',
            category: 'js-framework',
            detected: true,
            version: '3.4.1',
            supportStatus: 'Supported',
            advisoryMatchStatus: 'No Data',
            offlineMatchStatus: 'Not Covered',
            confidence: 85,
            confidenceLevel: 'high',
            evidence: [],
            advisories: [],
            productAdvisoryCount: 0,
            productSources: [],
            advisoryDataVersion: '20261031',
          },
        ],
      };

      const md = generateMarkdownReport(reportSection6);

      // Rev.2.1 が出ず、概要と同じ 2026-10-31 が出ること
      expect(md).not.toContain('Rev.2.1');
      expect(md).toContain('オフライン脆弱性DBスナップショット (2026-10-31) とのローカル突合結果です。');

      // Bootstrap の EOL は「サポート中のメジャーバージョンへの移行」となり、「最新LTS系列」が出ないこと
      const sec6 = md.split('## 6. EOL・既知脆弱性情報')[1]?.split('## 7.')[0] || '';
      const bootstrapLine = sec6.split('\n').find((l) => l.includes('**Bootstrap**')) || '';
      expect(bootstrapLine).toContain('サポート中のメジャーバージョンへの移行');
      expect(bootstrapLine).not.toContain('最新LTS系列');

      // LTS がある Node.js の EOL は「最新LTS系列への移行」になること
      const nodeLine = sec6.split('\n').find((l) => l.includes('**Node.js**')) || '';
      expect(nodeLine).toContain('最新LTS系列への移行');

      // バージョン不明の jQuery は「現状維持」ではなく「評価不可（バージョン不明）」になり、CVE列が「-」になること
      const jqLine = sec6.split('\n').find((l) => l.includes('**jQuery**')) || '';
      expect(jqLine).toContain('評価不可（バージョン不明）');
      expect(jqLine).not.toContain('現状維持');
      expect(jqLine).toContain('| - | - | - | 評価不可（バージョン不明） |');

      // 収録対象外の Tailwind CSS は「評価不可（収録対象外）」になり、CVE列が「-」になること
      const twLine = sec6.split('\n').find((l) => l.includes('**Tailwind CSS**')) || '';
      expect(twLine).toContain('評価不可（収録対象外）');
      expect(twLine).not.toContain('現状維持');
      expect(twLine).toContain('| この技術の脆弱性は収録していません | - | - | - | 評価不可（収録対象外） |');
    });

    it('指摘5 & 指摘8: 親ドメインの Cookie の注記が Cookie 節に入り、比較未実行時はセクション 11 も「比較未実行のため対象外」になること', () => {
      const md = generateMarkdownReport(dummyReportA);

      // セクション7に親ドメインの Cookie 注記があること
      const sec7 = md.split('## 7. Cookie属性診断')[1]?.split('## 8.')[0] || '';
      expect(sec7).toContain('このページが設定したとは限らない');

      // 前回レポート未指定（比較未実行）時はセクション11が「比較未実行のため対象外」になること
      const sec11 = md.split('## 11. 差分発生原因の推定分析')[1]?.split('## 12.')[0] || '';
      expect(sec11).toContain('比較未実行のため対象外');
      expect(sec11).not.toContain('分析対象の有意な差分変化はありません');
    });

    it('v1.7.1 T05 (N1): セクション 9 とダッシュボード通信先ビューに「読み込まれたリソースの取得元」の旨と非通信参照の除外が明記されていること', () => {
      const md = generateMarkdownReport(dummyReportA);
      expect(md).toContain(
        '## 9. 外部通信先・サードパーティ分析（読み込まれたリソースの取得元 / eTLD+1）'
      );
      expect(md).toContain(
        '`alternate`・`canonical`・`dns-prefetch`・`preconnect`・フォームの `action` 送信先など、読み込みを伴わない参照は含みません'
      );

      const dashHtml = renderExternalConnectionsHtml({
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
          security: 0,
          other: 1,
        },
        connections: [
          {
            hostname: 'secure.example.test',
            registrableDomain: 'example.test',
            publicSuffix: 'test',
            partyType: 'first-party',
            category: 'other',
            resourceCount: 3,
            sampleUrls: ['https://secure.example.test/'],
          },
        ],
      });
      expect(dashHtml).toContain('読み込まれたリソースの取得元ドメイン集計');
      expect(dashHtml).toContain('読み込みを伴わない参照は通信先に含めません');
    });

    it('v1.7.1 T09 (J, K, E4): セクション 14 で根拠の表示が代表 3 件＋「他 ○ 件」になり、WordPress のプラグイン・テーマ一覧が出力されること', () => {
      const wpReport: InspectionReport = {
        ...dummyReportA,
        technologies: [
          {
            technology: 'WordPress',
            category: 'cms',
            detected: true,
            version: '6.4.3',
            confidence: 95,
            confidenceLevel: 'high',
            detectionMethod: 'direct',
            runtimeStatus: 'confirmed',
            supportStatus: 'Supported',
            eolDate: null,
            advisoryMatchStatus: 'Not Affected',
            advisories: [],
            wpPlugins: [
              { name: 'contact-form-7', version: '5.8.7' },
              { name: 'akismet' },
            ],
            wpThemes: [{ name: 'twentytwentyfour', version: '1.0' }],
            evidence: [
              {
                type: 'script-url',
                name: 'script[src]',
                value: 'https://wp.example.test/wp-includes/js/wp-embed.min.js (v6.4.3)',
                source: 'https://wp.example.test/wp-includes/js/wp-embed.min.js',
                weight: 90,
              },
              {
                type: 'css-url',
                name: 'link[rel="stylesheet"]',
                value:
                  'https://wp.example.test/wp-includes/css/dist/block-library/style.min.css (v6.4.3)',
                source: 'https://wp.example.test/wp-includes/css/dist/block-library/style.min.css',
                weight: 85,
              },
              {
                type: 'script-url',
                name: 'script[src]',
                value:
                  'https://wp.example.test/wp-content/plugins/contact-form-7/includes/js/index.js',
                source:
                  'https://wp.example.test/wp-content/plugins/contact-form-7/includes/js/index.js',
                weight: 90,
              },
              {
                type: 'css-url',
                name: 'link[rel="stylesheet"]',
                value: 'https://wp.example.test/wp-content/themes/twentytwentyfour/style.css',
                source: 'https://wp.example.test/wp-content/themes/twentytwentyfour/style.css',
                weight: 85,
              },
              {
                type: 'link',
                name: 'link[rel="https://api.w.org/"]',
                value: 'https://wp.example.test/wp-json/',
                source: 'https://wp.example.test/wp-json/',
                weight: 95,
              },
            ],
          },
        ],
      };

      const md = generateMarkdownReport(wpReport);
      const sec14 = md.split('## 14. 検出根拠 (エビデンス詳細)')[1] || '';

      expect(sec14).toContain('- **検出されたプラグイン:** `contact-form-7` (ver: `5.8.7`), `akismet`');
      expect(sec14).toContain('- **検出されたテーマ:** `twentytwentyfour` (ver: `1.0`)');
      expect(sec14).toContain('- 他 2 件');
      // 4 件目・5 件目の根拠は Markdown の代表表示からは省略され、JSON 側には全 5 件残っていること
      expect(sec14).not.toContain('twentytwentyfour/style.css');
      expect(wpReport.technologies[0].evidence.length).toBe(5);
    });

    it('v1.7.1 T10 (指摘 3): セクション 8 にポリシーごとの問題点の表（ディレクティブ・重大度・内容・推奨）が出て、セクション 5 の観測値に問題点の要約が出ること', () => {
      const weakPolicy = parseCSPPolicy(
        "script-src 'self' 'unsafe-inline'; frame-ancestors 'self'",
        'response-header',
        'enforce'
      );
      const { policies, results } = analyzeCSPPolicies([weakPolicy], 'https://csp.example.test/', true);

      const cspReport: InspectionReport = {
        ...dummyReportA,
        url: 'https://csp.example.test/',
        hostname: 'csp.example.test',
        securityChecks: results,
        cspPolicies: policies,
      };

      const md = generateMarkdownReport(cspReport);
      const sec5 = md.split('## 5. セキュリティ診断結果')[1]?.split('## 6.')[0] || '';
      const sec8 = md.split('## 8. CSP（Content Security Policy）診断')[1]?.split('## 9.')[0] || '';

      // セクション 5 の観測値に問題点の要約が出て、「件のポリシーに改善点あり」が出ないこと
      expect(sec5).toContain("`'unsafe-inline' あり / object-src 未指定 / base-uri 未指定`");
      expect(sec5).not.toContain('件のポリシーに改善点あり');

      // セクション 8 にポリシーごとの問題点の表が出ること
      expect(sec8).toContain('| ディレクティブ | 重大度 | 内容 | 推奨 |');
      expect(sec8).toContain("| `script-src` | MEDIUM | script-src に 'unsafe-inline' が許可されており");
      expect(sec8).toContain('| `object-src` | LOW |');
      expect(sec8).toContain('| `base-uri` | LOW |');
    });

    it('v1.7.1 T10 (指摘 3): 問題点のない堅牢な CSP ポリシーおよび複数ポリシー積集合で防御済みのポリシーでは問題点なしと表示されること', () => {
      const headerFaOnly = parseCSPPolicy("frame-ancestors 'self'", 'response-header', 'enforce');
      const metaStrict = parseCSPPolicy(
        "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'self'",
        'meta',
        'enforce'
      );
      const { policies, results } = analyzeCSPPolicies(
        [headerFaOnly, metaStrict],
        'https://csp-combo.example.test/',
        true
      );

      const comboReport: InspectionReport = {
        ...dummyReportA,
        url: 'https://csp-combo.example.test/',
        hostname: 'csp-combo.example.test',
        securityChecks: results,
        cspPolicies: policies,
      };

      const md = generateMarkdownReport(comboReport);
      const sec8 = md.split('## 8. CSP（Content Security Policy）診断')[1]?.split('## 9.')[0] || '';

      expect(sec8).toContain('#### ポリシー #1 [取得元: response-header, モード: enforce]');
      expect(sec8).toContain('#### ポリシー #2 [取得元: meta, モード: enforce]');
      expect(sec8).toContain('> このポリシーに検出された問題点はありません。');
      expect(sec8).not.toContain('`script-src / default-src`');
    });
  });
});
