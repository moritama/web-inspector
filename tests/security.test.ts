/**
 * Web Technology & Security Inspector
 * セキュリティ診断エンジンの単体テスト (tests/security.test.ts)
 */

import { describe, expect, it } from 'vitest';
import { renderFullSecurityHtml } from '../src/dashboard/render';
import { exportReportToCsv } from '../src/export/csv';
import { generateMarkdownReport } from '../src/export/markdown';
import { renderSecurityCheckRowHtml } from '../src/popup/render';
import { checkCookies } from '../src/security/cookies';
import { SecurityEngine } from '../src/security/engine';
import { checkHttpHeaders } from '../src/security/headers';
import { checkHttpsAndMixedContent } from '../src/security/https';
import { summarizeSecurityChecks } from '../src/shared/security-status';
import { InspectedCookieInfo, InspectionReport, SecurityCheckResult } from '../src/shared/types';
import { readPackageVersion } from './helpers/release-version';

describe('Security Headers', () => {
  it('HSTSが未設定の場合にwarningを返すこと', () => {
    const checks = checkHttpHeaders({}, 'https://example.com/', true);
    const hsts = checks.find((c) => c.name.includes('HSTS'));
    expect(hsts).toBeDefined();
    expect(hsts?.status).toBe('warning');
    expect(hsts?.severity).toBe('medium');
  });

  it('適切なHSTSが設定されている場合にpassを返すこと', () => {
    const headers = {
      'strict-transport-security': ['max-age=31536000; includeSubDomains; preload'],
    };
    const checks = checkHttpHeaders(headers, 'https://example.com/', true);
    const hsts = checks.find((c) => c.name.includes('HSTS'));
    expect(hsts?.status).toBe('pass');
  });

  it('CSPの脆弱な設定 (unsafe-inline) を検知すること', () => {
    const headers = {
      'content-security-policy': ["default-src 'self'; script-src 'self' 'unsafe-inline'"],
    };
    const checks = checkHttpHeaders(headers, 'https://example.com/', true);
    const csp = checks.find((c) => c.name.includes('CSP'));
    expect(csp?.status).toBe('warning');
    expect(csp?.description).toContain('unsafe-inline');
  });

  it('CORS設定 (ワイルドカード + Credentials) はブラウザが拒否する設定ミスとしてinfoで検知すること (SPEC-12)', () => {
    const headers = {
      'access-control-allow-origin': ['*'],
      'access-control-allow-credentials': ['true'],
    };
    const checks = checkHttpHeaders(headers, 'https://example.com/', true);
    const cors = checks.find((c) => c.category === 'cors');
    expect(cors?.checkId).toBe('SEC-CORS-01');
    expect(cors?.severity).toBe('info');
    expect(cors?.status).toBe('info');
  });

  describe('T07 (SPEC-12): ヘッダー値検証のテーブル駆動テスト', () => {
    it.each([
      // X-Frame-Options
      {
        label: 'XFO: DENY は pass (info)',
        headers: { 'x-frame-options': ['DENY'] },
        prefix: 'SEC-XFO-',
        expectedId: 'SEC-XFO-00',
        expectedStatus: 'pass',
        expectedSeverity: 'info',
      },
      {
        label: 'XFO: SAMEORIGIN は pass (info)',
        headers: { 'x-frame-options': ['SAMEORIGIN'] },
        prefix: 'SEC-XFO-',
        expectedId: 'SEC-XFO-00',
        expectedStatus: 'pass',
        expectedSeverity: 'info',
      },
      {
        label: 'XFO: ALLOWALL は pass にせず warning (medium)',
        headers: { 'x-frame-options': ['ALLOWALL'] },
        prefix: 'SEC-XFO-',
        expectedId: 'SEC-XFO-02',
        expectedStatus: 'warning',
        expectedSeverity: 'medium',
      },
      {
        label: 'XFO: ALLOW-FROM は廃止値のため warning (medium)',
        headers: { 'x-frame-options': ['ALLOW-FROM https://example.org'] },
        prefix: 'SEC-XFO-',
        expectedId: 'SEC-XFO-02',
        expectedStatus: 'warning',
        expectedSeverity: 'medium',
      },
      {
        label: 'XFO: 不正値は warning (medium)',
        headers: { 'x-frame-options': ['INVALID_VALUE'] },
        prefix: 'SEC-XFO-',
        expectedId: 'SEC-XFO-02',
        expectedStatus: 'warning',
        expectedSeverity: 'medium',
      },
      {
        label: 'XFO: ALLOWALL でも CSP frame-ancestors があればそちらを優先して pass (info)',
        headers: {
          'x-frame-options': ['ALLOWALL'],
          'content-security-policy': ["default-src 'self'; frame-ancestors 'self'"],
        },
        prefix: 'SEC-XFO-',
        expectedId: 'SEC-XFO-00',
        expectedStatus: 'pass',
        expectedSeverity: 'info',
      },
      // HSTS
      {
        label: 'HSTS: 未設定は warning (medium)',
        headers: {},
        prefix: 'SEC-HSTS-',
        expectedId: 'SEC-HSTS-01',
        expectedStatus: 'warning',
        expectedSeverity: 'medium',
      },
      {
        label: 'HSTS: max-age=0 は明示的な無効化として warning (medium)',
        headers: { 'strict-transport-security': ['max-age=0'] },
        prefix: 'SEC-HSTS-',
        expectedId: 'SEC-HSTS-02',
        expectedStatus: 'warning',
        expectedSeverity: 'medium',
      },
      {
        label: 'HSTS: max-age が 1 年 (31536000秒) 未満は warning (low)',
        headers: { 'strict-transport-security': ['max-age=15552000'] },
        prefix: 'SEC-HSTS-',
        expectedId: 'SEC-HSTS-02',
        expectedStatus: 'warning',
        expectedSeverity: 'low',
      },
      {
        label: 'HSTS: max-age が 1 年 (31536000秒) 以上は pass (info)',
        headers: { 'strict-transport-security': ['max-age=31536000'] },
        prefix: 'SEC-HSTS-',
        expectedId: 'SEC-HSTS-00',
        expectedStatus: 'pass',
        expectedSeverity: 'info',
      },
      // Referrer-Policy
      {
        label: 'Referrer-Policy: 未設定はブラウザ既定値で安全のため info (info) (v1.7.1 T01)',
        headers: {},
        prefix: 'SEC-REF-',
        expectedId: 'SEC-REF-01',
        expectedStatus: 'info',
        expectedSeverity: 'info',
      },
      {
        label: 'Referrer-Policy: strict-origin-when-cross-origin は pass (info)',
        headers: { 'referrer-policy': ['strict-origin-when-cross-origin'] },
        prefix: 'SEC-REF-',
        expectedId: 'SEC-REF-00',
        expectedStatus: 'pass',
        expectedSeverity: 'info',
      },
      {
        label: 'Referrer-Policy: unsafe-url は warning (low)',
        headers: { 'referrer-policy': ['unsafe-url'] },
        prefix: 'SEC-REF-',
        expectedId: 'SEC-REF-02',
        expectedStatus: 'warning',
        expectedSeverity: 'low',
      },
      {
        label: 'Referrer-Policy: no-referrer-when-downgrade は info (info)',
        headers: { 'referrer-policy': ['no-referrer-when-downgrade'] },
        prefix: 'SEC-REF-',
        expectedId: 'SEC-REF-03',
        expectedStatus: 'info',
        expectedSeverity: 'info',
      },
      {
        label: 'Referrer-Policy: 無効なポリシー値は warning (low)',
        headers: { 'referrer-policy': ['unknown-policy'] },
        prefix: 'SEC-REF-',
        expectedId: 'SEC-REF-02',
        expectedStatus: 'warning',
        expectedSeverity: 'low',
      },
      // CORS
      {
        label: 'CORS: * と Allow-Credentials: true の組み合わせは info (info)',
        headers: {
          'access-control-allow-origin': ['*'],
          'access-control-allow-credentials': ['true'],
        },
        prefix: 'SEC-CORS-',
        expectedId: 'SEC-CORS-01',
        expectedStatus: 'info',
        expectedSeverity: 'info',
      },
      {
        label: 'CORS: * のみは info (info)',
        headers: { 'access-control-allow-origin': ['*'] },
        prefix: 'SEC-CORS-',
        expectedId: 'SEC-CORS-02',
        expectedStatus: 'info',
        expectedSeverity: 'info',
      },
    ])('$label', ({ headers, prefix, expectedId, expectedStatus, expectedSeverity }) => {
      const checks = checkHttpHeaders(headers as Record<string, string[]>, 'https://example.com/', true);
      const target = checks.find((c) => c.checkId.startsWith(prefix));
      expect(target).toBeDefined();
      expect(target?.checkId).toBe(expectedId);
      expect(target?.status).toBe(expectedStatus);
      expect(target?.severity).toBe(expectedSeverity);
    });
  });

  describe('v1.7.1 T01: X-Frame-Options の項目名統一と frame-ancestors 観測値区別', () => {
    it('PASS・WARN・frame-ancestors 判定の 3 パターンすべてで name が同一であり、frame-ancestors 判定時は observed で区別できること', () => {
      const passChecks = checkHttpHeaders(
        { 'x-frame-options': ['DENY'] },
        'https://app.example.test/',
        true
      );
      const warnUnsetChecks = checkHttpHeaders({}, 'https://app.example.test/', true);
      const warnInvalidChecks = checkHttpHeaders(
        { 'x-frame-options': ['ALLOWALL'] },
        'https://app.example.test/',
        true
      );
      const frameAncestorsOnlyChecks = checkHttpHeaders(
        { 'content-security-policy': ["default-src 'self'; frame-ancestors 'none'"] },
        'https://app.example.test/',
        true
      );
      const frameAncestorsWithXfoChecks = checkHttpHeaders(
        {
          'x-frame-options': ['SAMEORIGIN'],
          'content-security-policy': ["default-src 'self'; frame-ancestors 'self'"],
        },
        'https://app.example.test/',
        true
      );

      const passXfo = passChecks.find((c) => c.checkId.startsWith('SEC-XFO-'));
      const warnUnsetXfo = warnUnsetChecks.find((c) => c.checkId.startsWith('SEC-XFO-'));
      const warnInvalidXfo = warnInvalidChecks.find((c) => c.checkId.startsWith('SEC-XFO-'));
      const faOnlyXfo = frameAncestorsOnlyChecks.find((c) => c.checkId.startsWith('SEC-XFO-'));
      const faWithXfo = frameAncestorsWithXfoChecks.find((c) => c.checkId.startsWith('SEC-XFO-'));

      expect(passXfo?.name).toBe('X-Frame-Options');
      expect(warnUnsetXfo?.name).toBe('X-Frame-Options');
      expect(warnInvalidXfo?.name).toBe('X-Frame-Options');
      expect(faOnlyXfo?.name).toBe('X-Frame-Options');
      expect(faWithXfo?.name).toBe('X-Frame-Options');

      expect(passXfo?.observed).toBe('DENY');
      expect(faOnlyXfo?.observed).toContain('CSP frame-ancestors により保護');
      expect(faWithXfo?.observed).toContain('CSP frame-ancestors により保護');
    });
  });

  describe('v1.7.1 T01: ステータス表示と件数の整合', () => {
    it.each([
      {
        label: 'info の Referrer-Policy・Permissions-Policy・Report-Only CSP を含む標準ヘッダー構成',
        checks: checkHttpHeaders(
          { 'content-security-policy-report-only': ["default-src 'self'"] },
          'https://portal.example.test/',
          true
        ),
        expectedAttention: 3, // HSTS未設定(medium), XFO未設定(medium), XCTO未設定(low)
        expectedCritical: 0,
        expectedHigh: 0,
        expectedMedium: 2,
        expectedLow: 1,
      },
      {
        label: '例外設定（accepted / false-positive / muted）で除外された項目を含むケース',
        checks: [
          {
            checkId: 'SEC-CVE-JQUERY',
            category: 'library-security',
            name: 'jQuery (3.4.1) 既知脆弱性',
            status: 'fail',
            severity: 'critical',
            observed: 'バージョン 3.4.1 に該当する既知脆弱性 3 件 (重大度: CRITICAL / 悪用確認済み（CISA KEV）)',
            description: '既知の脆弱性が存在します。',
            recommendation: '更新してください。',
            referenceUrls: [],
            scope: 'https://portal.example.test/',
            exceptionStatus: 'accepted',
          },
          {
            checkId: 'SEC-HTTPS-01',
            category: 'https-communication',
            name: '暗号化通信未適用',
            status: 'fail',
            severity: 'high',
            observed: 'http://portal.example.test/',
            description: 'HTTP接続です。',
            recommendation: 'HTTPS化してください。',
            referenceUrls: [],
            scope: 'http://portal.example.test/',
            exceptionStatus: 'active',
          },
          {
            checkId: 'SEC-HSTS-01',
            category: 'http-headers',
            name: 'HSTS (Strict-Transport-Security)',
            status: 'warning',
            severity: 'medium',
            observed: 'ヘッダー未設定',
            description: 'HSTSが未設定です。',
            recommendation: '設定してください。',
            referenceUrls: [],
            scope: 'https://portal.example.test/',
            exceptionStatus: 'false-positive',
          },
          {
            checkId: 'SEC-XCTO-01',
            category: 'http-headers',
            name: 'X-Content-Type-Options',
            status: 'warning',
            severity: 'low',
            observed: 'ヘッダー未設定',
            description: 'nosniffが未設定です。',
            recommendation: '設定してください。',
            referenceUrls: [],
            scope: 'https://portal.example.test/',
            exceptionStatus: 'muted',
          },
          {
            checkId: 'SEC-REF-01',
            category: 'http-headers',
            name: 'Referrer-Policy',
            status: 'info',
            severity: 'info',
            observed: 'ヘッダー未設定 (ブラウザ既定値 strict-origin-when-cross-origin)',
            description: 'Referrer-Policyが未設定です。',
            recommendation: '検討してください。',
            referenceUrls: [],
            scope: 'https://portal.example.test/',
          },
          {
            checkId: 'SEC-PERM-01',
            category: 'http-headers',
            name: 'Permissions-Policy',
            status: 'info',
            severity: 'info',
            observed: 'ヘッダー未設定',
            description: 'Permissions-Policyが未設定です。',
            recommendation: '検討してください。',
            referenceUrls: [],
            scope: 'https://portal.example.test/',
          },
          {
            checkId: 'SEC-XFO-00',
            category: 'http-headers',
            name: 'X-Frame-Options',
            status: 'pass',
            severity: 'info',
            observed: 'DENY',
            description: '適切に設定されています。',
            recommendation: '維持してください。',
            referenceUrls: [],
            scope: 'https://portal.example.test/',
          },
        ] satisfies SecurityCheckResult[],
        expectedAttention: 1, // SEC-HTTPS-01 のみ
        expectedCritical: 0,
        expectedHigh: 1,
        expectedMedium: 0,
        expectedLow: 0,
      },
    ])(
      'summary.securityFindings の CRITICAL〜LOW 合計が requiresAttentionCount と常に一致すること: $label',
      ({ checks, expectedAttention, expectedCritical, expectedHigh, expectedMedium, expectedLow }) => {
        const { requiresAttentionCount, securityFindings } = summarizeSecurityChecks(checks);
        const severitySum =
          (securityFindings.critical ?? 0) +
          securityFindings.high +
          securityFindings.medium +
          securityFindings.low;

        expect(requiresAttentionCount).toBe(expectedAttention);
        expect(severitySum).toBe(requiresAttentionCount);
        expect(securityFindings.critical).toBe(expectedCritical);
        expect(securityFindings.high).toBe(expectedHigh);
        expect(securityFindings.medium).toBe(expectedMedium);
        expect(securityFindings.low).toBe(expectedLow);

        const expectedInfoCount = checks.filter((c) => c.status === 'pass' || c.status === 'info').length;
        expect(securityFindings.info).toBe(expectedInfoCount);
      }
    );

    it('status が info の項目が Markdown・CSV・ポップアップ・ダッシュボードで WARN と表示されないこと', () => {
      const checks = checkHttpHeaders(
        {
          'strict-transport-security': ['max-age=31536000'],
          'x-frame-options': ['DENY'],
          'x-content-type-options': ['nosniff'],
          'content-security-policy-report-only': ["default-src 'self'"],
        },
        'https://clean.example.test/',
        true
      );
      const infoChecks = checks.filter((c) => c.status === 'info');
      expect(infoChecks.length).toBeGreaterThanOrEqual(3); // Referrer-Policy, Permissions-Policy, CSP-Report-Only

      const { requiresAttentionCount, securityFindings } = summarizeSecurityChecks(checks);
      expect(requiresAttentionCount).toBe(0);

      const report: InspectionReport = {
        id: 'rep_t01_info_check',
        url: 'https://clean.example.test/',
        hostname: 'clean.example.test',
        inspectedAt: '2026-11-07T00:00:00.000Z',
        extensionVersion: readPackageVersion(),
        rulesVersion: '2026.10.2',
        technologies: [],
        securityChecks: checks,
        cookies: [],
        cspPolicies: [],
        mixedContent: [],
        summary: {
          totalTechnologies: 0,
          requiresAttentionCount,
          securityFindings,
          librarySecurity: {
            eolCount: 0,
            vulnerableLibraryCount: 0,
            mismatchCount: 0,
          },
          isHttps: true,
          mixedContentCount: 0,
        },
      };

      const md = generateMarkdownReport(report);
      expect(md).toContain('| **INFO (情報)** | **' + securityFindings.info + '** | 参考情報・問題のない項目 |');
      expect(md).not.toContain('**WARN**');
      for (const infoCheck of infoChecks) {
        expect(md).toContain(`| ${infoCheck.name} | INFO |`);
      }

      const csv = exportReportToCsv(report);
      expect(csv).not.toContain(',WARN,');
      expect(csv).toContain('"SEC-REF-01","http-headers","Referrer-Policy","info","info"');

      for (const infoCheck of infoChecks) {
        const popupRowHtml = renderSecurityCheckRowHtml(infoCheck);
        expect(popupRowHtml).toContain('sev-info');
        expect(popupRowHtml).toContain('>情報<');
        expect(popupRowHtml).not.toContain('WARN');
        expect(popupRowHtml).not.toContain('警告');
        expect(popupRowHtml).not.toContain('注意');
      }

      const dashHtml = renderFullSecurityHtml(infoChecks);
      expect(dashHtml).toContain('sev-info');
      expect(dashHtml).toContain('>INFO<');
      expect(dashHtml).not.toContain('WARN');
      expect(dashHtml).not.toContain('>LOW<');
    });
  });

  describe('v1.7.1 T08 (指摘 D): X-AspNet-Version ヘッダー露出の診断 (SEC-DISC-03)', () => {
    it('X-AspNet-Version が存在する場合に LOW (warning) の指摘 SEC-DISC-03 が追加されること（スナップショット testaspnet 検証含む）', () => {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const fs = require('node:fs');
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const path = require('node:path');
      const snapPath = path.resolve(
        __dirname,
        'fixtures',
        'snapshots',
        'testaspnet.vulnweb.com.json'
      );
      const snap = JSON.parse(fs.readFileSync(snapPath, 'utf-8'));

      const checks = checkHttpHeaders(snap.responseHeaders, snap.url, false);
      const aspNetDisc = checks.find((c) => c.checkId === 'SEC-DISC-03');
      expect(aspNetDisc).toBeDefined();
      expect(aspNetDisc?.category).toBe('information-disclosure');
      expect(aspNetDisc?.status).toBe('warning');
      expect(aspNetDisc?.severity).toBe('low');
      expect(aspNetDisc?.observed).toBe('X-AspNet-Version: 2.0.50727');
    });
  });
});

describe('Cookie Security', () => {
  it('セッションCookieのHttpOnlyおよびSecure欠落を検知すること', () => {
    const cookies: InspectedCookieInfo[] = [
      {
        name: 'PHPSESSID',
        domain: 'example.com',
        path: '/',
        secure: false,
        httpOnly: false,
        sameSite: 'unspecified',
        session: true,
        issues: [],
      },
    ];

    const { checks } = checkCookies(cookies, 'https://example.com/', true);
    const secureIssue = checks.find((c) => c.checkId === 'SEC-COOKIE-SECURE');
    const httpOnlyIssue = checks.find((c) => c.checkId === 'SEC-COOKIE-HTTPONLY');

    expect(secureIssue).toBeDefined();
    expect(httpOnlyIssue).toBeDefined();
  });
});

describe('HTTPS & Mixed Content', () => {
  it('平文HTTP接続をFail (High) と判定すること', () => {
    const checks = checkHttpsAndMixedContent('http://example.com/', false, []);
    const httpsCheck = checks.find((c) => c.checkId === 'SEC-HTTPS-01');
    expect(httpsCheck?.severity).toBe('high');
    expect(httpsCheck?.status).toBe('fail');
  });

  it('HTTPSページ内のHTTPスクリプト（アクティブ混在）を検知すること', () => {
    const checks = checkHttpsAndMixedContent('https://example.com/', true, [
      { resourceType: 'script', url: 'http://insecure.com/evil.js' },
    ]);
    const mixed = checks.find((c) => c.checkId === 'SEC-MIXED-ACTIVE');
    expect(mixed?.severity).toBe('high');
  });

  it.each([
    { resourceType: 'form' as const, url: 'http://insecure.com/login', expectedId: 'SEC-MIXED-ACTIVE', expectedSeverity: 'high' },
    { resourceType: 'object' as const, url: 'http://insecure.com/movie.swf', expectedId: 'SEC-MIXED-ACTIVE', expectedSeverity: 'high' },
    { resourceType: 'embed' as const, url: 'http://insecure.com/plugin.swf', expectedId: 'SEC-MIXED-ACTIVE', expectedSeverity: 'high' },
    { resourceType: 'image' as const, url: 'http://insecure.com/banner.jpg', expectedId: 'SEC-MIXED-PASSIVE', expectedSeverity: 'low' },
    { resourceType: 'video' as const, url: 'http://insecure.com/clip.mp4', expectedId: 'SEC-MIXED-PASSIVE', expectedSeverity: 'low' },
    { resourceType: 'audio' as const, url: 'http://insecure.com/sound.mp3', expectedId: 'SEC-MIXED-PASSIVE', expectedSeverity: 'low' },
  ])(
    'T07 (SPEC-15): 混在コンテンツ種別 $resourceType が $expectedId ($expectedSeverity) として診断されること',
    ({ resourceType, url, expectedId, expectedSeverity }) => {
      const checks = checkHttpsAndMixedContent('https://example.com/', true, [{ resourceType, url }]);
      const check = checks.find((c) => c.checkId === expectedId);
      expect(check).toBeDefined();
      expect(check?.severity).toBe(expectedSeverity);
      if (expectedId === 'SEC-MIXED-PASSIVE') {
        expect(check?.description).toContain('HTTPSへ昇格');
      }
    }
  );

  describe('v1.7.1 T06 (指摘 I): 混在コンテンツの観測値 (observed) への要素・マスク済み URL 出力', () => {
    it('アクティブ・パッシブ混在コンテンツの observed に要素ラベルと URL が出力され、クエリ文字列・フラグメントがマスクされること', () => {
      const checks = checkHttpsAndMixedContent('https://secure.example.test/', true, [
        {
          resourceType: 'script',
          url: 'http://cdn.example.test/app.js?token=secret123#section',
        },
        {
          resourceType: 'form',
          url: 'http://form.example.test/submit?session=abc',
        },
        {
          resourceType: 'image',
          url: 'http://img.example.test/photo.jpg?sig=xyz#top',
        },
      ]);

      const active = checks.find((c) => c.checkId === 'SEC-MIXED-ACTIVE');
      expect(active).toBeDefined();
      expect(active?.observed).toBe(
        '2件 (script: http://cdn.example.test/app.js, form[action]: http://form.example.test/submit)'
      );
      expect(active?.observed).not.toContain('secret123');
      expect(active?.observed).not.toContain('session=abc');

      const passive = checks.find((c) => c.checkId === 'SEC-MIXED-PASSIVE');
      expect(passive).toBeDefined();
      expect(passive?.observed).toBe('1件 (img: http://img.example.test/photo.jpg)');
      expect(passive?.observed).not.toContain('sig=xyz');
    });

    it('混在コンテンツが 3 件を超える場合、先頭 3 件の要素・URL に続けて「（他 ○ 件）」が出力されること', () => {
      const checks = checkHttpsAndMixedContent('https://secure.example.test/', true, [
        { resourceType: 'image', url: 'http://img.example.test/1.jpg' },
        { resourceType: 'image', url: 'http://img.example.test/2.jpg' },
        { resourceType: 'video', url: 'http://img.example.test/3.mp4' },
        { resourceType: 'audio', url: 'http://img.example.test/4.mp3' },
        { resourceType: 'image', url: 'http://img.example.test/5.jpg' },
      ]);

      const passive = checks.find((c) => c.checkId === 'SEC-MIXED-PASSIVE');
      expect(passive).toBeDefined();
      expect(passive?.observed).toBe(
        '5件 (img: http://img.example.test/1.jpg, img: http://img.example.test/2.jpg, video: http://img.example.test/3.mp4（他 2 件）)'
      );
    });
  });

  describe('v1.7.1 T09 (L, E5): 廃止済み計測タグ (ga.js / analytics.js) の INFO 指摘と要確認件数の非増加', () => {
    it('ga.js を読むページで SEC-LEGACY-TAG-01 (INFO) が 1 件出て、要確認 (requiresAttentionCount) の件数が増えないこと', () => {
      const engine = new SecurityEngine();
      const baseDom = {
        url: 'https://wp.example.test/',
        title: 'WP',
        metaTags: [],
        scriptUrls: ['https://wp.example.test/app.js'],
        linkUrls: [],
        domMarkers: [],
        htmlSnippets: [],
        mixedContent: [],
        cookiesFromDocument: [],
        cssAssets: [],
      };
      const baseNetwork = {
        url: 'https://wp.example.test/',
        responseHeaders: {
          'strict-transport-security': ['max-age=31536000; includeSubDomains'],
          'x-content-type-options': ['nosniff'],
          'x-frame-options': ['SAMEORIGIN'],
          'referrer-policy': ['strict-origin-when-cross-origin'],
          'permissions-policy': ['geolocation=()'],
          'content-security-policy': ["default-src 'self'"],
        },
        cookies: [],
      };

      const withoutLegacy = engine.evaluate({
        url: 'https://wp.example.test/',
        dom: baseDom,
        network: baseNetwork,
      });
      const summaryWithout = summarizeSecurityChecks(withoutLegacy.checks);

      const withLegacy = engine.evaluate({
        url: 'https://wp.example.test/',
        dom: {
          ...baseDom,
          scriptUrls: ['https://wp.example.test/app.js', 'https://ssl.google-analytics.com/ga.js'],
        },
        network: baseNetwork,
      });
      const summaryWith = summarizeSecurityChecks(withLegacy.checks);

      const legacyCheck = withLegacy.checks.find((c) => c.checkId === 'SEC-LEGACY-TAG-01');
      expect(legacyCheck).toBeDefined();
      expect(legacyCheck?.status).toBe('info');
      expect(legacyCheck?.severity).toBe('info');
      expect(legacyCheck?.description).toContain('計測されていない可能性');
      expect(legacyCheck?.recommendation).toContain('削除を検討');

      // 要確認件数（requiresAttentionCount）は増えず、INFO が 1 件増えること
      expect(summaryWith.requiresAttentionCount).toBe(summaryWithout.requiresAttentionCount);
      expect(summaryWith.securityFindings.info).toBe(summaryWithout.securityFindings.info + 1);
    });
  });

  describe('v1.7.1 T11: HSTS (N11)・証明書注記 (N12)・項目名の統一 (R05)', () => {
    it.each([
      {
        label: 'max-age=15552000; includeSubDomains; preload で preload の INFO が出ること',
        header: 'max-age=15552000; includeSubDomains; preload',
        expectedMainId: 'SEC-HSTS-02',
        expectedMainStatus: 'warning',
        expectedMainSeverity: 'low',
        expectPreloadInfo: true,
      },
      {
        label: 'max-age=31536000; preload (includeSubDomains なし) でも preload の INFO が出ること',
        header: 'max-age=31536000; preload',
        expectedMainId: 'SEC-HSTS-00',
        expectedMainStatus: 'pass',
        expectedMainSeverity: 'info',
        expectPreloadInfo: true,
      },
      {
        label: 'max-age=3600 (1日未満・0以外) で MEDIUM になること',
        header: 'max-age=3600',
        expectedMainId: 'SEC-HSTS-02',
        expectedMainStatus: 'warning',
        expectedMainSeverity: 'medium',
        expectPreloadInfo: false,
      },
      {
        label: 'max-age=31536000; includeSubDomains; preload で PASS になり preload の INFO は出ないこと',
        header: 'max-age=31536000; includeSubDomains; preload',
        expectedMainId: 'SEC-HSTS-00',
        expectedMainStatus: 'pass',
        expectedMainSeverity: 'info',
        expectPreloadInfo: false,
      },
    ])('N11 HSTS: $label', ({ header, expectedMainId, expectedMainStatus, expectedMainSeverity, expectPreloadInfo }) => {
      const checks = checkHttpHeaders(
        { 'strict-transport-security': [header] },
        'https://hsts.example.test/',
        true
      );
      const mainCheck = checks.find((c) => c.checkId === expectedMainId);
      expect(mainCheck).toBeDefined();
      expect(mainCheck?.name).toBe('HSTS (Strict-Transport-Security)');
      expect(mainCheck?.status).toBe(expectedMainStatus);
      expect(mainCheck?.severity).toBe(expectedMainSeverity);

      const preloadInfo = checks.find((c) => c.checkId === 'SEC-HSTS-03');
      if (expectPreloadInfo) {
        expect(preloadInfo).toBeDefined();
        expect(preloadInfo?.name).toBe('HSTS (Strict-Transport-Security)');
        expect(preloadInfo?.status).toBe('info');
        expect(preloadInfo?.severity).toBe('info');
        expect(preloadInfo?.observed).toContain('preload の登録条件を満たしていない');
        expect(preloadInfo?.description).toContain('preload の登録条件を満たしていない');
      } else {
        expect(preloadInfo).toBeUndefined();
      }
    });

    it('N12 証明書: HTTPS 接続時の観測値が「HTTPS で接続（証明書の有効性は対象外）」になること', () => {
      const checks = checkHttpsAndMixedContent('https://cert.example.test/', true, []);
      const httpsPass = checks.find((c) => c.checkId === 'SEC-HTTPS-00');
      expect(httpsPass).toBeDefined();
      expect(httpsPass?.name).toBe('HTTPS暗号化通信');
      expect(httpsPass?.observed).toBe('HTTPS で接続（証明書の有効性は対象外）');
    });

    it.each([
      {
        group: 'SEC-HTTPS-* (PASS)',
        run: () => checkHttpsAndMixedContent('https://secure.example.test/', true, []),
        targetId: 'SEC-HTTPS-00',
        expectedStatus: 'pass',
        expectedName: 'HTTPS暗号化通信',
      },
      {
        group: 'SEC-HTTPS-* (FAIL)',
        run: () => checkHttpsAndMixedContent('http://plain.example.test/', false, []),
        targetId: 'SEC-HTTPS-01',
        expectedStatus: 'fail',
        expectedName: 'HTTPS暗号化通信',
      },
      {
        group: 'SEC-CORS-* (SEC-CORS-01: * + credentials)',
        run: () =>
          checkHttpHeaders(
            {
              'access-control-allow-origin': ['*'],
              'access-control-allow-credentials': ['true'],
            },
            'https://cors.example.test/',
            true
          ),
        targetId: 'SEC-CORS-01',
        expectedStatus: 'info',
        expectedName: 'CORS (Cross-Origin Resource Sharing)',
      },
      {
        group: 'SEC-CORS-* (SEC-CORS-02: *)',
        run: () =>
          checkHttpHeaders(
            { 'access-control-allow-origin': ['*'] },
            'https://cors.example.test/',
            true
          ),
        targetId: 'SEC-CORS-02',
        expectedStatus: 'info',
        expectedName: 'CORS (Cross-Origin Resource Sharing)',
      },
      {
        group: 'SEC-REF-* (PASS: strict-origin-when-cross-origin)',
        run: () =>
          checkHttpHeaders(
            { 'referrer-policy': ['strict-origin-when-cross-origin'] },
            'https://ref.example.test/',
            true
          ),
        targetId: 'SEC-REF-00',
        expectedStatus: 'pass',
        expectedName: 'Referrer-Policy',
      },
      {
        group: 'SEC-REF-* (INFO: 未設定)',
        run: () => checkHttpHeaders({}, 'https://ref.example.test/', true),
        targetId: 'SEC-REF-01',
        expectedStatus: 'info',
        expectedName: 'Referrer-Policy',
      },
      {
        group: 'SEC-REF-* (WARN: 無効な設定値)',
        run: () =>
          checkHttpHeaders(
            { 'referrer-policy': ['invalid-policy-token'] },
            'https://ref.example.test/',
            true
          ),
        targetId: 'SEC-REF-02',
        expectedStatus: 'warning',
        expectedName: 'Referrer-Policy',
      },
      {
        group: 'SEC-REF-* (WARN: unsafe-url)',
        run: () =>
          checkHttpHeaders(
            { 'referrer-policy': ['unsafe-url'] },
            'https://ref.example.test/',
            true
          ),
        targetId: 'SEC-REF-02',
        expectedStatus: 'warning',
        expectedName: 'Referrer-Policy',
      },
      {
        group: 'SEC-REF-* (INFO: no-referrer-when-downgrade)',
        run: () =>
          checkHttpHeaders(
            { 'referrer-policy': ['no-referrer-when-downgrade'] },
            'https://ref.example.test/',
            true
          ),
        targetId: 'SEC-REF-03',
        expectedStatus: 'info',
        expectedName: 'Referrer-Policy',
      },
    ])('R05 項目名の統一: $group で項目名が「$expectedName」に統一されていること', ({ run, targetId, expectedStatus, expectedName }) => {
      const checks = run();
      const target = checks.find((c) => c.checkId === targetId);
      expect(target).toBeDefined();
      expect(target?.status).toBe(expectedStatus);
      expect(target?.name).toBe(expectedName);
    });
  });
});
