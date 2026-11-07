/**
 * Web Technology & Security Inspector
 * Cookie属性・用途別判定単体テスト (tests/cookies.test.ts) - IMP-01 & IMP-04 (Rev.2.1)
 */

import { describe, expect, it } from 'vitest';
import { exportReportToCsv } from '../src/export/csv';
import { exportReportToJson } from '../src/export/json';
import { generateMarkdownReport } from '../src/export/markdown';
import {
  checkCookies,
  classifyCookie,
  classifyCookieAdvanced,
  evaluateCookie,
  formatCookieCategory,
  normalizeCookieCategory,
  normalizeSameSite,
} from '../src/security/cookies';
import { CookieCategory, InspectionReport } from '../src/shared/types';
import { sanitizeReportUrls } from '../src/storage/history';

describe('Cookie用途別判定・分類テスト (IMP-01 & IMP-04)', () => {
  it('Cookie名に基づいて正しいカテゴリに分類されること', () => {
    // 認証・セッション系
    expect(classifyCookie('PHPSESSID')).toBe('authentication');
    expect(classifyCookie('JSESSIONID')).toBe('authentication');
    expect(classifyCookie('session_id')).toBe('authentication');
    expect(classifyCookie('auth_token')).toBe('authentication');
    expect(classifyCookie('jwt')).toBe('authentication');

    // CSRF対策系
    expect(classifyCookie('XSRF-TOKEN')).toBe('csrf');
    expect(classifyCookie('csrf_token')).toBe('csrf');
    expect(classifyCookie('_csrf')).toBe('csrf');

    // トラッキング・解析系
    expect(classifyCookie('_ga')).toBe('analytics');
    expect(classifyCookie('_gid')).toBe('analytics');
    expect(classifyCookie('_hjSession')).toBe('analytics');

    // 広告・マーケティング系 (v1.7.1 T07)
    expect(classifyCookie('_fbp')).toBe('advertising');

    // UI・設定系
    expect(classifyCookie('theme_mode')).toBe('preferences');
    expect(classifyCookie('user_lang')).toBe('preferences');
    expect(classifyCookie('sidebar_view')).toBe('preferences');

    // 一般・未分類
    expect(classifyCookie('custom_data')).toBe('general');
  });

  // --- Rev.2.1 IMP-04: C11 & C12 SameSite正規化 ---
  it('C11: SameSite=no_restriction が none に正規化されること', () => {
    expect(normalizeSameSite('no_restriction')).toBe('none');
    expect(normalizeSameSite('lax')).toBe('lax');
    expect(normalizeSameSite('strict')).toBe('strict');
  });

  it('C12: SameSite=unspecified が unspecified として扱われること', () => {
    expect(normalizeSameSite('unspecified')).toBe('unspecified');
    expect(normalizeSameSite(undefined)).toBe('unknown');
  });

  // --- v1.7.0 T07 (SPEC-12 / D7): ブラウザが保存しないCookieを対象にしたチェックの削除確認 ---
  it('C13: __Host- CookieでDomain指定（hostOnly=false）がある場合も、ブラウザが保存しないプレフィックス違反チェックは行わないこと (D7)', () => {
    const cookie: any = {
      name: '__Host-id',
      domain: '.example.com',
      hostOnly: false,
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'lax',
    };
    const issue = evaluateCookie(cookie, true);
    expect(issue).toBeNull();
  });

  it('C14: __Host- CookieでPath=/以外の場合も、ブラウザが保存しないプレフィックス違反チェックは行わないこと (D7)', () => {
    const cookie: any = {
      name: '__Host-id',
      domain: 'example.com',
      hostOnly: true,
      path: '/app',
      secure: true,
      httpOnly: true,
      sameSite: 'lax',
    };
    const issue = evaluateCookie(cookie, true);
    expect(issue).toBeNull();
  });

  it('C15: __Secure- CookieでSecureなしの場合、HTTPS上のSecure属性欠落のみ検出しプレフィックス違反チェックは行わないこと (D7)', () => {
    const cookie: any = {
      name: '__Secure-id',
      domain: 'example.com',
      hostOnly: true,
      path: '/',
      secure: false,
      httpOnly: true,
      sameSite: 'lax',
    };
    const issue = evaluateCookie(cookie, true);
    expect(issue).not.toBeNull();
    expect(issue?.missingAttributes).toEqual(['Secure']);
  });

  // --- Rev.2.1 IMP-04 / v1.7.0 T07 (D7): C16 Partitioned Cookie (CHIPS) ---
  it('C16: Partitioned Cookie (CHIPS) の属性を識別して保持し、HTTP環境での到達不能なCHIPS/SameSite=None固有チェックは行わないこと (D7)', () => {
    const partitionedCookie: any = {
      name: 'part_cookie',
      domain: 'example.com',
      path: '/',
      partitionKey: 'https://top-site.example',
      partitioned: true,
      secure: true,
      httpOnly: true,
      sameSite: 'none',
    };

    const { inspectedCookies } = checkCookies([partitionedCookie], 'https://example.com', true);
    expect(inspectedCookies[0].partitioned).toBe(true);
    expect(inspectedCookies[0].partitionKey).toBe('https://top-site.example');

    // HTTP環境 (isHttps=false) で SameSite=None / Partitioned かつ Secure=false でもブラウザ非保存チェックは発火しない
    const unstoredCookie: any = {
      ...partitionedCookie,
      secure: false,
    };
    expect(evaluateCookie(unstoredCookie, false)).toBeNull();
  });

  // --- Rev.2.1 IMP-04: C18 あいまいな分類 (ambiguous) ---
  it('C18: Cookie用途があいまい（複数パターンや境界ケース）な場合、ambiguous=true となること', () => {
    const classification = classifyCookieAdvanced('auth_theme_csrf');
    expect(classification.ambiguous).toBe(true);
    expect(classification.matchedRules.length).toBeGreaterThan(1);
  });

  // --- Rev.2.1 IMP-04: C19 Cookie値の完全除外（機密情報非保持） ---
  it('C19: Cookie値（Value）を含む入力であっても、診断結果や説明文に値が含まれないこと', () => {
    const secretValue = 'SECRET_PASSWORD_OR_SESSION_DATA_XYZ123';
    const cookie: any = {
      name: 'PHPSESSID',
      value: secretValue,
      domain: 'example.com',
      hostOnly: true,
      path: '/',
      secure: false,
      httpOnly: false,
      sameSite: 'lax',
    };

    const issue = evaluateCookie(cookie, true);
    expect(issue).not.toBeNull();
    // 説明文や推奨文に秘密値が含まれていないこと
    expect(JSON.stringify(issue)).not.toContain(secretValue);

    const { checks, inspectedCookies } = checkCookies([cookie], 'https://example.com', true);
    expect(JSON.stringify(checks)).not.toContain(secretValue);
    expect(JSON.stringify(inspectedCookies)).not.toContain(secretValue);
  });

  // --- Rev.2.1 IMP-04: C20 同名CookieでPath違い ---
  it('C20: 同名CookieでPathが異なる場合、独立した識別子として評価されること', () => {
    const cookies: any[] = [
      {
        name: 'token',
        domain: 'example.com',
        hostOnly: true,
        path: '/api',
        secure: false,
        httpOnly: true,
        sameSite: 'lax',
      },
      {
        name: 'token',
        domain: 'example.com',
        hostOnly: true,
        path: '/web',
        secure: false,
        httpOnly: false,
        sameSite: 'lax',
      },
    ];

    const { inspectedCookies } = checkCookies(cookies, 'https://example.com', true);
    expect(inspectedCookies.length).toBe(2);
    expect(inspectedCookies[0].path).toBe('/api');
    expect(inspectedCookies[1].path).toBe('/web');
  });

  it('認証系CookieでHttpOnly/Secureが欠落している場合、Highリスクと判定されること', () => {
    const authCookie: chrome.cookies.Cookie = {
      name: 'PHPSESSID',
      value: 'abc123xyz',
      domain: 'example.com',
      hostOnly: true,
      path: '/',
      secure: false,
      httpOnly: false,
      sameSite: 'lax',
      session: true,
      storeId: '0',
    };

    const issue = evaluateCookie(authCookie);
    expect(issue).not.toBeNull();
    expect(issue?.category).toBe('authentication');
    expect(issue?.severity).toBe('high');
    expect(issue?.missingAttributes).toContain('Secure');
    expect(issue?.missingAttributes).toContain('HttpOnly');
  });

  it('CSRFトークンでHttpOnlyが欠落していても、意図的な設定としてInfoまたは低リスクに抑えられること', () => {
    const csrfCookie: chrome.cookies.Cookie = {
      name: 'XSRF-TOKEN',
      value: 'token_val_123',
      domain: 'example.com',
      hostOnly: true,
      path: '/',
      secure: true,
      httpOnly: false,
      sameSite: 'lax',
      session: true,
      storeId: '0',
    };

    const issue = evaluateCookie(csrfCookie);
    if (issue) {
      expect(issue.category).toBe('csrf');
      expect(['low', 'info']).toContain(issue.severity);
      expect(issue.missingAttributes).not.toContain('HttpOnly');
    } else {
      expect(issue).toBeNull();
    }
  });

  it('checkCookies関数がサマリーと適切なチェック結果を返却すること', () => {
    const mockCookies: chrome.cookies.Cookie[] = [
      {
        name: 'auth_jwt',
        value: 'xxx',
        domain: 'example.com',
        hostOnly: true,
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'strict',
        session: false,
        storeId: '0',
      },
      {
        name: 'theme',
        value: 'dark',
        domain: 'example.com',
        hostOnly: true,
        path: '/',
        secure: true,
        httpOnly: false,
        sameSite: 'lax',
        session: false,
        storeId: '0',
      },
    ];

    const { checks } = checkCookies(mockCookies as any, 'https://example.com', true);
    const highWarnings = checks.filter((r) => r.severity === 'high');
    expect(highWarnings.length).toBe(0);
  });

  describe('v1.7.1 T07: Cookieの用途分類の拡張・優先順位・一般Cookieの独立チェック・HTTP観測値の書き分け', () => {
    it.each<[string, CookieCategory]>([
      // 計測 (analytics)
      ['ai_session', 'analytics'],
      ['ai_user', 'analytics'],
      ['__utma', 'analytics'],
      ['__utmb', 'analytics'],
      ['__utmc', 'analytics'],
      ['__utmt', 'analytics'],
      ['__utmz', 'analytics'],
      ['_mkto_trk', 'analytics'],
      ['kndctr_*', 'analytics'],
      ['kndctr_12345_AdobeOrg_identity', 'analytics'],
      // 広告 (advertising)
      ['_gcl_*', 'advertising'],
      ['_gcl_au', 'advertising'],
      ['_gcl_aw', 'advertising'],
      ['_fbp', 'advertising'],
      ['_twpid', 'advertising'],
      ['_twsid', 'advertising'],
      // 同意管理 (consent)
      ['OptanonConsent', 'consent'],
      ['OptanonAlertBoxClosed', 'consent'],
      ['zaraz-consent', 'consent'],
      ['CookieConsent', 'consent'],
      // CSRF (csrf)
      ['__RequestVerificationToken', 'csrf'],
      ['__RequestVerificationToken_Lw__', 'csrf'],
      ['anti_forgery*', 'csrf'],
      ['anti_forgery_token', 'csrf'],
      ['antiforgery*', 'csrf'],
      ['antiforgery_token', 'csrf'],
      ['.AspNetCore.Antiforgery.cdV5u', 'csrf'],
      ['mw-wp-form-token', 'csrf'],
      ['email_verification_token', 'csrf'],
      ['forgery_protection_token', 'csrf'],
      // 認証 (authentication)
      ['PHPSESSID', 'authentication'],
      ['JSESSIONID', 'authentication'],
      ['ASP.NET_SessionId', 'authentication'],
      ['ASPSESSIONID*', 'authentication'],
      ['ASPSESSIONIDQCSRDTQA', 'authentication'],
      ['_gh_sess', 'authentication'],
    ])('Cookie名 "%s" が用途 "%s" に分類されること（テーブル駆動テスト）', (cookieName, expectedCategory) => {
      const classification = classifyCookieAdvanced(cookieName);
      expect(classification.category).toBe(expectedCategory);
      expect(classifyCookie(cookieName)).toBe(expectedCategory);
      // 対応表や専用パターンにあるため、不要に ambiguous=true にならないこと
      expect(classification.ambiguous).toBe(false);
    });

    it('ai_session が認証用にならず、__RequestVerificationToken が CSRF になり、Secure なしの場合は MEDIUM (SEC-COOKIE-SECURE-CSRF) になること', () => {
      expect(classifyCookie('ai_session')).toBe('analytics');
      expect(classifyCookie('__RequestVerificationToken')).toBe('csrf');

      const { checks, inspectedCookies } = checkCookies(
        [
          {
            name: 'ai_session',
            domain: 'portal.example.test',
            path: '/',
            secure: false,
            httpOnly: false,
            sameSite: 'lax',
            session: true,
          },
          {
            name: '__RequestVerificationToken',
            domain: 'portal.example.test',
            path: '/',
            secure: false,
            httpOnly: false,
            sameSite: 'lax',
            session: true,
          },
        ],
        'https://portal.example.test/',
        true
      );

      // ai_session は analytics であり認証系の FAIL (SEC-COOKIE-HTTPONLY / SEC-COOKIE-SECURE) は出ない
      expect(checks.find((c) => c.checkId === 'SEC-COOKIE-HTTPONLY')).toBeUndefined();
      expect(checks.find((c) => c.checkId === 'SEC-COOKIE-SECURE')).toBeUndefined();

      // __RequestVerificationToken の Secure 欠落は SEC-COOKIE-SECURE-CSRF (warning / medium) になる
      const csrfCheck = checks.find((c) => c.checkId === 'SEC-COOKIE-SECURE-CSRF');
      expect(csrfCheck).toBeDefined();
      expect(csrfCheck?.status).toBe('warning');
      expect(csrfCheck?.severity).toBe('medium');
      expect(csrfCheck?.observed).toContain('__RequestVerificationToken');

      // ai_session の Secure 欠落は SEC-COOKIE-SECURE-GENERAL (warning / low) になる
      const generalCheck = checks.find((c) => c.checkId === 'SEC-COOKIE-SECURE-GENERAL');
      expect(generalCheck).toBeDefined();
      expect(generalCheck?.status).toBe('warning');
      expect(generalCheck?.severity).toBe('low');
      expect(generalCheck?.observed).toContain('ai_session');

      const aiCookie = inspectedCookies.find((c) => c.name === 'ai_session');
      const csrfCookie = inspectedCookies.find((c) => c.name === '__RequestVerificationToken');
      expect(aiCookie?.category).toBe('analytics');
      expect(csrfCookie?.category).toBe('csrf');
    });

    it('認証系の FAIL と、Secure のない _ga が同時にある場合に、両方の指摘が独立に出ること', () => {
      const { checks } = checkCookies(
        [
          {
            name: 'PHPSESSID',
            domain: 'app.example.test',
            path: '/',
            secure: false,
            httpOnly: false,
            sameSite: 'lax',
            session: true,
          },
          {
            name: '_ga',
            domain: '.example.test',
            path: '/',
            secure: false,
            httpOnly: false,
            sameSite: 'lax',
            session: false,
          },
        ],
        'https://app.example.test/',
        true
      );

      const authHttpOnly = checks.find((c) => c.checkId === 'SEC-COOKIE-HTTPONLY');
      const authSecure = checks.find((c) => c.checkId === 'SEC-COOKIE-SECURE');
      const generalSecure = checks.find((c) => c.checkId === 'SEC-COOKIE-SECURE-GENERAL');

      expect(authHttpOnly).toBeDefined();
      expect(authHttpOnly?.status).toBe('fail');
      expect(authSecure).toBeDefined();
      expect(authSecure?.status).toBe('fail');

      // 認証系の指摘があっても SEC-COOKIE-SECURE-GENERAL が独立に出る
      expect(generalSecure).toBeDefined();
      expect(generalSecure?.status).toBe('warning');
      expect(generalSecure?.severity).toBe('low');
      expect(generalSecure?.observed).toBe('1 件の非認証系CookieでSecure属性が未設定 (_ga)');
    });

    it('SEC-COOKIE-SECURE-GENERAL の対象に advertising と consent が含まれ、観測値に対象の Cookie 名が 3 件まで表示されること', () => {
      const { checks } = checkCookies(
        [
          { name: '_ga', domain: 'shop.example.test', path: '/', secure: false, httpOnly: false, sameSite: 'lax' },
          { name: '_fbp', domain: 'shop.example.test', path: '/', secure: false, httpOnly: false, sameSite: 'lax' },
          { name: 'OptanonConsent', domain: 'shop.example.test', path: '/', secure: false, httpOnly: false, sameSite: 'lax' },
          { name: 'CookieConsent', domain: 'shop.example.test', path: '/', secure: false, httpOnly: false, sameSite: 'lax' },
        ],
        'https://shop.example.test/',
        true
      );

      const generalSecure = checks.find((c) => c.checkId === 'SEC-COOKIE-SECURE-GENERAL');
      expect(generalSecure).toBeDefined();
      expect(generalSecure?.observed).toBe(
        '4 件の非認証系CookieでSecure属性が未設定 (_ga, _fbp, OptanonConsent 他 1 件)'
      );
      expect(generalSecure?.observed).not.toContain('CookieConsent');
    });

    it('HTTP のページでは Cookie の PASS (SEC-COOKIE-00) の観測値が「HTTP のため Secure は評価対象外」と書き分けられること', () => {
      const httpCookie = [
        {
          name: 'ASP.NET_SessionId',
          domain: 'legacy.example.test',
          path: '/',
          secure: false,
          httpOnly: true,
          sameSite: 'lax',
          session: true,
        },
      ];

      // HTTP ページ (isHttps = false)
      const httpRes = checkCookies(httpCookie, 'http://legacy.example.test/', false);
      const httpPass = httpRes.checks.find((c) => c.checkId === 'SEC-COOKIE-00');
      expect(httpPass).toBeDefined();
      expect(httpPass?.status).toBe('pass');
      expect(httpPass?.observed).toBe('1 件のCookieを検査（HTTP のため Secure は評価対象外）');

      // HTTPS ページ (isHttps = true, secure = true)
      const httpsCookie = [{ ...httpCookie[0], secure: true }];
      const httpsRes = checkCookies(httpsCookie, 'https://legacy.example.test/', true);
      const httpsPass = httpsRes.checks.find((c) => c.checkId === 'SEC-COOKIE-00');
      expect(httpsPass).toBeDefined();
      expect(httpsPass?.status).toBe('pass');
      expect(httpsPass?.observed).toBe('1 件のCookieを検査（全属性が適切）');
    });

    it('advertising と consent の表示名、エクスポート、および未知の用途の general への正規化が機能すること', () => {
      expect(formatCookieCategory('advertising')).toBe('広告・マーケティング');
      expect(formatCookieCategory('consent')).toBe('同意管理');
      expect(formatCookieCategory('unknown_future_category')).toBe('一般・未分類');
      expect(normalizeCookieCategory('advertising')).toBe('advertising');
      expect(normalizeCookieCategory('consent')).toBe('consent');
      expect(normalizeCookieCategory('unknown_future_category')).toBe('general');
      expect(normalizeCookieCategory(undefined)).toBe('general');

      const report: InspectionReport = {
        id: 'rep_cookie_export_t07',
        url: 'https://export.example.test/',
        hostname: 'export.example.test',
        inspectedAt: '2026-11-01T00:00:00.000Z',
        extensionVersion: '1.7.0',
        rulesVersion: '1.7.0',
        summary: {
          totalTechnologies: 0,
          requiresAttentionCount: 0,
          securityFindings: { critical: 0, high: 0, medium: 0, low: 0, info: 1, unknown: 0 },
          librarySecurity: { eolCount: 0, vulnerableLibraryCount: 0, mismatchCount: 0 },
          isHttps: true,
          mixedContentCount: 0,
        },
        technologies: [],
        securityChecks: [],
        cookies: [
          {
            name: '_fbp',
            domain: '.example.test',
            path: '/',
            secure: true,
            httpOnly: false,
            sameSite: 'lax',
            session: false,
            partitioned: false,
            category: 'advertising',
            issues: [],
          },
          {
            name: 'OptanonConsent',
            domain: '.example.test',
            path: '/',
            secure: true,
            httpOnly: false,
            sameSite: 'lax',
            session: false,
            partitioned: false,
            category: 'consent',
            issues: [],
          },
          {
            name: 'legacy_custom',
            domain: 'export.example.test',
            path: '/',
            secure: true,
            httpOnly: true,
            sameSite: 'lax',
            session: true,
            partitioned: false,
            category: 'legacy_unknown_type' as unknown as CookieCategory,
            issues: [],
          },
        ],
        mixedContent: [],
      };

      // 履歴読み込み・URLサニタイズ時に未知の用途が general に正規化されること
      const sanitized = sanitizeReportUrls(report);
      expect(sanitized.cookies[0].category).toBe('advertising');
      expect(sanitized.cookies[1].category).toBe('consent');
      expect(sanitized.cookies[2].category).toBe('general');

      // Markdown エクスポート
      const md = generateMarkdownReport(report);
      expect(md).toContain('| `_fbp` | `.example.test` | `/` | advertising |');
      expect(md).toContain('| `OptanonConsent` | `.example.test` | `/` | consent |');
      expect(md).toContain('| `legacy_custom` | `export.example.test` | `/` | general |');

      // CSV エクスポート
      const csv = exportReportToCsv(report);
      expect(csv).toContain('"広告・マーケティング (advertising)"');
      expect(csv).toContain('"同意管理 (consent)"');
      expect(csv).toContain('"一般・未分類 (general)"');

      // JSON エクスポート
      const json = JSON.parse(exportReportToJson(report)) as InspectionReport;
      expect(json.cookies[0].category).toBe('advertising');
      expect(json.cookies[1].category).toBe('consent');
      expect(json.cookies[2].category).toBe('general');
    });
  });
});
