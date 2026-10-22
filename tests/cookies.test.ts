/**
 * Web Technology & Security Inspector
 * Cookie属性・用途別判定単体テスト (tests/cookies.test.ts) - IMP-01 & IMP-04 (Rev.2.1)
 */

import { describe, expect, it } from 'vitest';
import {
  checkCookies,
  classifyCookie,
  classifyCookieAdvanced,
  evaluateCookie,
  normalizeSameSite,
} from '../src/security/cookies';
import { InspectedCookieInfo } from '../src/shared/types';

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
    expect(classifyCookie('_fbp')).toBe('analytics');
    expect(classifyCookie('_hjSession')).toBe('analytics');

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

  // --- Rev.2.1 IMP-04: C13, C14, C15 Cookieプレフィックス ---
  it('C13: __Host- CookieでDomain指定（hostOnly=false）がある場合、不備と判定されること', () => {
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
    expect(issue).not.toBeNull();
    expect(issue?.missingAttributes).toContain('Prefix');
  });

  it('C14: __Host- CookieでPath=/以外の場合、不備と判定されること', () => {
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
    expect(issue).not.toBeNull();
    expect(issue?.missingAttributes).toContain('Prefix');
  });

  it('C15: __Secure- CookieでSecureなしの場合、不備と判定されること', () => {
    const cookie: any = {
      name: '__Secure-id',
      domain: 'example.com',
      hostOnly: true,
      path: '/',
      secure: false, // 不備
      httpOnly: true,
      sameSite: 'lax',
    };
    const issue = evaluateCookie(cookie, true);
    expect(issue).not.toBeNull();
    expect(issue?.missingAttributes).toContain('Prefix');
    expect(issue?.missingAttributes).toContain('Secure');
  });

  // --- Rev.2.1 IMP-04: C16 Partitioned Cookie (CHIPS) ---
  it('C16: Partitioned Cookieを識別し、Secure属性がない場合に不備として検出すること', () => {
    const partitionedCookie: any = {
      name: 'part_cookie',
      domain: 'example.com',
      path: '/',
      partitionKey: 'https://top-site.example',
      partitioned: true,
      secure: false, // CHIPS仕様違反 (Partitioned CookieはSecure必須)
      httpOnly: false,
      sameSite: 'none',
    };

    const issue = evaluateCookie(partitionedCookie, true);
    expect(issue).not.toBeNull();
    expect(issue?.missingAttributes).toContain('Secure');
    expect(issue?.description).toContain('Partitioned');
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
    const highWarnings = checks.filter((r) => r.severity === 'high' || r.severity === 'critical');
    expect(highWarnings.length).toBe(0);
  });
});
