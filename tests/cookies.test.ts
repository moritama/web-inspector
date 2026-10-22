/**
 * Web Technology & Security Inspector
 * Cookie属性・用途別判定単体テスト (tests/cookies.test.ts)
 */

import { describe, expect, it } from 'vitest';
import { checkCookies, classifyCookie, evaluateCookie } from '../src/security/cookies';

describe('Cookie用途別判定・分類テスト (IMP-01)', () => {
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

  it('認証系CookieでHttpOnly/Secureが欠落している場合、Highリスクと判定されること', () => {
    const authCookie: chrome.cookies.Cookie = {
      name: 'PHPSESSID',
      value: 'abc123xyz',
      domain: 'example.com',
      hostOnly: true,
      path: '/',
      secure: false, // 欠落
      httpOnly: false, // 欠落
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
      secure: true, // Secureは設定済み
      httpOnly: false, // フロントエンドJSがヘッダー付与するために意図的にfalse
      sameSite: 'lax',
      session: true,
      storeId: '0',
    };

    const issue = evaluateCookie(csrfCookie);
    // CSRFトークンはSecureとSameSiteがあればHttpOnly欠落による警告は発生しないか、Infoレベル
    if (issue) {
      expect(issue.category).toBe('csrf');
      expect(['low', 'info']).toContain(issue.severity);
      expect(issue.missingAttributes).not.toContain('HttpOnly');
    } else {
      expect(issue).toBeNull();
    }
  });

  it('__Host- プレフィックスの各条件不備（Path, Secure, hostOnly）が正確に検出されること', () => {
    const brokenHostCookie: chrome.cookies.Cookie = {
      name: '__Host-session',
      value: 'secret',
      domain: '.example.com',
      hostOnly: false, // 不備 (trueでなければならない)
      path: '/app', // 不備 (/ でなければならない)
      secure: false, // 不備 (trueでなければならない)
      httpOnly: true,
      sameSite: 'lax',
      session: true,
      storeId: '0',
    };

    const issue = evaluateCookie(brokenHostCookie);
    expect(issue).not.toBeNull();
    expect(issue?.missingAttributes).toContain('Prefix');
    expect(issue?.missingAttributes).toContain('Secure');
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
        httpOnly: false, // UI設定なのでHttpOnly不要
        sameSite: 'lax',
        session: false,
        storeId: '0',
      },
    ];

    const { checks } = checkCookies(mockCookies as any, 'https://example.com', true);
    // 適切なCookie設定のためパスまたは低重大度
    const highWarnings = checks.filter((r) => r.severity === 'high' || r.severity === 'critical');
    expect(highWarnings.length).toBe(0);
  });
});
