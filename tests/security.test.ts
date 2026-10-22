/**
 * Web Technology & Security Inspector
 * セキュリティ診断エンジンの単体テスト (tests/security.test.ts)
 */

import { describe, expect, it } from 'vitest';
import { checkCookies } from '../src/security/cookies';
import { checkHttpHeaders } from '../src/security/headers';
import { checkHttpsAndMixedContent } from '../src/security/https';
import { InspectedCookieInfo } from '../src/shared/types';

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

  it('危険なCORS設定 (ワイルドカード + Credentials) をHighとして検知すること', () => {
    const headers = {
      'access-control-allow-origin': ['*'],
      'access-control-allow-credentials': ['true'],
    };
    const checks = checkHttpHeaders(headers, 'https://example.com/', true);
    const cors = checks.find((c) => c.category === 'cors');
    expect(cors?.severity).toBe('high');
    expect(cors?.status).toBe('fail');
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
});
