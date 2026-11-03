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
});
