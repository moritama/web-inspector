/**
 * Web Technology & Security Inspector
 * 安定ID・正規化処理 単体テスト (tests/identity.test.ts) - IMP-07
 */

import { describe, expect, it } from 'vitest';
import {
  buildCookieResourceKey,
  generateFindingId,
  normalizeCookieDomain,
  normalizeUrlForIdentity,
} from '../src/shared/identity';
import { FindingIdentity } from '../src/shared/types';

describe('安定ID・正規化処理テスト (IMP-07)', () => {
  it('I01: ホスト名の大文字小文字違いで同一の正規化・同一IDが生成されること', () => {
    const url1 = 'HTTPS://Example.COM/app/page';
    const url2 = 'https://example.com/app/page';

    const norm1 = normalizeUrlForIdentity(url1);
    const norm2 = normalizeUrlForIdentity(url2);
    expect(norm1).toBe(norm2);

    const id1 = generateFindingId({
      ruleId: 'SEC-HSTS-01',
      origin: norm1,
      resourceKey: 'hsts',
      targetKey: 'header',
    });
    const id2 = generateFindingId({
      ruleId: 'SEC-HSTS-01',
      origin: norm2,
      resourceKey: 'hsts',
      targetKey: 'header',
    });

    expect(id1).toBe(id2);
  });

  it('I02: HTTPSにおける:443の有無で同一の正規化・同一IDが生成されること', () => {
    const url1 = 'https://example.com:443/api';
    const url2 = 'https://example.com/api';

    expect(normalizeUrlForIdentity(url1)).toBe(normalizeUrlForIdentity(url2));

    const id1 = generateFindingId({
      ruleId: 'SEC-HTTPS-01',
      origin: normalizeUrlForIdentity(url1),
      resourceKey: 'url',
      targetKey: 'scheme',
    });
    const id2 = generateFindingId({
      ruleId: 'SEC-HTTPS-01',
      origin: normalizeUrlForIdentity(url2),
      resourceKey: 'url',
      targetKey: 'scheme',
    });

    expect(id1).toBe(id2);
  });

  it('I03: Cookie Domainの先頭ドットの有無が正規化されること', () => {
    expect(normalizeCookieDomain('.example.com')).toBe('example.com');
    expect(normalizeCookieDomain('example.com')).toBe('example.com');
    expect(normalizeCookieDomain('.sub.EXAMPLE.com')).toBe('sub.example.com');
  });

  it('I04: Host-onlyとDomain Cookieが別識別子・別IDとなること', () => {
    const resHost = buildCookieResourceKey('session', 'example.com', '/', true);
    const resDomain = buildCookieResourceKey('session', 'example.com', '/', false);

    expect(resHost).not.toBe(resDomain);

    const idHost = generateFindingId({
      ruleId: 'SEC-COOKIE-SECURE',
      origin: 'https://example.com',
      resourceKey: resHost,
      targetKey: 'Secure',
    });
    const idDomain = generateFindingId({
      ruleId: 'SEC-COOKIE-SECURE',
      origin: 'https://example.com',
      resourceKey: resDomain,
      targetKey: 'Secure',
    });

    expect(idHost).not.toBe(idDomain);
  });

  it('I05: Cookie Pathの大文字小文字違いが別識別子として区別されること', () => {
    const resUpper = buildCookieResourceKey('token', 'example.com', '/App', true);
    const resLower = buildCookieResourceKey('token', 'example.com', '/app', true);

    expect(resUpper).not.toBe(resLower);

    const idUpper = generateFindingId({
      ruleId: 'SEC-COOKIE-HTTPONLY',
      origin: 'https://example.com',
      resourceKey: resUpper,
      targetKey: 'HttpOnly',
    });
    const idLower = generateFindingId({
      ruleId: 'SEC-COOKIE-HTTPONLY',
      origin: 'https://example.com',
      resourceKey: resLower,
      targetKey: 'HttpOnly',
    });

    expect(idUpper).not.toBe(idLower);
  });

  it('I06: Cookie名の大文字小文字違いが別識別子として区別されること', () => {
    const res1 = buildCookieResourceKey('SessionId', 'example.com', '/', true);
    const res2 = buildCookieResourceKey('sessionid', 'example.com', '/', true);

    expect(res1).not.toBe(res2);
  });

  it('I07: 同一Findingであれば再調査時（異なる日時やCookie値に関わらず）に同一IDが生成されること', () => {
    const identity: FindingIdentity = {
      ruleId: 'SEC-CSP-UNSAFE-INLINE',
      origin: 'https://example.com',
      resourceKey: 'script-src',
      targetKey: "'unsafe-inline'",
    };

    const idFirst = generateFindingId(identity);
    const idSecond = generateFindingId(identity);

    expect(idFirst).toBe(idSecond);
    expect(idFirst.startsWith('find_')).toBe(true);
  });
});
