/**
 * Web Technology & Security Inspector
 * v1.8.2 T05（D-1）: secure context の判定と COOP・COEP の「対象外」の切り替え（H7）の受け入れテスト
 * (tests/secure-context.test.ts)
 *
 * 設計メモ: docs/dev/v1.8.2/design/T05.md
 *
 * - isSecureContextUrl(url) は指示書 §4.3 の表どおり（偽の行はすべて陰性テスト）
 * - localhost・127.0.0.0/8・[::1] の HTTP のページでは COOP・COEP を通常どおり判定する
 * - LAN の IP・.local・一般の HTTP のページでは従来どおり「対象外」（not-applicable）
 * - HTTPS は従来どおり
 * - HSTS・Cookie の Secure・混在コンテンツ・CORP は HTTPS かどうかで見るまま（localhost でも変わらない）
 */

import { describe, expect, it, vi } from 'vitest';
import { executeInspection, InspectionDependencies } from '../src/background/service-worker';
import { SecurityEngine } from '../src/security/engine';
import { checkHttpHeaders } from '../src/security/headers';
import { isSecureContextUrl } from '../src/shared/secure-context';
import type { DomSignals, InspectedCookieInfo, InspectionReport, MixedContentItem, SecurityCheckResult } from '../src/shared/types';

const NA = 'not-applicable';

// ---------------------------------------------------------------------------
// 1. isSecureContextUrl（§4.3 の表）
// ---------------------------------------------------------------------------

describe('T05: isSecureContextUrl — §4.3 の表の真の行', () => {
  it.each([
    'https://example.com/',
    'wss://example.com/',
    'http://localhost:3000/',
    'http://app.localhost/',
    'http://127.0.0.1/',
    'http://127.1.2.3/',
    'http://[::1]:8080/',
    'file:///tmp/a.html',
  ])('真: %s', (url) => {
    expect(isSecureContextUrl(url)).toBe(true);
  });

  it.each([
    // 表の行の変形（同じ規則の範囲）
    'https://secure.example.test:8443/path?q=1#f',
    'wss://ws.example.test/socket',
    'http://localhost/',
    'http://LOCALHOST:3000/',
    'http://a.b.localhost:5173/',
    'http://127.255.255.254/',
    'http://[0:0:0:0:0:0:0:1]/',
  ])('真（表の行の変形）: %s', (url) => {
    expect(isSecureContextUrl(url)).toBe(true);
  });
});

describe('T05: isSecureContextUrl — §4.3 の表の偽の行（陰性）', () => {
  it.each([
    'http://192.168.10.1/',
    'http://10.0.0.1/',
    'http://example.local/',
    'http://example.com/',
    'http://127.0.0.1.example.com/',
    'http://localhost.example.com/',
  ])('偽: %s', (url) => {
    expect(isSecureContextUrl(url)).toBe(false);
  });

  it.each(['', 'not a url', 'http://', '://localhost', 'localhost:3000'])('偽（不正な URL）: %j', (url) => {
    expect(isSecureContextUrl(url)).toBe(false);
  });

  it('偽（文字列でない入力）: 例外を投げず false', () => {
    for (const v of [undefined, null, 42, {}, []] as unknown[]) {
      expect(isSecureContextUrl(v as string)).toBe(false);
    }
  });

  it.each([
    // 表の偽の行の変形（isIpOrLocalHost が真にする範囲を流用していないこと）
    'http://192.168.10.1:3000/https-only-headers',
    'http://172.16.0.1/',
    'http://128.0.0.1/',
    'http://126.255.255.255/',
    'http://[::2]/',
    'http://[fe80::1]/',
    'http://printer.local:631/',
    'http://localhostx/',
    'http://mylocalhost/',
    'http://localhost.example.test/',
    'http://app.localhost.example.test/',
    'ws://example.test/',
    'ftp://localhost.example.test/',
  ])('偽（変形）: %s', (url) => {
    expect(isSecureContextUrl(url)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 2. COOP・COEP の判定（SecurityEngine と checkHttpHeaders）
// ---------------------------------------------------------------------------

const BASE_HEADERS: Record<string, string[]> = {
  'content-security-policy': ["default-src 'self'; frame-ancestors 'none'"],
  'x-frame-options': ['DENY'],
  'x-content-type-options': ['nosniff'],
  'referrer-policy': ['strict-origin-when-cross-origin'],
  'permissions-policy': ['geolocation=(), camera=(), microphone=()'],
};
const withBase = (extra: Record<string, string[]>): Record<string, string[]> => ({ ...BASE_HEADERS, ...extra });

/** test-server の /https-only-headers と同じ値（仕様で有効な値） */
const VALID_COOP_COEP = withBase({
  'cross-origin-opener-policy': ['same-origin'],
  'cross-origin-embedder-policy': ['require-corp'],
});
/** 仕様外の値（secure context なら info が出る） */
const INVALID_COOP_COEP = withBase({
  'cross-origin-opener-policy': ['same-site'],
  'cross-origin-embedder-policy': ['require_corp'],
});

const SECURE_HTTP_URLS = [
  'http://localhost:3000/https-only-headers',
  'http://app.localhost:3000/',
  'http://127.0.0.1:3000/',
  'http://127.1.2.3/',
  'http://[::1]:8080/',
];
const NON_SECURE_HTTP_URLS = [
  'http://192.168.10.1:3000/https-only-headers',
  'http://10.0.0.1/',
  'http://example.local/',
  'http://https-only.example.test/',
  'http://127.0.0.1.example.com/',
  'http://localhost.example.com/',
];

function emptyDom(url: string, mixedContent: MixedContentItem[] = []): DomSignals {
  return {
    url,
    title: 'secure context test',
    metaTags: [],
    scriptUrls: [],
    linkUrls: [],
    domMarkers: [],
    htmlSnippets: [],
    mixedContent,
    cookiesFromDocument: [],
    cssAssets: [],
  } as unknown as DomSignals;
}

function evaluate(
  url: string,
  headers: Record<string, string[]>,
  cookies: InspectedCookieInfo[] = [],
  mixedContent: MixedContentItem[] = []
): SecurityCheckResult[] {
  return new SecurityEngine().evaluate({
    url,
    dom: emptyDom(url, mixedContent),
    network: { url, responseHeaders: headers, cookies },
  }).checks;
}

const byPrefix = (checks: readonly SecurityCheckResult[], prefix: string): SecurityCheckResult[] =>
  checks.filter((c) => c.checkId.startsWith(prefix));
const isCoopCoep = (id: string): boolean => id.startsWith('SEC-COOP-') || id.startsWith('SEC-COEP-');

describe('T05: localhost などの secure context の HTTP のページでは COOP・COEP を通常どおり判定する', () => {
  it.each(SECURE_HTTP_URLS)('%s: COOP が無ければ SEC-COOP-01 は info（HTTPS と同じ）で、対象外ではない', (url) => {
    const coop = byPrefix(evaluate(url, BASE_HEADERS), 'SEC-COOP-');
    expect(coop.map((c) => c.status)).toEqual(['info']);
    expect(coop[0].severity).toBe('info');
  });

  it.each(SECURE_HTTP_URLS)('%s: 有効な COOP・COEP なら SEC-COOP-・SEC-COEP- の項目を作らない（HTTPS と同じ）', (url) => {
    const checks = evaluate(url, VALID_COOP_COEP);
    expect(checks.filter((c) => isCoopCoep(c.checkId))).toEqual([]);
    expect(checks.some((c) => c.status === NA)).toBe(false);
  });

  it.each(SECURE_HTTP_URLS)('%s: 仕様外の COOP・COEP は info（値の誤りを指摘する）', (url) => {
    const checks = evaluate(url, INVALID_COOP_COEP);
    expect(byPrefix(checks, 'SEC-COOP-').map((c) => c.status)).toEqual(['info']);
    expect(byPrefix(checks, 'SEC-COEP-').map((c) => c.status)).toEqual(['info']);
  });

  it('localhost の結果（COOP・COEP の項目）は、同じヘッダーの HTTPS のページの結果と同じ', () => {
    for (const headers of [BASE_HEADERS, VALID_COOP_COEP, INVALID_COOP_COEP]) {
      const pick = (checks: SecurityCheckResult[]) =>
        checks.filter((c) => isCoopCoep(c.checkId)).map((c) => ({ id: c.checkId, status: c.status, severity: c.severity, observed: c.observed }));
      expect(pick(evaluate('http://localhost:3000/', headers))).toEqual(pick(evaluate('https://localhost:3000/', headers)));
    }
  });
});

describe('T05: secure context でない HTTP のページでは従来どおり「対象外」（陰性）', () => {
  it.each(NON_SECURE_HTTP_URLS)('%s: COOP・COEP を返すと両方とも対象外', (url) => {
    const checks = evaluate(url, VALID_COOP_COEP);
    expect(byPrefix(checks, 'SEC-COOP-').map((c) => c.status)).toEqual([NA]);
    expect(byPrefix(checks, 'SEC-COEP-').map((c) => c.status)).toEqual([NA]);
  });

  it.each(NON_SECURE_HTTP_URLS)('%s: COOP が無くても SEC-COOP-01 は対象外（info にしない）', (url) => {
    expect(byPrefix(evaluate(url, BASE_HEADERS), 'SEC-COOP-').map((c) => c.status)).toEqual([NA]);
  });

  it('対象外の説明文は「安全なコンテキスト（HTTPS・localhost）でないページ」の趣旨', () => {
    const checks = evaluate('http://192.168.10.1:3000/https-only-headers', VALID_COOP_COEP);
    for (const c of checks.filter((x) => x.status === NA)) {
      expect(isCoopCoep(c.checkId), c.checkId).toBe(true);
      expect(c.description).toContain('安全なコンテキスト');
      expect(c.description).toContain('localhost');
      expect(c.description).toContain('HTTPS');
    }
    expect(checks.filter((x) => x.status === NA).length).toBe(2);
  });
});

describe('T05: HTTPS のページは従来どおり', () => {
  it('COOP が無ければ info、有効な値なら項目なし、対象外は出ない', () => {
    const url = 'https://https-only.example.test/';
    expect(byPrefix(evaluate(url, BASE_HEADERS), 'SEC-COOP-').map((c) => c.status)).toEqual(['info']);
    const valid = evaluate(url, VALID_COOP_COEP);
    expect(valid.filter((c) => isCoopCoep(c.checkId))).toEqual([]);
    for (const headers of [BASE_HEADERS, VALID_COOP_COEP, INVALID_COOP_COEP]) {
      expect(evaluate(url, headers).some((c) => c.status === NA)).toBe(false);
    }
  });
});

describe('T05: checkHttpHeaders の isSecureContext オプション', () => {
  it('isHttps が false でも isSecureContext: true なら COOP・COEP は通常の判定', () => {
    const url = 'http://localhost:3000/';
    const checks = checkHttpHeaders(INVALID_COOP_COEP, url, false, { isSecureContext: true });
    expect(byPrefix(checks, 'SEC-COOP-').map((c) => c.status)).toEqual(['info']);
    expect(byPrefix(checks, 'SEC-COEP-').map((c) => c.status)).toEqual(['info']);
    expect(checks.some((c) => c.status === NA)).toBe(false);
  });

  it('isSecureContext: false なら対象外', () => {
    const url = 'http://192.168.10.1/';
    const checks = checkHttpHeaders(VALID_COOP_COEP, url, false, { isSecureContext: false });
    expect(byPrefix(checks, 'SEC-COOP-').map((c) => c.status)).toEqual([NA]);
    expect(byPrefix(checks, 'SEC-COEP-').map((c) => c.status)).toEqual([NA]);
  });

  it('互換: オプションを省くと isHttps に従う（既存の呼び出しが変わらない）', () => {
    const http = checkHttpHeaders(VALID_COOP_COEP, 'http://https-only.example.test/', false);
    expect(byPrefix(http, 'SEC-COOP-').map((c) => c.status)).toEqual([NA]);
    const https = checkHttpHeaders(BASE_HEADERS, 'https://https-only.example.test/', true);
    expect(byPrefix(https, 'SEC-COOP-').map((c) => c.status)).toEqual(['info']);
    // metaCsp だけを渡す既存の形も同じ
    const meta = checkHttpHeaders(VALID_COOP_COEP, 'http://https-only.example.test/', false, { metaCsp: [] });
    expect(byPrefix(meta, 'SEC-COOP-').map((c) => c.status)).toEqual([NA]);
  });

  it('isSecureContext: true でも HSTS・CORP は isHttps に従う（切り替えるのは COOP・COEP だけ）', () => {
    const headers = withBase({
      'strict-transport-security': ['max-age=31536000; includeSubDomains'],
      'cross-origin-resource-policy': ['same_origin'],
    });
    const url = 'http://localhost:3000/';
    const a = checkHttpHeaders(headers, url, false, { isSecureContext: true });
    const b = checkHttpHeaders(headers, url, false, { isSecureContext: false });
    const pick = (checks: SecurityCheckResult[]) =>
      checks.filter((c) => !isCoopCoep(c.checkId)).map((c) => `${c.checkId}:${c.status}:${c.severity}`).sort();
    expect(pick(a)).toEqual(pick(b));
    // HTTP のページでは HSTS の項目を作らない（従来どおり）
    expect(byPrefix(a, 'SEC-HSTS-')).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 3. HSTS・Cookie の Secure・混在コンテンツの判定は変わらない（陰性）
// ---------------------------------------------------------------------------

describe('T05: HSTS・Cookie の Secure・混在コンテンツは HTTPS かどうかで見るまま（localhost でも変わらない）', () => {
  const insecureCookie = (domain: string): InspectedCookieInfo[] => [
    { name: 'sessionid', value: 'x', domain, path: '/', secure: false, httpOnly: false, sameSite: 'unspecified', hostOnly: true, session: true },
    { name: '_ga', value: 'GA1.1.1.1', domain, path: '/', secure: false, httpOnly: false, sameSite: 'unspecified', hostOnly: true, session: false },
  ];
  const mixed: MixedContentItem[] = [
    { resourceType: 'script', url: 'http://cdn.example.test/a.js' } as MixedContentItem,
    { resourceType: 'image', url: 'http://img.example.test/b.png' } as MixedContentItem,
  ];
  const headers = withBase({
    'strict-transport-security': ['max-age=31536000; includeSubDomains'],
    'cross-origin-resource-policy': ['same_origin'],
    'cross-origin-opener-policy': ['same-origin'],
    'cross-origin-embedder-policy': ['require-corp'],
  });

  const run = (url: string): SecurityCheckResult[] => evaluate(url, headers, insecureCookie(new URL(url).hostname), mixed);
  const pickNonCoopCoep = (checks: SecurityCheckResult[]) =>
    checks.filter((c) => !isCoopCoep(c.checkId)).map((c) => `${c.checkId}:${c.status}:${c.severity}`).sort();

  it('localhost と LAN の IP で、COOP・COEP 以外の項目（checkId・status・重大度）が同じ', () => {
    const local = run('http://localhost:3000/');
    for (const other of ['http://192.168.10.1:3000/', 'http://https-only.example.test/', 'http://127.0.0.1:3000/', 'http://[::1]:3000/']) {
      expect(pickNonCoopCoep(run(other)), other).toEqual(pickNonCoopCoep(local));
    }
  });

  it('localhost の HTTP のページ: HTTPS の項目は従来どおり fail、HSTS の項目は作らない', () => {
    const checks = run('http://localhost:3000/');
    expect(byPrefix(checks, 'SEC-HTTPS-01').map((c) => c.status)).toEqual(['fail']);
    expect(byPrefix(checks, 'SEC-HTTPS-00')).toEqual([]);
    expect(byPrefix(checks, 'SEC-HSTS-')).toEqual([]);
  });

  it('localhost の HTTP のページ: Cookie の Secure 未設定の指摘を出さない（HTTP のページと同じ）', () => {
    const checks = run('http://localhost:3000/');
    expect(byPrefix(checks, 'SEC-COOKIE-SECURE')).toEqual([]);
  });

  it('対照: HTTPS のページでは Cookie の Secure 未設定と HSTS の項目が出る（判定そのものは生きている）', () => {
    const checks = run('https://https-only.example.test/');
    expect(byPrefix(checks, 'SEC-COOKIE-SECURE').length).toBeGreaterThan(0);
    expect(byPrefix(checks, 'SEC-HSTS-').length).toBeGreaterThan(0);
    expect(byPrefix(checks, 'SEC-HTTPS-01')).toEqual([]);
  });

  it('localhost の HTTP のページ: 混在コンテンツの指摘を出さない（HTTP のページと同じ）', () => {
    for (const url of ['http://localhost:3000/', 'http://127.0.0.1:3000/', 'http://192.168.10.1:3000/']) {
      expect(byPrefix(run(url), 'SEC-MIXED-'), url).toEqual([]);
    }
    // 対照: HTTPS のページでは同じ入力で混在コンテンツの指摘が出る
    expect(byPrefix(run('https://https-only.example.test/'), 'SEC-MIXED-').length).toBeGreaterThan(0);
  });

  it('CORP の仕様外の値は localhost でも LAN でも info（secure context で切り替えない）', () => {
    for (const url of ['http://localhost:3000/', 'http://192.168.10.1:3000/']) {
      expect(byPrefix(run(url), 'SEC-CORP-').map((c) => c.status), url).toEqual(['info']);
    }
  });
});

// ---------------------------------------------------------------------------
// 4. 調査全体（executeInspection）: 目視の URL と同じ形
// ---------------------------------------------------------------------------

function makeDeps(url: string, headers: Record<string, string[]>): InspectionDependencies {
  return {
    tab: { id: 805, url },
    fetchDomSignals: vi.fn().mockResolvedValue(emptyDom(url)),
    fetchRuntimeVersions: vi.fn().mockResolvedValue({ versions: {}, frameworkMarkers: [] }),
    getCachedHeaders: vi.fn().mockResolvedValue({ url, headers, observed: true }),
    getInspectedCookies: vi.fn().mockResolvedValue([]),
    getAllFindingExceptions: vi.fn().mockResolvedValue([]),
    saveReport: vi.fn().mockResolvedValue(undefined),
    updateBadge: vi.fn(),
    hasWebRequestPermission: true,
  };
}

async function inspect(url: string, headers: Record<string, string[]>): Promise<InspectionReport> {
  return executeInspection(makeDeps(url, headers));
}

describe('T05: 調査全体 — /https-only-headers を localhost と LAN の IP で調べる', () => {
  it('localhost: COOP・COEP が対象外にならない（有効な値なので項目なし）', async () => {
    const report = await inspect('http://localhost:3000/https-only-headers', VALID_COOP_COEP);
    expect(report.securityChecks.some((c) => c.status === NA)).toBe(false);
    expect(report.summary.securityFindings.notApplicable ?? 0).toBe(0);
  });

  it('localhost: 仕様外の値なら COOP・COEP が info で出る', async () => {
    const report = await inspect('http://localhost:3000/https-only-headers', INVALID_COOP_COEP);
    expect(byPrefix(report.securityChecks, 'SEC-COOP-').map((c) => c.status)).toEqual(['info']);
    expect(byPrefix(report.securityChecks, 'SEC-COEP-').map((c) => c.status)).toEqual(['info']);
  });

  it('LAN の IP: COOP・COEP が対象外（従来どおり）', async () => {
    const report = await inspect('http://192.168.10.1:3000/https-only-headers', VALID_COOP_COEP);
    expect(byPrefix(report.securityChecks, 'SEC-COOP-').map((c) => c.status)).toEqual([NA]);
    expect(byPrefix(report.securityChecks, 'SEC-COEP-').map((c) => c.status)).toEqual([NA]);
    expect(report.summary.securityFindings.notApplicable).toBe(2);
  });
});
