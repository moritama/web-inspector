// @vitest-environment happy-dom
/**
 * Web Technology & Security Inspector
 * v1.8.0 T08 (NEW-03c): SRI・認証ページの Cache-Control・Cookie の有効期限と SameSite の受け入れテスト
 * (tests/sri-cache-cookie.test.ts)
 *
 * 設計メモ: docs/dev/v1.8.0/design/T08.md
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ALLOWED_RESPONSE_HEADERS,
  executeInspection,
  filterAndSanitizeHeaders,
  HEADER_DEPENDENT_CHECK_PREFIXES,
} from '../src/background/service-worker';
import { extractDomSignals } from '../src/content/content-script';
import { generateMarkdownReport } from '../src/export/markdown';
import { checkCookies } from '../src/security/cookies';
import { SecurityEngine } from '../src/security/engine';
import { isRequiresAttention } from '../src/shared/security-status';
import { DomSignals, InspectedCookieInfo, InspectionReport, SecurityCheckResult } from '../src/shared/types';
import { getAllHistoryReports, saveReportToHistory } from '../src/storage/history';
// @ts-expect-error -- Node ESM スクリプト (.mjs) の直接インポート
import { lintReportPair as rawLintReportPair } from '../scripts/report-lint.mjs';

const lintReportPair = rawLintReportPair as (
  report: unknown,
  markdown: string,
  options?: { includePending?: boolean }
) => { ok: boolean; violations: unknown[] };

// ---------------------------------------------------------------------------
// 共通
// ---------------------------------------------------------------------------

/** 指示書 T08 の表（ID → status / 重大度） */
const NEW_CHECKS = [
  { id: 'SEC-SRI-01', status: 'warning', severity: 'low' },
  { id: 'SEC-SRI-02', status: 'info', severity: 'info' },
  { id: 'SEC-CACHE-01', status: 'warning', severity: 'low' },
  { id: 'SEC-COOKIE-EXPIRY', status: 'warning', severity: 'low' },
  { id: 'SEC-COOKIE-SAMESITE-NONE', status: 'warning', severity: 'low' },
] as const;
const NEW_IDS: readonly string[] = NEW_CHECKS.map((c) => c.id);

const PAGE = 'https://www.example.test/account/';

/** 設計メモ「実装の方針」の DomSignals.sriResources の要素（テストではローカルに型を置く） */
interface SriItem {
  kind: 'script' | 'stylesheet';
  url: string;
  hasIntegrity: boolean;
}

const DAY_SEC = 24 * 60 * 60;
const YEAR_SEC = 365 * DAY_SEC;

function baseDom(url = PAGE): DomSignals {
  return {
    url,
    title: 'T08 test',
    metaTags: [],
    scriptUrls: [],
    linkUrls: [],
    domMarkers: [],
    htmlSnippets: [],
    mixedContent: [],
    cookiesFromDocument: [],
    cssAssets: [],
  } as unknown as DomSignals;
}

function domWithSri(items: SriItem[], url = PAGE): DomSignals {
  return { ...baseDom(url), sriResources: items } as unknown as DomSignals;
}

const script = (url: string, hasIntegrity = false): SriItem => ({ kind: 'script', url, hasIntegrity });
const style = (url: string, hasIntegrity = false): SriItem => ({ kind: 'stylesheet', url, hasIntegrity });

/** 問題のない（既存の Cookie 指摘が出ない）認証系 Cookie。session_id は既存の分類で authentication */
function authCookie(overrides: Partial<InspectedCookieInfo> = {}): InspectedCookieInfo {
  return {
    name: 'session_id',
    domain: 'www.example.test',
    path: '/',
    secure: true,
    httpOnly: true,
    sameSite: 'lax',
    session: true,
    hostOnly: true,
    issues: [],
    ...overrides,
  } as InspectedCookieInfo;
}

function cookieOf(name: string, overrides: Partial<InspectedCookieInfo> = {}): InspectedCookieInfo {
  return authCookie({ name, ...overrides });
}

function evaluate(opts: {
  dom?: DomSignals;
  headers?: Record<string, string[]>;
  cookies?: InspectedCookieInfo[];
  url?: string;
}): SecurityCheckResult[] {
  const url = opts.url ?? PAGE;
  return new SecurityEngine().evaluate({
    url,
    dom: opts.dom ?? baseDom(url),
    network: { url, responseHeaders: opts.headers ?? {}, cookies: opts.cookies ?? [] },
  }).checks;
}

const byId = (checks: SecurityCheckResult[], id: string): SecurityCheckResult[] =>
  checks.filter((c) => c.checkId === id);
const has = (checks: SecurityCheckResult[], id: string): boolean => byId(checks, id).length > 0;

/** 表の status / 重大度どおりに 1 件だけ出ることを確かめる */
function expectFires(checks: SecurityCheckResult[], id: string, scope = PAGE): SecurityCheckResult {
  const found = byId(checks, id);
  expect(found.length, `${id} がちょうど 1 件出ていません`).toBe(1);
  const spec = NEW_CHECKS.find((c) => c.id === id)!;
  expect(found[0].status).toBe(spec.status);
  expect(found[0].severity).toBe(spec.severity);
  expect(found[0].scope).toBe(scope);
  expect(typeof found[0].observed).toBe('string');
  expect(found[0].observed.length).toBeGreaterThan(0);
  expect(found[0].description.length).toBeGreaterThan(0);
  expect(found[0].recommendation.length).toBeGreaterThan(0);
  return found[0];
}

/** 指摘の本文（観測値・説明・推奨）をまとめた文字列 */
const textOf = (c: SecurityCheckResult): string => `${c.observed}\n${c.description}\n${c.recommendation}`;

// ---------------------------------------------------------------------------
// content-script: 集めるのは URL と「integrity 属性があるか」だけ
// ---------------------------------------------------------------------------

const INTEGRITY_MARKER_A = 'sha384-T08MARKERAAAAintegrityValueMustNotLeak0000000000000000000000';
const INTEGRITY_MARKER_B = 'sha256-T08MARKERBBBBintegrityValueMustNotLeak11111111111';

function sriItemsOf(signals: DomSignals): SriItem[] {
  const items = (signals as unknown as { sriResources?: SriItem[] }).sriResources;
  expect(Array.isArray(items), 'DomSignals.sriResources が配列ではありません').toBe(true);
  return items as SriItem[];
}

describe('v1.8.0 T08: content-script の SRI 収集 (extractDomSignals)', () => {
  beforeEach(() => {
    document.head.innerHTML = '';
    document.body.innerHTML = '';
  });

  it('script[src] と link[rel=stylesheet] の絶対 URL と integrity 属性の有無を集める', () => {
    document.head.innerHTML = `
      <script src="https://cdn.vendor.example/lib.js" integrity="${INTEGRITY_MARKER_A}" crossorigin="anonymous"></script>
      <script src="https://cdn.vendor.example/no-sri.js"></script>
      <link rel="stylesheet" href="https://cdn.vendor.example/style.css" integrity="${INTEGRITY_MARKER_B}" crossorigin="anonymous">
      <link rel="stylesheet" href="/local/site.css">
    `;
    const items = sriItemsOf(extractDomSignals(PAGE));

    const find = (url: string) => items.find((i) => i.url === url);
    expect(find('https://cdn.vendor.example/lib.js')).toMatchObject({ kind: 'script', hasIntegrity: true });
    expect(find('https://cdn.vendor.example/no-sri.js')).toMatchObject({ kind: 'script', hasIntegrity: false });
    expect(find('https://cdn.vendor.example/style.css')).toMatchObject({ kind: 'stylesheet', hasIntegrity: true });
    expect(find('https://www.example.test/local/site.css')).toMatchObject({ kind: 'stylesheet', hasIntegrity: false });
  });

  it('stylesheet 以外の link（icon・preload・preconnect）と、src の無い script は集めない', () => {
    document.head.innerHTML = `
      <link rel="icon" href="https://cdn.vendor.example/favicon.ico">
      <link rel="preload" as="script" href="https://cdn.vendor.example/preload.js">
      <link rel="preconnect" href="https://cdn.vendor.example/">
      <script>window.inlineOnly = true;</script>
      <script src="https://cdn.vendor.example/only.js"></script>
    `;
    const items = sriItemsOf(extractDomSignals(PAGE));
    expect(items.map((i) => i.url)).toEqual(['https://cdn.vendor.example/only.js']);
  });

  it('integrity の値を集めない（要素のキーは kind・url・hasIntegrity だけで、値はどこにも無い）', () => {
    document.head.innerHTML = `
      <script src="https://cdn.vendor.example/lib.js" integrity="${INTEGRITY_MARKER_A}"></script>
      <link rel="stylesheet" href="https://cdn.vendor.example/style.css" integrity="${INTEGRITY_MARKER_B}">
    `;
    const signals = extractDomSignals(PAGE);
    const items = sriItemsOf(signals);
    expect(items.length).toBe(2);
    for (const item of items) {
      for (const key of Object.keys(item)) {
        expect(['kind', 'url', 'hasIntegrity']).toContain(key);
      }
      expect(typeof item.hasIntegrity).toBe('boolean');
    }
    const json = JSON.stringify(signals);
    expect(json).not.toContain('T08MARKERAAAA');
    expect(json).not.toContain('T08MARKERBBBB');
  });
});

// ---------------------------------------------------------------------------
// SEC-SRI-01: サードパーティの script / stylesheet に integrity がない
// ---------------------------------------------------------------------------

describe('v1.8.0 T08: SEC-SRI-01 — サードパーティ（PSL で別サイト）の資源に integrity がない', () => {
  it('陽性: 別サイトの script に integrity がないとき warning / low で出て、観測値に URL がある', () => {
    const c = expectFires(evaluate({ dom: domWithSri([script('https://cdn.vendor.example/lib.js')]) }), 'SEC-SRI-01');
    expect(c.observed).toContain('https://cdn.vendor.example/lib.js');
  });

  it('陽性: 別サイトの stylesheet に integrity がないときも出る', () => {
    const c = expectFires(evaluate({ dom: domWithSri([style('https://cdn.vendor.example/theme.css')]) }), 'SEC-SRI-01');
    expect(c.observed).toContain('https://cdn.vendor.example/theme.css');
  });

  it('陽性: 公開 CDN（cdn.jsdelivr.net）の版を固定した資源は SRI を付けられるので SEC-SRI-01 になる', () => {
    const checks = evaluate({
      dom: domWithSri([script('https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js')]),
    });
    expectFires(checks, 'SEC-SRI-01');
    expect(has(checks, 'SEC-SRI-02')).toBe(false);
  });

  it('陽性: PSL の複合サフィックス（co.jp）で別の登録ドメインなら別サイトとして出る', () => {
    const page = 'https://www.example.co.jp/';
    const checks = evaluate({
      url: page,
      dom: domWithSri([script('https://static.example-cdn.co.jp/app.js')], page),
    });
    expectFires(checks, 'SEC-SRI-01', page);
  });

  it('陽性: 12 件の URL は 1 行にまとまり、観測値に出る URL は 10 件まで', () => {
    const urls = Array.from({ length: 12 }, (_, i) => `https://cdn.vendor.example/lib-${String(i + 1).padStart(2, '0')}.js`);
    const c = expectFires(evaluate({ dom: domWithSri(urls.map((u) => script(u))) }), 'SEC-SRI-01');
    const listed = urls.filter((u) => c.observed.includes(u));
    expect(listed.length).toBe(10);
  });

  it('陽性: 同じ URL が複数あっても 1 行で、件数を重ねない（観測値に同じ URL は 1 回）', () => {
    const u = 'https://cdn.vendor.example/dup.js';
    const c = expectFires(evaluate({ dom: domWithSri([script(u), script(u), script(u)]) }), 'SEC-SRI-01');
    expect(c.observed.split(u).length - 1).toBe(1);
  });

  it('陽性: URL のクエリとフラグメントは指摘の本文に出さない（URL マスク IMPL-07 と同じ扱い）', () => {
    const c = expectFires(
      evaluate({ dom: domWithSri([script('https://cdn.vendor.example/w.js?api_key=T08QUERYSECRET#T08FRAG')]) }),
      'SEC-SRI-01'
    );
    expect(textOf(c)).not.toContain('T08QUERYSECRET');
    expect(textOf(c)).not.toContain('T08FRAG');
    expect(c.observed).toContain('https://cdn.vendor.example/w.js');
  });

  it('陰性: 別サイトでも integrity があれば出ない', () => {
    const checks = evaluate({
      dom: domWithSri([script('https://cdn.vendor.example/lib.js', true), style('https://cdn.vendor.example/a.css', true)]),
    });
    expect(has(checks, 'SEC-SRI-01')).toBe(false);
    expect(has(checks, 'SEC-SRI-02')).toBe(false);
  });

  it('陰性: 同一サイト（cdn.example.test と www.example.test）の資源は対象外', () => {
    const checks = evaluate({
      dom: domWithSri([
        script('https://cdn.example.test/app.js'),
        style('https://static.cdn.example.test/site.css'),
        script('https://www.example.test/js/main.js'),
      ]),
    });
    expect(has(checks, 'SEC-SRI-01')).toBe(false);
    expect(has(checks, 'SEC-SRI-02')).toBe(false);
  });

  it('陰性: 同一サイト（co.jp の同じ登録ドメイン）の資源は対象外', () => {
    const page = 'https://www.example.co.jp/';
    const checks = evaluate({ url: page, dom: domWithSri([script('https://static.example.co.jp/app.js')], page) });
    expect(has(checks, 'SEC-SRI-01')).toBe(false);
  });

  it('陰性: 集めた資源が無い / sriResources が無い（過去の形の DomSignals）ときは出ない', () => {
    expect(has(evaluate({ dom: domWithSri([]) }), 'SEC-SRI-01')).toBe(false);
    const old = evaluate({ dom: baseDom() });
    expect(old.some((c) => c.checkId.startsWith('SEC-SRI-') && c.status !== 'pass' && c.status !== 'info')).toBe(false);
    expect(has(old, 'SEC-SRI-01')).toBe(false);
    expect(has(old, 'SEC-SRI-02')).toBe(false);
  });

  it('陰性: http(s) 以外の URL（data:・blob:）は対象外', () => {
    const checks = evaluate({
      dom: domWithSri([script('data:text/javascript,alert(1)'), script('blob:https://www.example.test/abc')]),
    });
    expect(has(checks, 'SEC-SRI-01')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// SEC-SRI-02: SRI を付けられない配信元（コード内の一覧）
// ---------------------------------------------------------------------------

/** 設計メモ「外部の事実」で一次資料を確かめた配信元 */
const UNSUPPORTED_PROVIDER_URLS = [
  'https://www.googletagmanager.com/gtm.js?id=GTM-T08TEST',
  'https://js.stripe.com/v3/',
  'https://www.paypal.com/sdk/js?client-id=t08-test',
  'https://accounts.google.com/gsi/client',
];

describe('v1.8.0 T08: SEC-SRI-02 — 内容が常に更新され SRI を付けられない配信元', () => {
  it.each(UNSUPPORTED_PROVIDER_URLS)('陽性: %s に integrity がないとき info / info で出て、SEC-SRI-01 にはならない', (u) => {
    const checks = evaluate({ dom: domWithSri([script(u)]) });
    const c = expectFires(checks, 'SEC-SRI-02');
    expect(c.observed).toContain(new URL(u).hostname);
    expect(has(checks, 'SEC-SRI-01')).toBe(false);
  });

  it('陽性: 一覧の配信元が複数あっても 1 行にまとまる', () => {
    expectFires(evaluate({ dom: domWithSri(UNSUPPORTED_PROVIDER_URLS.map((u) => script(u))) }), 'SEC-SRI-02');
  });

  it('陽性: 一覧の配信元と一般の配信元が混ざると、SRI-01 と SRI-02 にそれぞれの URL だけが出る', () => {
    const generic = 'https://cdn.vendor.example/lib.js';
    const gtm = 'https://www.googletagmanager.com/gtm.js?id=GTM-T08TEST';
    const checks = evaluate({ dom: domWithSri([script(generic), script(gtm)]) });
    const sri01 = expectFires(checks, 'SEC-SRI-01');
    const sri02 = expectFires(checks, 'SEC-SRI-02');
    expect(sri01.observed).toContain(generic);
    expect(sri01.observed).not.toContain('googletagmanager.com');
    expect(sri02.observed).toContain('www.googletagmanager.com');
    expect(sri02.observed).not.toContain('cdn.vendor.example');
  });

  it('陰性: 一覧の配信元でも integrity があれば出ない', () => {
    const checks = evaluate({ dom: domWithSri([script('https://js.stripe.com/v3/', true)]) });
    expect(has(checks, 'SEC-SRI-02')).toBe(false);
    expect(has(checks, 'SEC-SRI-01')).toBe(false);
  });

  it('陰性: 一覧のホスト名で始まるだけの別ホスト（偽装）は一覧に入らず SEC-SRI-01 になる', () => {
    const checks = evaluate({ dom: domWithSri([script('https://www.googletagmanager.com.attacker.example/gtm.js')]) });
    expect(has(checks, 'SEC-SRI-02')).toBe(false);
    expectFires(checks, 'SEC-SRI-01');
  });

  it('陰性: 一覧に無い一般の配信元だけなら SEC-SRI-02 は出ない', () => {
    expect(has(evaluate({ dom: domWithSri([script('https://cdn.vendor.example/lib.js')]) }), 'SEC-SRI-02')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// SEC-CACHE-01: 認証系の Cookie があるページで Cache-Control に no-store がない
// ---------------------------------------------------------------------------

describe('v1.8.0 T08: SEC-CACHE-01 — 認証系 Cookie のあるページで no-store がない', () => {
  it('陽性: 認証系 Cookie があり Cache-Control が無いとき warning / low で出る', () => {
    expectFires(evaluate({ cookies: [authCookie()], headers: {} }), 'SEC-CACHE-01');
  });

  it.each(['private, max-age=0', 'no-cache', 'max-age=0, must-revalidate', 'max-age=0, x-no-store'])(
    '陽性: Cache-Control が %j（no-store ディレクティブが無い）のとき出る',
    (value) => {
      expectFires(evaluate({ cookies: [authCookie()], headers: { 'cache-control': [value] } }), 'SEC-CACHE-01');
    }
  );

  it('陽性: 既知の認証系 Cookie 名（PHPSESSID・JSESSIONID）でも出る', () => {
    expectFires(evaluate({ cookies: [cookieOf('PHPSESSID')], headers: {} }), 'SEC-CACHE-01');
    expectFires(evaluate({ cookies: [cookieOf('JSESSIONID')], headers: {} }), 'SEC-CACHE-01');
  });

  it.each([
    ['no-store'],
    ['private, no-store'],
    ['no-cache, no-store, must-revalidate'],
    ['NO-STORE'],
    [' no-store '],
  ])('陰性: Cache-Control が %j のとき出ない', (value) => {
    expect(has(evaluate({ cookies: [authCookie()], headers: { 'cache-control': [value] } }), 'SEC-CACHE-01')).toBe(false);
  });

  it('陰性: Cache-Control が複数行で、どれかに no-store があれば出ない', () => {
    const checks = evaluate({ cookies: [authCookie()], headers: { 'cache-control': ['private', 'no-store'] } });
    expect(has(checks, 'SEC-CACHE-01')).toBe(false);
  });

  it('陰性: Cookie が無いページでは出ない', () => {
    expect(has(evaluate({ cookies: [], headers: {} }), 'SEC-CACHE-01')).toBe(false);
  });

  it('陰性: 認証系でない Cookie（解析・CSRF・UI 設定・一般）だけなら出ない', () => {
    const cookies = [cookieOf('_ga'), cookieOf('csrftoken'), cookieOf('theme'), cookieOf('banner_closed')];
    expect(has(evaluate({ cookies, headers: {} }), 'SEC-CACHE-01')).toBe(false);
  });

  it('SEC-CACHE- が HEADER_DEPENDENT_CHECK_PREFIXES にある', () => {
    expect(HEADER_DEPENDENT_CHECK_PREFIXES as readonly string[]).toContain('SEC-CACHE-');
  });

  it('G5: cache-control を取得する（許可リストにあり、filterAndSanitizeHeaders が残す）', () => {
    expect(ALLOWED_RESPONSE_HEADERS.has('cache-control')).toBe(true);
    const out = filterAndSanitizeHeaders([
      { name: 'Cache-Control', value: 'private, no-store' },
      { name: 'Set-Cookie', value: 'session_id=secret' },
    ] as chrome.webRequest.HttpHeader[]);
    expect(out['cache-control']).toEqual(['private, no-store']);
    expect(out['set-cookie']).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// SEC-COOKIE-EXPIRY: 認証系 Cookie の有効期限が 1 年を超える
// ---------------------------------------------------------------------------

describe('v1.8.0 T08: SEC-COOKIE-EXPIRY — 認証系 Cookie の有効期限が 1 年を超える', () => {
  let nowSec = 0;
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(Date.now()));
    nowSec = Date.now() / 1000;
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  const persistent = (name: string, lifetimeSec: number): InspectedCookieInfo =>
    cookieOf(name, { session: false, expirationDate: nowSec + lifetimeSec });

  const run = (cookies: InspectedCookieInfo[]) => checkCookies(cookies, PAGE, true).checks;

  it('陽性: 有効期限が 400 日後の認証系 Cookie で warning / low・category cookies で出て、観測値に Cookie 名がある', () => {
    const c = expectFires(run([persistent('session_id', 400 * DAY_SEC)]), 'SEC-COOKIE-EXPIRY');
    expect(c.category).toBe('cookies');
    expect(c.observed).toContain('session_id');
  });

  it('陽性: 1 年と 1 時間後でも出る（1 年を超える）', () => {
    expectFires(run([persistent('auth_token', YEAR_SEC + 3600)]), 'SEC-COOKIE-EXPIRY');
  });

  it('陽性: 該当する認証系 Cookie が 2 つあっても 1 行で、両方の名前が根拠にある', () => {
    const c = expectFires(
      run([persistent('session_id', 400 * DAY_SEC), persistent('auth_token', 380 * DAY_SEC)]),
      'SEC-COOKIE-EXPIRY'
    );
    expect(textOf(c)).toContain('session_id');
    expect(textOf(c)).toContain('auth_token');
  });

  it('陰性: ちょうど 1 年（超えない）・30 日・セッション Cookie では出ない', () => {
    expect(has(run([persistent('session_id', YEAR_SEC)]), 'SEC-COOKIE-EXPIRY')).toBe(false);
    expect(has(run([persistent('session_id', 30 * DAY_SEC)]), 'SEC-COOKIE-EXPIRY')).toBe(false);
    expect(has(run([authCookie({ session: true, expirationDate: undefined })]), 'SEC-COOKIE-EXPIRY')).toBe(false);
  });

  it('陰性: 認証系でない Cookie（解析・CSRF・UI 設定）は有効期限が長くても出ない', () => {
    const checks = run([
      persistent('_ga', 400 * DAY_SEC),
      persistent('csrftoken', 400 * DAY_SEC),
      persistent('theme', 400 * DAY_SEC),
    ]);
    expect(has(checks, 'SEC-COOKIE-EXPIRY')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// SEC-COOKIE-SAMESITE-NONE: 認証系 Cookie が SameSite=None（Secure あり）
// ---------------------------------------------------------------------------

describe('v1.8.0 T08: SEC-COOKIE-SAMESITE-NONE — 認証系 Cookie が SameSite=None（Secure あり）', () => {
  const run = (cookies: InspectedCookieInfo[]) => checkCookies(cookies, PAGE, true).checks;

  it('陽性: Chrome API の no_restriction（SameSite=None）・Secure ありで warning / low・category cookies で出る', () => {
    const c = expectFires(run([authCookie({ sameSite: 'no_restriction', secure: true })]), 'SEC-COOKIE-SAMESITE-NONE');
    expect(c.category).toBe('cookies');
    expect(c.observed).toContain('session_id');
  });

  it('陽性: 該当する認証系 Cookie が 2 つあっても 1 行', () => {
    expectFires(
      run([
        authCookie({ sameSite: 'no_restriction' }),
        cookieOf('auth_token', { sameSite: 'no_restriction' }),
      ]),
      'SEC-COOKIE-SAMESITE-NONE'
    );
  });

  it('陰性: Secure なしの SameSite=None はブラウザが保存しないので対象外（D7）', () => {
    expect(has(run([authCookie({ sameSite: 'no_restriction', secure: false })]), 'SEC-COOKIE-SAMESITE-NONE')).toBe(false);
  });

  it.each(['lax', 'strict', 'unspecified'] as const)('陰性: SameSite=%s では出ない', (sameSite) => {
    expect(has(run([authCookie({ sameSite })]), 'SEC-COOKIE-SAMESITE-NONE')).toBe(false);
  });

  it('陰性: 認証系でない Cookie（解析・CSRF・一般）は SameSite=None でも出ない', () => {
    const checks = run([
      cookieOf('_ga', { sameSite: 'no_restriction' }),
      cookieOf('csrftoken', { sameSite: 'no_restriction' }),
      cookieOf('banner_closed', { sameSite: 'no_restriction' }),
    ]);
    expect(has(checks, 'SEC-COOKIE-SAMESITE-NONE')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// G4・重複なし
// ---------------------------------------------------------------------------

describe('v1.8.0 T08: 新しい指摘は LOW 以下（G4）で、同じ ID は 1 行', () => {
  let nowSec = 0;
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(Date.now()));
    nowSec = Date.now() / 1000;
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  function triggerAll(): SecurityCheckResult[] {
    return evaluate({
      dom: domWithSri([
        script('https://cdn.vendor.example/a.js'),
        style('https://cdn.vendor.example/b.css'),
        script('https://www.googletagmanager.com/gtm.js?id=GTM-T08TEST'),
        script('https://js.stripe.com/v3/'),
      ]),
      headers: { 'cache-control': ['private'] },
      cookies: [
        authCookie({ sameSite: 'no_restriction', session: false, expirationDate: nowSec + 400 * DAY_SEC }),
        cookieOf('auth_token', { sameSite: 'no_restriction', session: false, expirationDate: nowSec + 390 * DAY_SEC }),
      ],
    });
  }

  it('1 つの入力で 5 つの ID がすべて出る（入力の確認）', () => {
    const checks = triggerAll();
    for (const id of NEW_IDS) expect(has(checks, id), `${id} が出ていません`).toBe(true);
  });

  it('新しい ID の重大度は low か info だけで、status / 重大度は表のとおり', () => {
    const checks = triggerAll();
    for (const spec of NEW_CHECKS) {
      for (const c of byId(checks, spec.id)) {
        expect(['low', 'info']).toContain(c.severity);
        expect(c.status).toBe(spec.status);
        expect(c.severity).toBe(spec.severity);
      }
    }
  });

  it('同じ新しい ID は 2 件以上出ない', () => {
    const checks = triggerAll();
    for (const id of NEW_IDS) expect(byId(checks, id).length, id).toBeLessThanOrEqual(1);
  });

  it('既存の Cookie 指摘（SEC-COOKIE-HTTPONLY / SECURE）は、問題のない属性の Cookie では出ない（対照）', () => {
    const checks = triggerAll();
    expect(has(checks, 'SEC-COOKIE-HTTPONLY')).toBe(false);
    expect(has(checks, 'SEC-COOKIE-SECURE')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// executeInspection: SPEC-01（ヘッダー未観測）と、観測ありの対照
// ---------------------------------------------------------------------------

interface InspectOpts {
  headers?: Record<string, string[]>;
  cache?: 'observed' | 'none' | 'other-origin';
  cookies?: InspectedCookieInfo[];
  dom?: DomSignals | (() => DomSignals);
  saveReport?: (r: InspectionReport) => Promise<void>;
}

async function inspect(opts: InspectOpts = {}): Promise<InspectionReport> {
  const cache = opts.cache ?? 'observed';
  const domFactory = typeof opts.dom === 'function' ? opts.dom : () => (opts.dom as DomSignals | undefined) ?? baseDom();
  return executeInspection({
    tab: { id: 801, url: PAGE },
    fetchDomSignals: vi.fn().mockImplementation(async () => domFactory()),
    fetchRuntimeVersions: vi.fn().mockResolvedValue({ versions: {}, frameworkMarkers: [] }),
    getCachedHeaders: vi.fn().mockResolvedValue(
      cache === 'none'
        ? undefined
        : {
            url: cache === 'other-origin' ? 'https://other.example.test/' : PAGE,
            headers: opts.headers || {},
            observed: true,
          }
    ),
    getInspectedCookies: vi.fn().mockResolvedValue(opts.cookies ?? []),
    getAllFindingExceptions: vi.fn().mockResolvedValue([]),
    saveReport: opts.saveReport ?? vi.fn().mockResolvedValue(undefined),
  });
}

describe('v1.8.0 T08: SPEC-01 — ヘッダー未観測なら SEC-CACHE-01 は unknown で要確認に入らない', () => {
  it.each(['none', 'other-origin'] as const)('キャッシュ %s: SEC-CACHE-* はすべて unknown / info、要確認 0', async (cache) => {
    const report = await inspect({ cache, cookies: [authCookie()], headers: { 'cache-control': ['private'] } });
    const cacheChecks = report.securityChecks.filter((c) => c.checkId.startsWith('SEC-CACHE-'));
    expect(cacheChecks.every((c) => c.status === 'unknown' && c.severity === 'info')).toBe(true);
    expect(cacheChecks.some((c) => isRequiresAttention(c))).toBe(false);
    expect(report.summary.requiresAttentionCount).toBe(0);
  });

  it('対照: ヘッダーを観測でき no-store が無いとき、SEC-CACHE-01 は warning / low で要確認に入る', async () => {
    const report = await inspect({ cookies: [authCookie()], headers: { 'cache-control': ['private'] } });
    const c = expectFires(report.securityChecks, 'SEC-CACHE-01');
    expect(isRequiresAttention(c)).toBe(true);
    expect(report.summary.requiresAttentionCount).toBeGreaterThanOrEqual(1);
  });

  it('対照: ヘッダーを観測でき no-store があれば SEC-CACHE-01 は出ない', async () => {
    const report = await inspect({ cookies: [authCookie()], headers: { 'cache-control': ['no-store'] } });
    expect(has(report.securityChecks, 'SEC-CACHE-01')).toBe(false);
  });

  it('SEC-SRI-* は DOM の情報だけで判定するので、ヘッダー未観測でも出る（unknown にしない）', async () => {
    const report = await inspect({ cache: 'none', dom: domWithSri([script('https://cdn.vendor.example/lib.js')]) });
    expectFires(report.securityChecks, 'SEC-SRI-01');
  });
});

// ---------------------------------------------------------------------------
// レポートと履歴に integrity の値が出ない
// ---------------------------------------------------------------------------

describe('v1.8.0 T08: レポートと履歴に integrity の値が出ない', () => {
  const store: Record<string, unknown> = {};
  let prevChrome: unknown;

  beforeEach(() => {
    for (const k of Object.keys(store)) delete store[k];
    prevChrome = (globalThis as { chrome?: unknown }).chrome;
    (globalThis as { chrome?: unknown }).chrome = {
      storage: {
        local: {
          get: vi.fn(async (key: string) => ({ [key]: store[key] })),
          set: vi.fn(async (items: Record<string, unknown>) => {
            Object.assign(store, items);
          }),
          remove: vi.fn(async (key: string) => {
            delete store[key];
          }),
        },
      },
    };
    document.head.innerHTML = `
      <script src="https://cdn.vendor.example/with-sri.js" integrity="${INTEGRITY_MARKER_A}" crossorigin="anonymous"></script>
      <link rel="stylesheet" href="https://cdn.vendor.example/with-sri.css" integrity="${INTEGRITY_MARKER_B}" crossorigin="anonymous">
      <script src="https://cdn.vendor.example/no-sri.js"></script>
    `;
    document.body.innerHTML = '<p>T08</p>';
  });

  afterEach(() => {
    (globalThis as { chrome?: unknown }).chrome = prevChrome;
    document.head.innerHTML = '';
    document.body.innerHTML = '';
  });

  const expectNoMarker = (text: string, label: string) => {
    expect(text, `${label} に integrity の値があります`).not.toContain('T08MARKERAAAA');
    expect(text, `${label} に integrity の値があります`).not.toContain('T08MARKERBBBB');
  };

  it('DOM から調査した結果（レポート JSON・Markdown・保存した履歴）に integrity の値が無く、SEC-SRI-01 は出る', async () => {
    const report = await inspect({
      dom: () => extractDomSignals(PAGE),
      headers: { 'cache-control': ['no-store'] },
      saveReport: saveReportToHistory,
    });

    // 前提: integrity の無いサードパーティ資源から SEC-SRI-01 が出ている（SRI の診断が動いている）
    const sri01 = expectFires(report.securityChecks, 'SEC-SRI-01');
    expect(sri01.observed).toContain('https://cdn.vendor.example/no-sri.js');
    expect(sri01.observed).not.toContain('with-sri.js');

    expectNoMarker(JSON.stringify(report), 'レポート');
    expectNoMarker(generateMarkdownReport(report), 'Markdown');
    const history = await getAllHistoryReports();
    expect(history.length).toBe(1);
    expectNoMarker(JSON.stringify(history), '履歴');
    expectNoMarker(JSON.stringify(store), '保存領域');
  });

  it('受け取った sriResources に想定外の integrity の値が混ざっていても、レポートと履歴に出ない', async () => {
    const dirty = {
      ...baseDom(),
      sriResources: [
        { kind: 'script', url: 'https://cdn.vendor.example/x.js', hasIntegrity: true, integrity: INTEGRITY_MARKER_A },
        { kind: 'script', url: 'https://cdn.vendor.example/y.js', hasIntegrity: false, integrity: INTEGRITY_MARKER_B },
      ],
    } as unknown as DomSignals;
    const report = await inspect({ dom: dirty, saveReport: saveReportToHistory });
    expectNoMarker(JSON.stringify(report), 'レポート');
    expectNoMarker(generateMarkdownReport(report), 'Markdown');
    expectNoMarker(JSON.stringify(store), '保存領域');
  });
});

// ---------------------------------------------------------------------------
// レポートの整合性チェッカー・仕様書
// ---------------------------------------------------------------------------

describe('v1.8.0 T08: レポートの整合性と仕様書', () => {
  it('新しい指摘を含むレポートと Markdown の組が reports:lint の検査を通り、Markdown に項目の名前がある', async () => {
    const nowSec = Date.now() / 1000;
    const report = await inspect({
      dom: domWithSri([
        script('https://cdn.vendor.example/a.js'),
        script('https://www.googletagmanager.com/gtm.js?id=GTM-T08TEST'),
      ]),
      headers: { 'cache-control': ['private'] },
      cookies: [authCookie({ sameSite: 'no_restriction', session: false, expirationDate: nowSec + 400 * DAY_SEC })],
    });
    for (const id of NEW_IDS) expect(has(report.securityChecks, id), `${id} が出ていません`).toBe(true);

    const md = generateMarkdownReport(report);
    for (const id of NEW_IDS) {
      const c = byId(report.securityChecks, id)[0];
      expect(md).toContain(c.name.replace(/\|/g, '\\|'));
    }
    const lint = lintReportPair(report, md, { includePending: true });
    expect(lint.violations).toEqual([]);
    expect(lint.ok).toBe(true);
  });

  it('docs/DETECTION_SPECIFICATION.md に 5 つの ID がある', () => {
    const spec = fs.readFileSync(path.resolve(__dirname, '../docs/DETECTION_SPECIFICATION.md'), 'utf8');
    for (const id of NEW_IDS) expect(spec, `${id} が仕様書にありません`).toContain(id);
  });
});
