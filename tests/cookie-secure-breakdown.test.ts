/**
 * Secure 未設定の内訳（v1.8.2 T04 / A、指示書 §4.2・§6 T04）
 *
 * Cookie の Secure 未設定の指摘（SEC-COOKIE-SECURE・SEC-COOKIE-SECURE-CSRF・SEC-COOKIE-SECURE-GENERAL）に、
 * 「うち N 件は親ドメインのスコープ」を添える（Markdown・ダッシュボード）。そのホストの管理者が直せない Cookie を区別するため。
 *
 * 公開 API（設計メモ「実装の方針」）:
 * - SecurityCheckResult.parentDomainCookieCount?: number（Secure 未設定の Cookie のうち hostOnly === false の件数。1 以上のときだけ付ける）
 * - observed の文字列は変えない（ポップアップ・差分に影響させない）
 * - Markdown §5 とダッシュボードの観測値に「うち N 件は親ドメインのスコープ」
 *
 * 件数は合成データから数える（直書きしない）。
 */
import { describe, expect, it } from 'vitest';
import { checkCookies } from '../src/security/cookies';
import { generateMarkdownReport } from '../src/export/markdown';
import { renderFullSecurityHtml } from '../src/dashboard/render';
import { sanitizeReportUrls } from '../src/storage/history';
import type { InspectedCookieInfo, InspectionReport, SecurityCheckResult } from '../src/shared/types';

const PAGE_URL = 'https://app.example.test/';
const PAGE_HOST = 'app.example.test';
const SECURE_CHECK_IDS = ['SEC-COOKIE-SECURE', 'SEC-COOKIE-SECURE-CSRF', 'SEC-COOKIE-SECURE-GENERAL'];
const PARENT_PHRASE = '親ドメインのスコープ';
const breakdownText = (n: number): string => `うち ${n} 件は${PARENT_PHRASE}`;

interface CookieOpts {
  secure?: boolean;
  hostOnly?: boolean;
  domain?: string;
}

const cookie = (name: string, opts: CookieOpts = {}): InspectedCookieInfo => {
  const hostOnly = opts.hostOnly ?? true;
  return {
    name,
    domain: opts.domain ?? (hostOnly ? PAGE_HOST : '.example.test'),
    path: '/',
    secure: opts.secure ?? false,
    httpOnly: false,
    sameSite: 'lax',
    session: true,
    hostOnly,
  };
};

const parentCount = (check: SecurityCheckResult | undefined): number | undefined =>
  (check as (SecurityCheckResult & { parentDomainCookieCount?: number }) | undefined)?.parentDomainCookieCount;

const byId = (checks: SecurityCheckResult[], id: string): SecurityCheckResult | undefined =>
  checks.find((c) => c.checkId === id);

/** observed の先頭の「N 件」（指摘の総数） */
const totalOf = (check: SecurityCheckResult): number => {
  const m = /^(\d+)\s*件/.exec(check.observed);
  if (!m) throw new Error(`observed に件数がありません: ${check.observed}`);
  return Number(m[1]);
};

/** 合成データのうち、Secure が無く hostOnly === false の Cookie の数（期待値） */
const expectedParent = (cookies: InspectedCookieInfo[], names: string[]): number =>
  cookies.filter((c) => names.includes(c.name) && !c.secure && c.hostOnly === false).length;

const buildReport = (checks: SecurityCheckResult[], cookies: InspectedCookieInfo[]): InspectionReport => ({
  id: 'report-secure-breakdown',
  url: PAGE_URL,
  hostname: PAGE_HOST,
  inspectedAt: new Date().toISOString(),
  extensionVersion: '0.0.0-test',
  rulesVersion: 'test',
  summary: {
    totalTechnologies: 0,
    requiresAttentionCount: 0,
    securityFindings: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
    librarySecurity: { eolCount: 0, vulnerableLibraryCount: 0, mismatchCount: 0 },
    isHttps: true,
    mixedContentCount: 0,
  },
  technologies: [],
  securityChecks: checks,
  cookies,
  mixedContent: [],
});

const mdSection = (md: string, num: number): string => {
  const start = md.indexOf(`## ${num}.`);
  expect(start, `§${num} がありません`).toBeGreaterThanOrEqual(0);
  const next = md.indexOf('\n## ', start + 1);
  return md.slice(start, next < 0 ? undefined : next);
};

/** §5 の表で、指摘の名前を含む行 */
const mdRow = (md: string, check: SecurityCheckResult): string => {
  const row = mdSection(md, 5)
    .split('\n')
    .find((l) => l.startsWith('|') && l.includes(check.name));
  expect(row, `§5 に ${check.checkId} の行がありません`).toBeDefined();
  return row!;
};

// 一般・解析用: 親ドメイン 2 件（_ga・_gid）、host-only 1 件（theme_mode）、どれも Secure なし
const GENERAL_MIXED = [
  cookie('_ga', { hostOnly: false }),
  cookie('_gid', { hostOnly: false }),
  cookie('theme_mode', { hostOnly: true }),
];
const GENERAL_NAMES = ['_ga', '_gid', 'theme_mode'];

describe('T04: checkCookies が Secure 未設定の内訳（親ドメインの件数）を持つ', () => {
  it('陽性: 一般・解析用の Secure 未設定のうち、親ドメインの件数が合う（総数以下）', () => {
    const { checks } = checkCookies(GENERAL_MIXED, PAGE_URL, true);
    const general = byId(checks, 'SEC-COOKIE-SECURE-GENERAL');
    expect(general).toBeDefined();
    const n = expectedParent(GENERAL_MIXED, GENERAL_NAMES);
    expect(n).toBeGreaterThan(0);
    expect(parentCount(general)).toBe(n);
    expect(parentCount(general)!).toBeLessThanOrEqual(totalOf(general!));
  });

  it('陰性: すべて host-only → 内訳を付けない', () => {
    const cookies = [cookie('_ga'), cookie('_gid'), cookie('theme_mode')];
    const { checks } = checkCookies(cookies, PAGE_URL, true);
    const general = byId(checks, 'SEC-COOKIE-SECURE-GENERAL');
    expect(general).toBeDefined();
    expect(parentCount(general)).toBeUndefined();
  });

  it('陰性: Secure 付きの親ドメインの Cookie は数えない', () => {
    const cookies = [
      cookie('_ga', { hostOnly: false, secure: true }),
      cookie('_gid', { hostOnly: false }),
      cookie('theme_mode', { hostOnly: true }),
    ];
    const { checks } = checkCookies(cookies, PAGE_URL, true);
    const general = byId(checks, 'SEC-COOKIE-SECURE-GENERAL');
    expect(parentCount(general)).toBe(expectedParent(cookies, GENERAL_NAMES));
  });

  it('複数の指摘: 認証・CSRF・一般でそれぞれの件数を持つ（親ドメインが無い指摘には付けない）', () => {
    const cookies = [
      cookie('PHPSESSID', { hostOnly: false }),
      cookie('XSRF-TOKEN', { hostOnly: true }),
      cookie('_ga', { hostOnly: false }),
      cookie('theme_mode', { hostOnly: true }),
    ];
    const { checks } = checkCookies(cookies, PAGE_URL, true);
    const auth = byId(checks, 'SEC-COOKIE-SECURE');
    const csrf = byId(checks, 'SEC-COOKIE-SECURE-CSRF');
    const general = byId(checks, 'SEC-COOKIE-SECURE-GENERAL');
    expect(auth).toBeDefined();
    expect(csrf).toBeDefined();
    expect(general).toBeDefined();
    expect(parentCount(auth)).toBe(expectedParent(cookies, ['PHPSESSID']));
    expect(parentCount(csrf)).toBeUndefined();
    expect(parentCount(general)).toBe(expectedParent(cookies, ['_ga', 'theme_mode']));
  });

  it('複数: 同じ名前の Cookie が 2 つの親ドメインにある → 1 件ずつ数える（総数と同じ数え方）', () => {
    const cookies = [
      cookie('_ga', { hostOnly: false, domain: '.example.test' }),
      cookie('_ga', { hostOnly: false, domain: '.app.example.test' }),
    ];
    const { checks } = checkCookies(cookies, PAGE_URL, true);
    const general = byId(checks, 'SEC-COOKIE-SECURE-GENERAL')!;
    expect(general).toBeDefined();
    expect(parentCount(general)).toBe(cookies.length);
    expect(totalOf(general)).toBe(cookies.length);
  });

  it('陰性: Secure 以外の指摘（HttpOnly など）には付けない', () => {
    const cookies = [cookie('PHPSESSID', { hostOnly: false })];
    const { checks } = checkCookies(cookies, PAGE_URL, true);
    for (const c of checks.filter((x) => !SECURE_CHECK_IDS.includes(x.checkId))) {
      expect(parentCount(c), c.checkId).toBeUndefined();
    }
  });

  it('陰性: HTTP のページ（Secure を評価しない）では、どの指摘にも内訳を付けない', () => {
    const { checks } = checkCookies(GENERAL_MIXED, 'http://app.example.test/', false);
    expect(checks.some((c) => SECURE_CHECK_IDS.includes(c.checkId))).toBe(false);
    for (const c of checks) expect(parentCount(c), c.checkId).toBeUndefined();
  });

  it('observed の文字列は変えない（内訳は別の項目に持つ。ポップアップと差分に影響させない）', () => {
    const { checks } = checkCookies(GENERAL_MIXED, PAGE_URL, true);
    const general = byId(checks, 'SEC-COOKIE-SECURE-GENERAL')!;
    expect(general.observed).not.toContain(PARENT_PHRASE);
  });
});

describe('T04: Markdown §5 とダッシュボードの観測値に「うち N 件は親ドメインのスコープ」', () => {
  it('陽性: Markdown §5 の行に件数つきの内訳', () => {
    const { checks, inspectedCookies } = checkCookies(GENERAL_MIXED, PAGE_URL, true);
    const general = byId(checks, 'SEC-COOKIE-SECURE-GENERAL')!;
    const md = generateMarkdownReport(buildReport(checks, inspectedCookies));
    expect(mdRow(md, general)).toContain(breakdownText(expectedParent(GENERAL_MIXED, GENERAL_NAMES)));
  });

  it('陽性: ダッシュボードの観測値に件数つきの内訳', () => {
    const { checks } = checkCookies(GENERAL_MIXED, PAGE_URL, true);
    const general = byId(checks, 'SEC-COOKIE-SECURE-GENERAL')!;
    const html = renderFullSecurityHtml([general]);
    const obsIdx = html.indexOf('観測値');
    expect(obsIdx).toBeGreaterThanOrEqual(0);
    expect(html.slice(obsIdx)).toContain(breakdownText(expectedParent(GENERAL_MIXED, GENERAL_NAMES)));
  });

  it('複数の指摘: Markdown で指摘ごとに自分の件数、親ドメインの無い指摘には内訳なし', () => {
    const cookies = [
      cookie('PHPSESSID', { hostOnly: false }),
      cookie('XSRF-TOKEN', { hostOnly: true }),
      cookie('_ga', { hostOnly: false }),
      cookie('_gid', { hostOnly: false }),
    ];
    const { checks, inspectedCookies } = checkCookies(cookies, PAGE_URL, true);
    const md = generateMarkdownReport(buildReport(checks, inspectedCookies));
    expect(mdRow(md, byId(checks, 'SEC-COOKIE-SECURE')!)).toContain(breakdownText(expectedParent(cookies, ['PHPSESSID'])));
    expect(mdRow(md, byId(checks, 'SEC-COOKIE-SECURE-GENERAL')!)).toContain(
      breakdownText(expectedParent(cookies, ['_ga', '_gid']))
    );
    expect(mdRow(md, byId(checks, 'SEC-COOKIE-SECURE-CSRF')!)).not.toContain(PARENT_PHRASE);
  });

  it('陰性: すべて host-only → Markdown §5 とダッシュボードに内訳なし', () => {
    const cookies = [cookie('_ga'), cookie('theme_mode')];
    const { checks, inspectedCookies } = checkCookies(cookies, PAGE_URL, true);
    const md = generateMarkdownReport(buildReport(checks, inspectedCookies));
    expect(mdSection(md, 5)).not.toContain(PARENT_PHRASE);
    expect(renderFullSecurityHtml(checks)).not.toContain(PARENT_PHRASE);
  });

  it('互換: 内訳の項目が無い保存済みの指摘（v1.8.1 以前）→ 内訳を出さず、「うち 0 件」とも書かない', () => {
    const legacy: SecurityCheckResult = {
      checkId: 'SEC-COOKIE-SECURE-GENERAL',
      category: 'cookies',
      name: 'Cookie Secure属性未設定 (一般・解析用)',
      status: 'warning',
      severity: 'low',
      observed: '2 件の非認証系CookieでSecure属性が未設定 (_ga, _gid)',
      description: 'legacy',
      recommendation: 'legacy',
      referenceUrls: [],
      scope: PAGE_URL,
    };
    const md = generateMarkdownReport(buildReport([legacy], []));
    expect(mdRow(md, legacy)).not.toContain(PARENT_PHRASE);
    expect(md).not.toContain(breakdownText(0));
    const html = renderFullSecurityHtml([legacy]);
    expect(html).not.toContain(PARENT_PHRASE);
  });

  it('履歴に保存した後（sanitizeReportUrls）も内訳が出る', () => {
    const { checks, inspectedCookies } = checkCookies(GENERAL_MIXED, PAGE_URL, true);
    const saved = sanitizeReportUrls(buildReport(checks, inspectedCookies));
    const general = byId(saved.securityChecks, 'SEC-COOKIE-SECURE-GENERAL')!;
    const md = generateMarkdownReport(saved);
    expect(mdRow(md, general)).toContain(breakdownText(expectedParent(GENERAL_MIXED, GENERAL_NAMES)));
  });
});
