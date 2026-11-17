/**
 * Web Technology & Security Inspector
 * v1.8.1 T07: HTTPS でしか効かないヘッダーを HTTP のページで「対象外」にする（H6）の受け入れテスト
 * (tests/https-only-headers.test.ts)
 *
 * 設計メモ: docs/dev/v1.8.1/design/T07.md
 *
 * - 対象は COOP（SEC-COOP-01）と COEP（SEC-COEP-01）。HTML の仕様で、安全でないコンテキストでは
 *   ブラウザが既定のポリシーを使う（ヘッダーを無視する）。HSTS は既存の扱いのまま
 * - 「対象外」は新しい SecurityStatus 'not-applicable'。要確認件数・重大度の内訳・INFO・UNKNOWN・バッジに数えない
 * - HTTPS の入力では v1.8.0 と同じ結果（'not-applicable' は出ない）
 * - ヘッダー未観測なら従来どおり unknown（「対象外」より unknown を優先。SPEC-01）
 */

import { describe, expect, it, vi } from 'vitest';
import {
  executeInspection,
  HEADER_DEPENDENT_CHECK_PREFIXES,
  InspectionDependencies,
} from '../src/background/service-worker';
import { exportReportToCsv } from '../src/export/csv';
import { exportReportToJson } from '../src/export/json';
import { generateMarkdownReport } from '../src/export/markdown';
import { checkHttpHeaders } from '../src/security/headers';
import {
  formatMarkdownStatusBadge,
  formatPlainStatusCode,
  getSecurityCheckDisplayBadge,
  isRequiresAttention,
  summarizeSecurityChecks,
} from '../src/shared/security-status';
import type { DomSignals, InspectionReport, SecurityCheckResult, SecurityStatus } from '../src/shared/types';
// @ts-expect-error -- Node ESM スクリプト (.mjs) の直接インポート
import { lintReportPair as rawLintReportPair } from '../scripts/report-lint.mjs';

const lintReportPair = rawLintReportPair as (
  report: unknown,
  markdown: string,
  options?: { includePending?: boolean }
) => { ok: boolean; violations: unknown[] };

/** 「対象外」の status（設計メモ「実装の方針」） */
const NA: SecurityStatus = 'not-applicable';

const URL_HTTP = 'http://https-only.example.test/';
const URL_HTTPS = 'https://https-only.example.test/';

/** HTTPS で 1 件も出ない COOP・COEP の値（仕様で有効な値） */
const VALID_COOP_COEP: Record<string, string[]> = {
  'cross-origin-opener-policy': ['same-origin'],
  'cross-origin-embedder-policy': ['require-corp'],
};

/** COOP・COEP 以外の既存ヘッダーを揃えた土台 */
const BASE_HEADERS: Record<string, string[]> = {
  'content-security-policy': ["default-src 'self'; frame-ancestors 'none'"],
  'x-frame-options': ['DENY'],
  'x-content-type-options': ['nosniff'],
  'referrer-policy': ['strict-origin-when-cross-origin'],
  'permissions-policy': ['geolocation=(), camera=(), microphone=()'],
};

const withBase = (extra: Record<string, string[]>): Record<string, string[]> => ({ ...BASE_HEADERS, ...extra });

const runHttp = (headers: Record<string, string[]>): SecurityCheckResult[] =>
  checkHttpHeaders(headers, URL_HTTP, false);
const runHttps = (headers: Record<string, string[]>): SecurityCheckResult[] =>
  checkHttpHeaders(headers, URL_HTTPS, true);

const byPrefix = (checks: readonly SecurityCheckResult[], prefix: string): SecurityCheckResult[] =>
  checks.filter((c) => c.checkId.startsWith(prefix));

const isTargetId = (id: string): boolean => id.startsWith('SEC-COOP-') || id.startsWith('SEC-COEP-');

/** 「対象外」の 1 件を確かめる */
function expectNotApplicable(checks: readonly SecurityCheckResult[], prefix: string, url: string): SecurityCheckResult {
  const found = byPrefix(checks, prefix);
  expect(found.length, `${prefix} の項目は 1 件のはずです`).toBe(1);
  const c = found[0];
  expect(c.status).toBe(NA);
  expect(c.severity).toBe('info');
  expect(c.scope).toBe(url);
  expect(c.observed.length).toBeGreaterThan(0);
  expect(c.description).toMatch(/HTTPS/);
  expect(c.recommendation.length).toBeGreaterThan(0);
  expect(isRequiresAttention(c)).toBe(false);
  return c;
}

function emptyDom(url: string): DomSignals {
  return {
    url,
    title: 'HTTPS only headers test',
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

interface InspectOpts {
  url: string;
  headers?: Record<string, string[]>;
  /** observed: 同じ origin のキャッシュ / none: キャッシュなし / other-origin: 別の origin のキャッシュ */
  cache?: 'observed' | 'none' | 'other-origin';
}

function makeDeps(opts: InspectOpts): InspectionDependencies & { updateBadge: ReturnType<typeof vi.fn> } {
  const cache = opts.cache ?? 'observed';
  const otherOrigin = opts.url.startsWith('https:') ? 'https://other.example.test/' : 'http://other.example.test/';
  return {
    tab: { id: 711, url: opts.url },
    fetchDomSignals: vi.fn().mockResolvedValue(emptyDom(opts.url)),
    fetchRuntimeVersions: vi.fn().mockResolvedValue({ versions: {}, frameworkMarkers: [] }),
    getCachedHeaders: vi.fn().mockResolvedValue(
      cache === 'none'
        ? undefined
        : {
            url: cache === 'other-origin' ? otherOrigin : opts.url,
            headers: opts.headers || {},
            observed: true,
          }
    ),
    getInspectedCookies: vi.fn().mockResolvedValue([]),
    getAllFindingExceptions: vi.fn().mockResolvedValue([]),
    saveReport: vi.fn().mockResolvedValue(undefined),
    updateBadge: vi.fn(),
    hasWebRequestPermission: true,
  };
}

async function inspect(opts: InspectOpts): Promise<{ report: InspectionReport; badge: unknown[] | undefined }> {
  const deps = makeDeps(opts);
  const report = await executeInspection(deps);
  return { report, badge: deps.updateBadge.mock.calls[0] };
}

// ---------------------------------------------------------------------------
// 1. HTTP の入力で COOP・COEP が「対象外」になる（checkHttpHeaders）
// ---------------------------------------------------------------------------

describe('T07: HTTP のページで COOP は「対象外」（not-applicable）', () => {
  it('COOP が無い HTTP のページ: SEC-COOP-01 が 1 件、対象外・info で、要確認に入らない', () => {
    const c = expectNotApplicable(runHttp(BASE_HEADERS), 'SEC-COOP-', URL_HTTP);
    expect(c.checkId).toBe('SEC-COOP-01');
  });

  it.each(['same-origin', 'same-origin-allow-popups', 'noopener-allow-popups', 'unsafe-none', 'same-site'])(
    'COOP: %s を返す HTTP のページでも SEC-COOP-01 は対象外の 1 件だけ（値の良し悪しを判定しない）',
    (value) => {
      const checks = runHttp(withBase({ 'cross-origin-opener-policy': [value] }));
      const c = expectNotApplicable(checks, 'SEC-COOP-', URL_HTTP);
      expect(c.checkId).toBe('SEC-COOP-01');
      // 観測した値が分かるようにする
      expect(c.observed).toContain(value);
    }
  );
});

describe('T07: HTTP のページで COEP は「対象外」（not-applicable）', () => {
  it.each(['require-corp', 'credentialless', 'unsafe-none', 'require_corp'])(
    'COEP: %s を返す HTTP のページで SEC-COEP-01 が対象外の 1 件',
    (value) => {
      const checks = runHttp(withBase({ 'cross-origin-embedder-policy': [value] }));
      const c = expectNotApplicable(checks, 'SEC-COEP-', URL_HTTP);
      expect(c.checkId).toBe('SEC-COEP-01');
      expect(c.observed).toContain(value);
    }
  );

  it('陰性: COEP を返さない HTTP のページには SEC-COEP- の項目を作らない（COEP は既定で推奨しない）', () => {
    expect(byPrefix(runHttp(BASE_HEADERS), 'SEC-COEP-')).toEqual([]);
    expect(byPrefix(runHttp(withBase({ 'cross-origin-opener-policy': ['same-origin'] })), 'SEC-COEP-')).toEqual([]);
  });
});

describe('T07: 対象は COOP と COEP だけ（ほかのチェックは HTTP でも従来どおり）', () => {
  it('HTTP のページで「対象外」になるのは SEC-COOP- と SEC-COEP- の項目だけ', () => {
    const checks = runHttp({
      'cross-origin-opener-policy': ['unsafe-none'],
      'cross-origin-embedder-policy': ['require_corp'],
      'cross-origin-resource-policy': ['same_origin'],
      'x-xss-protection': ['1; mode=block'],
      'permissions-policy': ['camera=*'],
      'strict-transport-security': ['max-age=31536000; includeSubDomains'],
    });
    const na = checks.filter((c) => c.status === NA);
    expect(na.length).toBeGreaterThan(0);
    for (const c of na) {
      expect(isTargetId(c.checkId), `${c.checkId} は対象外にしない`).toBe(true);
    }
  });

  it('陰性: CORP は secure context の要件が無いので、HTTP でも仕様外の値は従来どおり info', () => {
    const corp = byPrefix(runHttp(withBase({ 'cross-origin-resource-policy': ['same_origin'] })), 'SEC-CORP-');
    expect(corp.length).toBe(1);
    expect(corp[0].status).toBe('info');
  });

  it('陰性: X-Frame-Options が無い HTTP のページの SEC-XFO- は従来どおり（対象外にしない）', () => {
    const noXfo = { ...BASE_HEADERS };
    delete noXfo['x-frame-options'];
    delete noXfo['content-security-policy'];
    const http = byPrefix(runHttp(noXfo), 'SEC-XFO-');
    const https = byPrefix(runHttps(noXfo), 'SEC-XFO-');
    expect(http.length).toBeGreaterThan(0);
    expect(http.map((c) => c.status)).toEqual(https.map((c) => c.status));
    expect(http.some((c) => c.status === NA)).toBe(false);
  });

  it('HSTS は既存の扱いのまま: HTTP のページで SEC-HSTS- の項目が「対象外」にならない', () => {
    for (const headers of [BASE_HEADERS, withBase({ 'strict-transport-security': ['max-age=31536000'] })]) {
      expect(byPrefix(runHttp(headers), 'SEC-HSTS-').some((c) => c.status === NA)).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// 2. HTTPS の入力では v1.8.0 と同じ結果
// ---------------------------------------------------------------------------

describe('T07: HTTPS の入力では v1.8.0 と同じ結果（対象外は出ない）', () => {
  it('COOP が無い HTTPS のページ: SEC-COOP-01 は info / info のまま', () => {
    const coop = byPrefix(runHttps(BASE_HEADERS), 'SEC-COOP-');
    expect(coop.length).toBe(1);
    expect(coop[0].checkId).toBe('SEC-COOP-01');
    expect(coop[0].status).toBe('info');
    expect(coop[0].severity).toBe('info');
  });

  it.each(['unsafe-none', 'same-site'])('COOP: %s の HTTPS のページ: SEC-COOP-01 は info のまま', (value) => {
    const coop = byPrefix(runHttps(withBase({ 'cross-origin-opener-policy': [value] })), 'SEC-COOP-');
    expect(coop.length).toBe(1);
    expect(coop[0].status).toBe('info');
  });

  it.each(['same-origin', 'same-origin-allow-popups', 'noopener-allow-popups'])(
    '陰性: COOP: %s の HTTPS のページには SEC-COOP- の項目を作らない',
    (value) => {
      expect(byPrefix(runHttps(withBase({ 'cross-origin-opener-policy': [value] })), 'SEC-COOP-')).toEqual([]);
    }
  );

  it('COEP の仕様外の値の HTTPS のページ: SEC-COEP-01 は info のまま', () => {
    const coep = byPrefix(runHttps(withBase({ 'cross-origin-embedder-policy': ['require_corp'] })), 'SEC-COEP-');
    expect(coep.length).toBe(1);
    expect(coep[0].status).toBe('info');
  });

  it.each(['require-corp', 'credentialless', 'unsafe-none'])(
    '陰性: COEP: %s の HTTPS のページには SEC-COEP- の項目を作らない',
    (value) => {
      expect(byPrefix(runHttps(withBase({ 'cross-origin-embedder-policy': [value] })), 'SEC-COEP-')).toEqual([]);
    }
  );

  it('HTTPS のページでは、どのヘッダーの組でも status が not-applicable の項目が無い', () => {
    const sets: Record<string, string[]>[] = [
      {},
      BASE_HEADERS,
      withBase(VALID_COOP_COEP),
      withBase({ 'cross-origin-opener-policy': ['unsafe-none'], 'cross-origin-embedder-policy': ['require_corp'] }),
      withBase({ 'strict-transport-security': ['max-age=31536000; includeSubDomains'] }),
    ];
    for (const headers of sets) {
      expect(runHttps(headers).some((c) => c.status === NA)).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// 3. 要確認件数・内訳・バッジの表示
// ---------------------------------------------------------------------------

describe('T07: 「対象外」は要確認件数・内訳・INFO・UNKNOWN に数えない', () => {
  const mk = (id: string, status: SecurityStatus, severity: SecurityCheckResult['severity']): SecurityCheckResult => ({
    checkId: id,
    category: 'http-headers',
    name: id,
    status,
    severity,
    observed: '-',
    description: '-',
    recommendation: '-',
    referenceUrls: [],
    scope: URL_HTTP,
  });

  it('isRequiresAttention は「対象外」に false を返す（重大度にかかわらず）', () => {
    for (const sev of ['info', 'low', 'medium', 'high', 'critical'] as const) {
      expect(isRequiresAttention(mk('SEC-COOP-01', NA, sev))).toBe(false);
    }
  });

  it('summarizeSecurityChecks: 対象外は要確認件数・CRITICAL〜LOW・INFO・UNKNOWN のどれにも入らず、notApplicable に数える', () => {
    const base = [
      mk('SEC-XFO-01', 'warning', 'medium'),
      mk('SEC-XCTO-01', 'pass', 'info'),
      mk('SEC-CORP-01', 'info', 'info'),
      mk('SEC-PERM-01', 'unknown', 'info'),
    ];
    const withNa = [...base, mk('SEC-COOP-01', NA, 'info'), mk('SEC-COEP-01', NA, 'info')];
    const a = summarizeSecurityChecks(base);
    const b = summarizeSecurityChecks(withNa);
    expect(b.requiresAttentionCount).toBe(a.requiresAttentionCount);
    for (const key of ['critical', 'high', 'medium', 'low', 'info', 'unknown'] as const) {
      expect(b.securityFindings[key] ?? 0, key).toBe(a.securityFindings[key] ?? 0);
    }
    expect(b.securityFindings.notApplicable).toBe(2);
    expect(a.securityFindings.notApplicable ?? 0).toBe(0);
  });

  it('表示: ポップアップとダッシュボードのラベルは「対象外」で、警告の色（重大度のバッジ）を使わない', () => {
    const badge = getSecurityCheckDisplayBadge({ status: NA, severity: 'info' });
    expect(badge.popupLabel).toBe('対象外');
    expect(badge.dashLabel).toBe('対象外');
    expect(['sev-critical', 'sev-high', 'sev-medium', 'sev-low']).not.toContain(badge.badgeClass);
    // severity が low 以上でも重大度のバッジにしない
    const badgeLow = getSecurityCheckDisplayBadge({ status: NA, severity: 'low' });
    expect(badgeLow.popupLabel).toBe('対象外');
    expect(['sev-critical', 'sev-high', 'sev-medium', 'sev-low']).not.toContain(badgeLow.badgeClass);
  });

  it('表記: プレーン表記と Markdown の表記は空でなく、ほかの status と区別でき、警告の太字にしない', () => {
    const others: SecurityStatus[] = ['pass', 'info', 'warning', 'fail', 'unknown'];
    const plain = formatPlainStatusCode(NA);
    const md = formatMarkdownStatusBadge(NA);
    expect(typeof plain).toBe('string');
    expect(plain.length).toBeGreaterThan(0);
    expect(md.length).toBeGreaterThan(0);
    expect(md).not.toContain('**');
    for (const s of others) {
      expect(plain).not.toBe(formatPlainStatusCode(s));
      expect(md).not.toBe(formatMarkdownStatusBadge(s));
    }
    const badge = getSecurityCheckDisplayBadge({ status: NA, severity: 'info' });
    expect(badge.statusCode).toBe(plain);
    expect(badge.markdownBadge).toBe(md);
  });
});

// ---------------------------------------------------------------------------
// 4. 調査全体（executeInspection）: HTTP / HTTPS / 未観測
// ---------------------------------------------------------------------------

describe('T07: 調査全体 — HTTP の入力で対象のチェックが対象外になり、要確認件数とバッジに入らない', () => {
  it('HTTP: COOP・COEP を返すページで SEC-COOP-01・SEC-COEP-01 が対象外になる', async () => {
    const { report } = await inspect({ url: URL_HTTP, headers: withBase(VALID_COOP_COEP) });
    expectNotApplicable(report.securityChecks, 'SEC-COOP-', URL_HTTP);
    expectNotApplicable(report.securityChecks, 'SEC-COEP-', URL_HTTP);
    // 対象外になるのは COOP・COEP だけ
    for (const c of report.securityChecks.filter((x) => x.status === NA)) {
      expect(isTargetId(c.checkId), c.checkId).toBe(true);
    }
  });

  it('HTTP: COOP・COEP の有無や値で要確認件数・内訳・バッジが変わらない', async () => {
    const none = await inspect({ url: URL_HTTP, headers: BASE_HEADERS });
    const valid = await inspect({ url: URL_HTTP, headers: withBase(VALID_COOP_COEP) });
    const invalid = await inspect({
      url: URL_HTTP,
      headers: withBase({ 'cross-origin-opener-policy': ['unsafe-none'], 'cross-origin-embedder-policy': ['require_corp'] }),
    });
    for (const r of [valid, invalid]) {
      expect(r.report.summary.requiresAttentionCount).toBe(none.report.summary.requiresAttentionCount);
      for (const key of ['critical', 'high', 'medium', 'low', 'info', 'unknown'] as const) {
        expect(r.report.summary.securityFindings[key] ?? 0, key).toBe(none.report.summary.securityFindings[key] ?? 0);
      }
      expect(r.badge).toEqual(none.badge);
    }
  });

  it('HTTP: 要確認件数は warning / fail の項目の数と一致し、INFO は pass / info の数と一致する（対象外を含めない）', async () => {
    const { report } = await inspect({ url: URL_HTTP, headers: withBase(VALID_COOP_COEP) });
    const checks = report.securityChecks;
    expect(checks.some((c) => c.status === NA)).toBe(true);
    expect(report.summary.requiresAttentionCount).toBe(checks.filter((c) => isRequiresAttention(c)).length);
    expect(report.summary.securityFindings.info).toBe(
      checks.filter((c) => c.status === 'pass' || c.status === 'info').length
    );
    expect(report.summary.securityFindings.unknown).toBe(checks.filter((c) => c.status === 'unknown').length);
    expect(report.summary.securityFindings.notApplicable).toBe(checks.filter((c) => c.status === NA).length);
  });

  it('HTTPS: 同じヘッダーでは対象外の項目が無く、COOP が無ければ SEC-COOP-01 は info（v1.8.0 と同じ）', async () => {
    const valid = await inspect({ url: URL_HTTPS, headers: withBase(VALID_COOP_COEP) });
    expect(valid.report.securityChecks.some((c) => c.status === NA)).toBe(false);
    expect(byPrefix(valid.report.securityChecks, 'SEC-COOP-')).toEqual([]);
    expect(byPrefix(valid.report.securityChecks, 'SEC-COEP-')).toEqual([]);

    const missing = await inspect({ url: URL_HTTPS, headers: BASE_HEADERS });
    expect(missing.report.securityChecks.some((c) => c.status === NA)).toBe(false);
    const coop = byPrefix(missing.report.securityChecks, 'SEC-COOP-');
    expect(coop.map((c) => c.status)).toEqual(['info']);
  });
});

describe('T07: ヘッダー未観測の入力では従来どおり unknown（対象外より unknown を優先）', () => {
  it('SEC-COOP- と SEC-COEP- は HEADER_DEPENDENT_CHECK_PREFIXES に残っている', () => {
    expect(HEADER_DEPENDENT_CHECK_PREFIXES).toContain('SEC-COOP-');
    expect(HEADER_DEPENDENT_CHECK_PREFIXES).toContain('SEC-COEP-');
  });

  it('HTTP・キャッシュなし: SEC-COOP-01 は unknown / info で、対象外の項目が無い', async () => {
    const { report } = await inspect({ url: URL_HTTP, cache: 'none' });
    const coop = byPrefix(report.securityChecks, 'SEC-COOP-');
    expect(coop.length).toBe(1);
    expect(coop[0].status).toBe('unknown');
    expect(coop[0].severity).toBe('info');
    expect(report.securityChecks.some((c) => c.status === NA)).toBe(false);
  });

  it('HTTP・別の origin のキャッシュに COOP・COEP があっても、対象外にせず unknown（または項目なし）', async () => {
    const { report } = await inspect({ url: URL_HTTP, cache: 'other-origin', headers: withBase(VALID_COOP_COEP) });
    const targets = report.securityChecks.filter((c) => isTargetId(c.checkId));
    expect(targets.length).toBeGreaterThan(0);
    for (const c of targets) {
      expect(c.status, c.checkId).toBe('unknown');
    }
    expect(report.securityChecks.some((c) => c.status === NA)).toBe(false);
  });

  it('対照: HTTP・同じ origin のキャッシュなら対象外になる（未観測のときだけ unknown）', async () => {
    const { report } = await inspect({ url: URL_HTTP, cache: 'observed', headers: withBase(VALID_COOP_COEP) });
    expect(byPrefix(report.securityChecks, 'SEC-COOP-').map((c) => c.status)).toEqual([NA]);
  });
});

// ---------------------------------------------------------------------------
// 5. エクスポート（Markdown・JSON・CSV）とレポートの整合性チェッカー
// ---------------------------------------------------------------------------

describe('T07: エクスポートでの扱い（数えない）', () => {
  it('Markdown: セキュリティ診断の表で COOP の行が対象外の表記になり、ロードマップに載らず、reports:lint が通る', async () => {
    const { report } = await inspect({ url: URL_HTTP, headers: withBase(VALID_COOP_COEP) });
    const md = generateMarkdownReport(report);
    const coop = report.securityChecks.find((c) => c.checkId === 'SEC-COOP-01')!;
    const rows = md.split('\n').filter((l) => l.startsWith('|') && l.includes(coop.name));
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.some((l) => l.includes(`| ${formatMarkdownStatusBadge(NA)} |`))).toBe(true);
    expect(rows.some((l) => l.includes('**WARN**') || l.includes('**FAIL**'))).toBe(false);

    const roadmapStart = md.indexOf('推奨対応ロードマップ');
    expect(roadmapStart).toBeGreaterThan(-1);
    const afterRoadmap = md.slice(roadmapStart);
    const nextHeading = afterRoadmap.indexOf('\n## ', 1);
    const roadmap = nextHeading > 0 ? afterRoadmap.slice(0, nextHeading) : afterRoadmap;
    expect(roadmap).not.toContain(coop.name);

    const lint = lintReportPair(report, md, { includePending: true });
    expect(lint.violations).toEqual([]);
    expect(lint.ok).toBe(true);
  });

  it('JSON: status が not-applicable のまま出力され、要確認件数は対象外を含まない', async () => {
    const { report } = await inspect({ url: URL_HTTP, headers: withBase(VALID_COOP_COEP) });
    const json = JSON.parse(exportReportToJson(report)) as InspectionReport;
    expect(json.securityChecks.find((c) => c.checkId === 'SEC-COOP-01')?.status).toBe(NA);
    expect(json.securityChecks.find((c) => c.checkId === 'SEC-COEP-01')?.status).toBe(NA);
    expect(json.summary.requiresAttentionCount).toBe(
      json.securityChecks.filter((c) => isRequiresAttention(c)).length
    );
  });

  it('CSV: SEC-COOP-01 の行に対象外であることが出る', async () => {
    const { report } = await inspect({ url: URL_HTTP, headers: withBase(VALID_COOP_COEP) });
    const csv = exportReportToCsv(report);
    const line = csv.split(/\r?\n/).find((l) => l.includes('SEC-COOP-01'));
    expect(line).toBeDefined();
    expect(line!.includes('not-applicable') || line!.includes('対象外')).toBe(true);
  });
});
