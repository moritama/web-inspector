/**
 * Web Technology & Security Inspector
 * v1.8.0 T06 NEW-03a: ヘッダーの追加評価の受け入れテスト (tests/header-extras.test.ts)
 *
 * 設計メモ: docs/dev/v1.8.0/design/T06.md
 *
 * - SEC-COOP-01 / SEC-COEP-01 / SEC-CORP-01 / SEC-XXSS-01 / SEC-PERM-02 / SEC-PERM-03 / SEC-DISC-04 / SEC-DISC-05
 * - 表の各行について、発火する入力（陽性）と発火しない入力（陰性）を確かめる
 * - ヘッダー未観測なら新しいチェックはすべて unknown になり、要確認件数に入らない（SPEC-01）
 * - 新しい指摘はすべて LOW 以下（G4）
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import {
  ALLOWED_RESPONSE_HEADERS,
  executeInspection,
  filterAndSanitizeHeaders,
  HEADER_DEPENDENT_CHECK_PREFIXES,
} from '../src/background/service-worker';
import { generateMarkdownReport } from '../src/export/markdown';
import { checkHttpHeaders, SECURITY_HEADER_NAMES } from '../src/security/headers';
import { isRequiresAttention } from '../src/shared/security-status';
import { DomSignals, InspectionReport, SecurityCheckResult } from '../src/shared/types';
// @ts-expect-error -- Node ESM スクリプト (.mjs) の直接インポート
import { lintReportPair as rawLintReportPair } from '../scripts/report-lint.mjs';

const lintReportPair = rawLintReportPair as (
  report: unknown,
  markdown: string,
  options?: { includePending?: boolean }
) => { ok: boolean; violations: unknown[] };

const URL_HTTPS = 'https://headers.example.test/';

/** 指示書 T06 の表（ID → status / 重大度） */
const NEW_CHECKS = [
  { id: 'SEC-COOP-01', status: 'info', severity: 'info' },
  { id: 'SEC-COEP-01', status: 'info', severity: 'info' },
  { id: 'SEC-CORP-01', status: 'info', severity: 'info' },
  { id: 'SEC-XXSS-01', status: 'info', severity: 'info' },
  { id: 'SEC-PERM-02', status: 'warning', severity: 'low' },
  { id: 'SEC-PERM-03', status: 'info', severity: 'info' },
  { id: 'SEC-DISC-04', status: 'warning', severity: 'low' },
  { id: 'SEC-DISC-05', status: 'info', severity: 'info' },
] as const;
const NEW_IDS: readonly string[] = NEW_CHECKS.map((c) => c.id);

/** 新しいチェックのうち、1 回の調査で同時に発火させられる組（PERM-02 と PERM-03 は排他なので 2 組に分ける） */
const TRIGGER_ALL_WITH_PERM02: Record<string, string[]> = {
  'cross-origin-opener-policy': ['unsafe-none'],
  'cross-origin-embedder-policy': ['require_corp'],
  'cross-origin-resource-policy': ['same_origin'],
  'x-xss-protection': ['1; mode=block'],
  'permissions-policy': ['camera=*, microphone=()'],
  'x-aspnetmvc-version': ['5.2'],
  'server-timing': ['db;dur=53, app;dur=47.2'],
};
const TRIGGER_ALL_WITH_PERM03: Record<string, string[]> = {
  ...TRIGGER_ALL_WITH_PERM02,
  'permissions-policy': ["camera 'none'; microphone 'none'"],
};

/** 既存のヘッダーを揃えた「きれいな」基準のヘッダー（新しいチェックの陰性の土台） */
const BASE_HEADERS: Record<string, string[]> = {
  'strict-transport-security': ['max-age=31536000; includeSubDomains'],
  'content-security-policy': ["default-src 'self'; frame-ancestors 'none'"],
  'x-frame-options': ['DENY'],
  'x-content-type-options': ['nosniff'],
  'referrer-policy': ['strict-origin-when-cross-origin'],
  'permissions-policy': ['geolocation=(), camera=(), microphone=()'],
  'cross-origin-opener-policy': ['same-origin'],
};

const run = (headers: Record<string, string[]>, isHttps = true): SecurityCheckResult[] =>
  checkHttpHeaders(headers, isHttps ? URL_HTTPS : 'http://headers.example.test/', isHttps);

const withBase = (extra: Record<string, string[]>): Record<string, string[]> => ({ ...BASE_HEADERS, ...extra });

const byId = (checks: SecurityCheckResult[], id: string): SecurityCheckResult[] =>
  checks.filter((c) => c.checkId === id);

const has = (checks: SecurityCheckResult[], id: string): boolean => byId(checks, id).length > 0;

/** 表の status / 重大度どおりであることを確かめる */
function expectFires(checks: SecurityCheckResult[], id: string): SecurityCheckResult {
  const found = byId(checks, id);
  expect(found.length, `${id} が出ていません`).toBe(1);
  const spec = NEW_CHECKS.find((c) => c.id === id)!;
  expect(found[0].status).toBe(spec.status);
  expect(found[0].severity).toBe(spec.severity);
  expect(found[0].scope).toBe(URL_HTTPS);
  expect(typeof found[0].observed).toBe('string');
  expect(found[0].observed.length).toBeGreaterThan(0);
  expect(found[0].description.length).toBeGreaterThan(0);
  expect(found[0].recommendation.length).toBeGreaterThan(0);
  return found[0];
}

function emptyDom(url: string): DomSignals {
  return {
    url,
    title: 'Header extras test',
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
  headers?: Record<string, string[]>;
  /** undefined: キャッシュなし（未観測） */
  cache?: 'observed' | 'none' | 'other-origin';
}

async function inspect(opts: InspectOpts): Promise<InspectionReport> {
  const url = URL_HTTPS;
  const cache = opts.cache ?? 'observed';
  return executeInspection({
    tab: { id: 601, url },
    fetchDomSignals: vi.fn().mockResolvedValue(emptyDom(url)),
    fetchRuntimeVersions: vi.fn().mockResolvedValue({ versions: {}, frameworkMarkers: [] }),
    getCachedHeaders: vi.fn().mockResolvedValue(
      cache === 'none'
        ? undefined
        : {
            url: cache === 'other-origin' ? 'https://other.example.test/' : url,
            headers: opts.headers || {},
            observed: true,
          }
    ),
    getInspectedCookies: vi.fn().mockResolvedValue([]),
    getAllFindingExceptions: vi.fn().mockResolvedValue([]),
    saveReport: vi.fn().mockResolvedValue(undefined),
  });
}

// ---------------------------------------------------------------------------
// 表の各行: 陽性と陰性
// ---------------------------------------------------------------------------

describe('v1.8.0 T06: SEC-COOP-01 — COOP がない、または unsafe-none', () => {
  it('陽性: COOP ヘッダーがないとき info / info で出る', () => {
    const headers = { ...BASE_HEADERS };
    delete headers['cross-origin-opener-policy'];
    expectFires(run(headers), 'SEC-COOP-01');
  });

  it.each(['unsafe-none', ' unsafe-none ', 'unsafe-none; report-to="coop"'])('陽性: COOP が %j のとき出る', (value) => {
    expectFires(run(withBase({ 'cross-origin-opener-policy': [value] })), 'SEC-COOP-01');
  });

  it('陽性: 仕様にない値（ブラウザは無視して unsafe-none 扱い）のときも出る', () => {
    expectFires(run(withBase({ 'cross-origin-opener-policy': ['same-site'] })), 'SEC-COOP-01');
  });

  it.each([
    'same-origin',
    'same-origin-allow-popups',
    'noopener-allow-popups',
    'same-origin; report-to="coop"',
    ' same-origin ',
  ])('陰性: COOP が %j のとき出ない', (value) => {
    expect(has(run(withBase({ 'cross-origin-opener-policy': [value] })), 'SEC-COOP-01')).toBe(false);
  });
});

describe('v1.8.0 T06: SEC-COEP-01 — COEP の値が仕様にない（COEP は既定で推奨しない）', () => {
  it.each(['require_corp', 'same-origin', 'require-corp-typo', 'none'])('陽性: COEP が %j のとき info / info で出る', (value) => {
    expectFires(run(withBase({ 'cross-origin-embedder-policy': [value] })), 'SEC-COEP-01');
  });

  it.each(['require-corp', 'credentialless', 'unsafe-none', 'require-corp; report-to="coep"', ' credentialless '])(
    '陰性: COEP が仕様どおりの %j のとき出ない',
    (value) => {
      expect(has(run(withBase({ 'cross-origin-embedder-policy': [value] })), 'SEC-COEP-01')).toBe(false);
    }
  );

  it('陰性: COEP がないときは何も指摘しない（設定を勧める INFO / WARN を出さない）', () => {
    const checks = run(BASE_HEADERS);
    expect(has(checks, 'SEC-COEP-01')).toBe(false);
    const coepIssues = checks.filter(
      (c) => c.checkId.startsWith('SEC-COEP-') && (c.status === 'info' || c.status === 'warning' || c.status === 'fail')
    );
    expect(coepIssues).toEqual([]);
  });
});

describe('v1.8.0 T06: SEC-CORP-01 — CORP の値が仕様にない', () => {
  it.each(['same_origin', 'none', 'SAME-ORIGIN', 'same-origin; foo', 'self'])('陽性: CORP が %j のとき info / info で出る', (value) => {
    expectFires(run(withBase({ 'cross-origin-resource-policy': [value] })), 'SEC-CORP-01');
  });

  it.each(['same-origin', 'same-site', 'cross-origin', ' same-site '])('陰性: CORP が仕様どおりの %j のとき出ない', (value) => {
    expect(has(run(withBase({ 'cross-origin-resource-policy': [value] })), 'SEC-CORP-01')).toBe(false);
  });

  it('陰性: CORP がないときは出ない', () => {
    expect(has(run(BASE_HEADERS), 'SEC-CORP-01')).toBe(false);
  });
});

describe('v1.8.0 T06: SEC-XXSS-01 — X-XSS-Protection が 1 または 1; mode=block（旧式）', () => {
  it.each(['1', '1; mode=block', '1;mode=block', ' 1 ; mode=block'])('陽性: X-XSS-Protection が %j のとき info / info で出る', (value) => {
    expectFires(run(withBase({ 'x-xss-protection': [value] })), 'SEC-XXSS-01');
  });

  it.each(['0', ' 0 '])('陰性: X-XSS-Protection が %j（推奨）のとき出ない', (value) => {
    expect(has(run(withBase({ 'x-xss-protection': [value] })), 'SEC-XXSS-01')).toBe(false);
  });

  it('陰性: X-XSS-Protection がない（推奨）とき出ない', () => {
    expect(has(run(BASE_HEADERS), 'SEC-XXSS-01')).toBe(false);
  });
});

describe('v1.8.0 T06: SEC-PERM-02 — 強い権限を * で許可', () => {
  it.each(['camera', 'microphone', 'geolocation', 'payment', 'usb'])(
    '陽性: %s=* のとき warning / low で出て、項目名が Permissions-Policy、根拠に権限名がある',
    (feature) => {
      const c = expectFires(run(withBase({ 'permissions-policy': [`${feature}=*`] })), 'SEC-PERM-02');
      expect(c.name).toBe('Permissions-Policy');
      expect(`${c.observed} ${c.description}`).toContain(feature);
    }
  );

  it('陽性: inner list に * を含む camera=(*) も「すべて許可」として出る', () => {
    const c = expectFires(run(withBase({ 'permissions-policy': ['camera=(*)'] })), 'SEC-PERM-02');
    expect(`${c.observed} ${c.description}`).toContain('camera');
  });

  it('陽性: 複数の強い権限を * で許可しても 1 件にまとまり、根拠にすべての権限名がある', () => {
    const checks = run(withBase({ 'permissions-policy': ['camera=*, microphone=*, fullscreen=*'] }));
    const c = expectFires(checks, 'SEC-PERM-02');
    const text = `${c.observed} ${c.description}`;
    expect(text).toContain('camera');
    expect(text).toContain('microphone');
  });

  it('陽性: 複数行の Permissions-Policy ヘッダーのどれかで * を許可していれば出る', () => {
    expectFires(run(withBase({ 'permissions-policy': ['geolocation=()', 'usb=*'] })), 'SEC-PERM-02');
  });

  it.each([
    'camera=()',
    'camera=self',
    'camera=(self)',
    'camera=(self "https://cdn.example.test")',
    'geolocation=(self "https://*.example.test")',
    'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    'fullscreen=*',
    'picture-in-picture=*, fullscreen=(*)',
  ])('陰性: %j のとき出ない', (value) => {
    expect(has(run(withBase({ 'permissions-policy': [value] })), 'SEC-PERM-02')).toBe(false);
  });

  it('陰性: Permissions-Policy がないとき出ない（従来どおり SEC-PERM-01 が出る）', () => {
    const headers = { ...BASE_HEADERS };
    delete headers['permissions-policy'];
    const checks = run(headers);
    expect(has(checks, 'SEC-PERM-02')).toBe(false);
    expect(has(checks, 'SEC-PERM-01')).toBe(true);
  });

  it('陰性: 構文が解釈できないヘッダーでは * の許可を断定しない（SEC-PERM-02 は出ない）', () => {
    expect(has(run(withBase({ 'permissions-policy': ['camera *; microphone *'] })), 'SEC-PERM-02')).toBe(false);
  });
});

describe('v1.8.0 T06: SEC-PERM-03 — Permissions-Policy の構文が解釈できない', () => {
  it.each([
    "camera 'none'; microphone 'none'",
    'camera *; microphone *',
    'geolocation=(self',
    'geolocation=(), , camera=()',
    'geolocation=(),',
  ])('陽性: %j のとき info / info で出て、項目名が Permissions-Policy', (value) => {
    const c = expectFires(run(withBase({ 'permissions-policy': [value] })), 'SEC-PERM-03');
    expect(c.name).toBe('Permissions-Policy');
  });

  it.each([
    'geolocation=()',
    'camera=(), microphone=(), geolocation=()',
    'camera=(self "https://cdn.example.test")',
    'camera=self',
    'fullscreen=*',
    'camera=*',
    'geolocation=(self), camera=()',
  ])('陰性: 構文が正しい %j のとき出ない', (value) => {
    const checks = run(withBase({ 'permissions-policy': [value] }));
    expect(has(checks, 'SEC-PERM-03')).toBe(false);
    // ヘッダーがあるので「未設定」の SEC-PERM-01 も出ない（従来どおり）
    expect(has(checks, 'SEC-PERM-01')).toBe(false);
  });

  it('陰性: 正しい値が複数行に分かれていても出ない', () => {
    expect(has(run(withBase({ 'permissions-policy': ['camera=()', 'microphone=()'] })), 'SEC-PERM-03')).toBe(false);
  });

  it('陰性: Permissions-Policy がないとき出ない', () => {
    const headers = { ...BASE_HEADERS };
    delete headers['permissions-policy'];
    expect(has(run(headers), 'SEC-PERM-03')).toBe(false);
  });
});

describe('v1.8.0 T06: SEC-DISC-04 — X-AspNetMvc-Version がある', () => {
  it('陽性: X-AspNetMvc-Version があるとき warning / low で出て、根拠に値がある', () => {
    const c = expectFires(run(withBase({ 'x-aspnetmvc-version': ['5.2'] })), 'SEC-DISC-04');
    expect(c.category).toBe('information-disclosure');
    expect(c.observed).toContain('5.2');
  });

  it('陰性: X-AspNetMvc-Version がないとき出ない（X-AspNet-Version だけでも SEC-DISC-04 は出ない）', () => {
    expect(has(run(BASE_HEADERS), 'SEC-DISC-04')).toBe(false);
    const onlyAspNet = run(withBase({ 'x-aspnet-version': ['4.0.30319'] }));
    expect(has(onlyAspNet, 'SEC-DISC-04')).toBe(false);
    expect(has(onlyAspNet, 'SEC-DISC-03')).toBe(true);
  });
});

describe('v1.8.0 T06: SEC-DISC-05 — Server-Timing がある', () => {
  it('陽性: Server-Timing があるとき info / info で出る', () => {
    const c = expectFires(run(withBase({ 'server-timing': ['db;dur=53, app;dur=47.2'] })), 'SEC-DISC-05');
    expect(c.category).toBe('information-disclosure');
  });

  it('陰性: Server-Timing がないとき出ない', () => {
    expect(has(run(BASE_HEADERS), 'SEC-DISC-05')).toBe(false);
  });
});

describe('v1.8.0 T06: 陰性の総合 — 推奨どおりのヘッダーでは新しいチェックが 1 件も発火しない', () => {
  it('BASE_HEADERS（COOP same-origin、Permissions-Policy で権限を制限、COEP・CORP・X-XSS-Protection・Server-Timing なし）', () => {
    const checks = run(BASE_HEADERS);
    for (const id of NEW_IDS) {
      expect(has(checks, id), `${id} が誤って出ています`).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// G4: 新しい指摘はすべて LOW 以下
// ---------------------------------------------------------------------------

describe('v1.8.0 T06: G4 — 新しい指摘はすべて LOW 以下', () => {
  it.each([
    { label: 'PERM-02 を含む組', headers: TRIGGER_ALL_WITH_PERM02 },
    { label: 'PERM-03 を含む組', headers: TRIGGER_ALL_WITH_PERM03 },
  ])('$label: 新しい ID の重大度は low か info だけで、status / 重大度が表のとおり', ({ headers }) => {
    const checks = run(headers);
    const fresh = checks.filter((c) => NEW_IDS.includes(c.checkId));
    expect(fresh.length).toBeGreaterThan(0);
    for (const c of fresh) {
      expect(['low', 'info'], `${c.checkId} の重大度が LOW を超えています`).toContain(c.severity);
      const spec = NEW_CHECKS.find((s) => s.id === c.checkId)!;
      expect(c.status).toBe(spec.status);
      expect(c.severity).toBe(spec.severity);
    }
  });

  it('2 つの組で、表の 8 つの ID がすべて発火する（テストの入力の確認）', () => {
    const fired = new Set(
      [...run(TRIGGER_ALL_WITH_PERM02), ...run(TRIGGER_ALL_WITH_PERM03)].map((c) => c.checkId)
    );
    for (const id of NEW_IDS) {
      expect(fired.has(id), `${id} が発火していません`).toBe(true);
    }
  });

  it('新しい ID の項目は、1 回の診断で同じ ID が 2 件以上出ない', () => {
    for (const headers of [TRIGGER_ALL_WITH_PERM02, TRIGGER_ALL_WITH_PERM03]) {
      const checks = run(headers);
      for (const id of NEW_IDS) {
        expect(byId(checks, id).length, `${id} が重複しています`).toBeLessThanOrEqual(1);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// SPEC-01: ヘッダー未観測なら unknown、要確認件数に入らない
// ---------------------------------------------------------------------------

describe('v1.8.0 T06: SPEC-01 — 新しい ID の接頭辞が HEADER_DEPENDENT_CHECK_PREFIXES にある', () => {
  it.each(NEW_IDS.map((id) => [id]))('%s はヘッダー依存のチェックとして扱われる', (id) => {
    expect(HEADER_DEPENDENT_CHECK_PREFIXES.some((p) => id.startsWith(p))).toBe(true);
  });
});

describe('v1.8.0 T06: SPEC-01 — ヘッダー未観測の入力で新しいチェックがすべて unknown になり、要確認件数に入らない', () => {
  it('ヘッダーのキャッシュがないとき: 新しい ID の項目はすべて unknown / info、SEC-COOP-01 も unknown、要確認件数 0', async () => {
    const report = await inspect({ cache: 'none' });
    const fresh = report.securityChecks.filter((c) => NEW_IDS.includes(c.checkId));
    // COOP は「ない」ことが発火条件なので、空のヘッダーでも項目が作られ、未観測として unknown になる
    expect(fresh.some((c) => c.checkId === 'SEC-COOP-01')).toBe(true);
    for (const c of fresh) {
      expect(c.status, `${c.checkId} が unknown になっていません`).toBe('unknown');
      expect(c.severity).toBe('info');
    }
    expect(report.summary.requiresAttentionCount).toBe(0);
    expect(report.coverage?.details?.unobservedPreScan).toBe(true);
  });

  it('キャッシュの origin がタブと異なるとき（未観測扱い）: 発火条件のヘッダーがキャッシュにあっても warning にならず、要確認件数 0', async () => {
    const report = await inspect({ cache: 'other-origin', headers: TRIGGER_ALL_WITH_PERM02 });
    const fresh = report.securityChecks.filter((c) => NEW_IDS.includes(c.checkId));
    expect(fresh.length).toBeGreaterThan(0);
    for (const c of fresh) {
      expect(c.status, `${c.checkId} が unknown になっていません`).toBe('unknown');
      expect(c.severity).toBe('info');
    }
    expect(report.securityChecks.some((c) => c.checkId === 'SEC-PERM-02' && c.status === 'warning')).toBe(false);
    expect(report.securityChecks.some((c) => c.checkId === 'SEC-DISC-04' && c.status === 'warning')).toBe(false);
    expect(report.summary.requiresAttentionCount).toBe(0);
  });

  it('対照: ヘッダーを観測したときは SEC-PERM-02 と SEC-DISC-04 が warning / low で要確認件数に入る', async () => {
    const clean = await inspect({ headers: BASE_HEADERS });
    const dirty = await inspect({
      headers: withBase({ 'permissions-policy': ['camera=*'], 'x-aspnetmvc-version': ['5.2'] }),
    });
    for (const id of ['SEC-PERM-02', 'SEC-DISC-04']) {
      const c = dirty.securityChecks.find((x) => x.checkId === id);
      expect(c?.status, `${id}`).toBe('warning');
      expect(c?.severity, `${id}`).toBe('low');
    }
    const freshAttention = dirty.securityChecks.filter((c) => NEW_IDS.includes(c.checkId) && isRequiresAttention(c));
    expect(freshAttention.map((c) => c.checkId).sort()).toEqual(['SEC-DISC-04', 'SEC-PERM-02']);
    // X-AspNetMvc-Version は技術検出にも使われるため、件数は「少なくとも 2 件増える」で確かめる
    expect(dirty.summary.requiresAttentionCount).toBeGreaterThanOrEqual(clean.summary.requiresAttentionCount + 2);
    expect(dirty.summary.securityFindings.low).toBeGreaterThanOrEqual(clean.summary.securityFindings.low + 2);
  });

  it('対照: ヘッダーを観測したとき、info の新しい ID（COOP・COEP・CORP・X-XSS・Server-Timing）は要確認件数に入らない', async () => {
    const clean = await inspect({ headers: BASE_HEADERS });
    const infoOnly = await inspect({
      headers: withBase({
        'cross-origin-opener-policy': ['unsafe-none'],
        'cross-origin-embedder-policy': ['require_corp'],
        'cross-origin-resource-policy': ['same_origin'],
        'x-xss-protection': ['1; mode=block'],
        'server-timing': ['db;dur=53'],
      }),
    });
    for (const id of ['SEC-COOP-01', 'SEC-COEP-01', 'SEC-CORP-01', 'SEC-XXSS-01', 'SEC-DISC-05']) {
      expect(infoOnly.securityChecks.find((x) => x.checkId === id)?.status, id).toBe('info');
    }
    expect(infoOnly.summary.requiresAttentionCount).toBe(clean.summary.requiresAttentionCount);
  });
});

// ---------------------------------------------------------------------------
// 取得するヘッダー（G5）とレポート・仕様書との整合
// ---------------------------------------------------------------------------

describe('v1.8.0 T06: 評価に使うヘッダーが取得される（G5）', () => {
  const NEEDED = ['x-xss-protection', 'server-timing', 'x-aspnetmvc-version'];

  it.each(NEEDED)('%s が SECURITY_HEADER_NAMES と ALLOWED_RESPONSE_HEADERS にある', (h) => {
    expect(SECURITY_HEADER_NAMES).toContain(h);
    expect(ALLOWED_RESPONSE_HEADERS.has(h)).toBe(true);
  });

  it('filterAndSanitizeHeaders が評価に使うヘッダーを残し、許可されないヘッダーは捨てる', () => {
    const out = filterAndSanitizeHeaders([
      { name: 'X-XSS-Protection', value: '1; mode=block' },
      { name: 'Server-Timing', value: 'db;dur=53' },
      { name: 'X-AspNetMvc-Version', value: '5.2' },
      { name: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
      { name: 'Cross-Origin-Embedder-Policy', value: 'require-corp' },
      { name: 'Cross-Origin-Resource-Policy', value: 'same-site' },
      { name: 'Set-Cookie', value: 'sid=secret' },
    ] as chrome.webRequest.HttpHeader[]);
    expect(out['x-xss-protection']).toEqual(['1; mode=block']);
    expect(out['server-timing']).toEqual(['db;dur=53']);
    expect(out['x-aspnetmvc-version']).toEqual(['5.2']);
    expect(out['cross-origin-opener-policy']).toEqual(['same-origin']);
    expect(out['cross-origin-embedder-policy']).toEqual(['require-corp']);
    expect(out['cross-origin-resource-policy']).toEqual(['same-site']);
    expect(out['set-cookie']).toBeUndefined();
  });
});

describe('v1.8.0 T06: レポートと仕様書', () => {
  it.each([
    { label: 'PERM-02 を含む組', headers: TRIGGER_ALL_WITH_PERM02 },
    { label: 'PERM-03 を含む組', headers: TRIGGER_ALL_WITH_PERM03 },
  ])('$label: 新しい指摘を含むレポートと Markdown が整合性チェッカーを通る', async ({ headers }) => {
    const report = await inspect({ headers: withBase(headers) });
    const md = generateMarkdownReport(report);
    for (const c of report.securityChecks.filter((x) => NEW_IDS.includes(x.checkId))) {
      expect(md, `${c.checkId} の項目が Markdown にありません`).toContain(c.name);
    }
    const lint = lintReportPair(report, md, { includePending: true });
    expect(lint.violations).toEqual([]);
    expect(lint.ok).toBe(true);
  });

  it('仕様書（docs/DETECTION_SPECIFICATION.md）に新しい ID がすべて載っている', () => {
    const spec = fs.readFileSync(path.resolve(__dirname, '..', 'docs', 'DETECTION_SPECIFICATION.md'), 'utf-8');
    for (const id of NEW_IDS) {
      expect(spec.includes(id), `${id} が仕様書にありません`).toBe(true);
    }
  });
});
