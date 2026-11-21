/**
 * Web Technology & Security Inspector
 * v1.8.2 T05（D-2）: 通信先の内訳に Local を足す（H8）の受け入れテスト
 * (tests/connection-local-count.test.ts)
 *
 * 設計メモ: docs/dev/v1.8.2/design/T05.md
 *
 * - analyzeExternalConnections が localCount（partyType === 'local' のホスト数）を返し、
 *   総数 = First-Party + Third-Party + Local になる
 * - Markdown §9 に「Local（ローカル・IP アドレス）: N 件」、ダッシュボードに「ローカル N」
 * - localCount の無い保存済みレポート（v1.8.1 以前）でも総数と内訳が食い違わない。分からないときに 0 と表示しない
 * - report-lint の R10「総数 = First-Party + Third-Party + Local」が、合わないレポートを不合格にする
 */

import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { executeInspection, InspectionDependencies } from '../src/background/service-worker';
import { renderExternalConnectionsHtml } from '../src/dashboard/render';
import { generateMarkdownReport } from '../src/export/markdown';
import { analyzeExternalConnections } from '../src/security/domain-analyzer';
import { resolveLocalConnectionCount } from '../src/shared/connection-counts';
import { sanitizeReportUrls } from '../src/storage/history';
import type { DomSignals, ExternalConnectionItem, ExternalConnectionsAnalysis, InspectionReport } from '../src/shared/types';
import {
  CHECK_DEFINITIONS as rawCheckDefinitions,
  lintReportPair as rawLintReportPair,
  // @ts-expect-error -- Node ESM スクリプト (.mjs) の直接インポート
} from '../scripts/report-lint.mjs';

interface LintResultItem {
  id: string;
  passed: boolean;
  violations: string[];
}
const lintReportPair = rawLintReportPair as (
  report: unknown,
  markdown: string,
  options?: { includePending?: boolean }
) => { ok: boolean; results: LintResultItem[]; violations: Array<{ id: string; message: string }> };
const CHECK_DEFINITIONS = rawCheckDefinitions as Array<{ id: string; number: number; title: string; pending: boolean }>;

// 照合の DB は tests/setup/advisory-db.ts が各テストの前に固定 DB へ差し替える

const localOf = (a: ExternalConnectionsAnalysis): number => a.connections.filter((c) => c.partyType === 'local').length;

// ---------------------------------------------------------------------------
// 1. analyzeExternalConnections の localCount
// ---------------------------------------------------------------------------

describe('T05: analyzeExternalConnections が localCount を数える', () => {
  it('localhost のページ: 同じホストと LAN の IP は Local、外部は Third-Party。総数 = 内訳の合計', () => {
    const a = analyzeExternalConnections('http://localhost:3000/https-only-headers', [
      'http://localhost:3000/https-only-headers',
      'http://localhost:3000/app.js',
      'http://192.168.10.20/img.png',
      'https://cdn.example.test/lib.js',
    ]);
    expect(typeof a.localCount).toBe('number');
    expect(a.localCount).toBe(localOf(a));
    expect(a.localCount).toBeGreaterThan(0);
    expect(a.connections.find((c) => c.hostname === '192.168.10.20')?.partyType).toBe('local');
    expect(a.totalConnections).toBe(a.firstPartyCount + a.thirdPartyCount + (a.localCount as number));
  });

  it('単一の Local: HTTPS のページに IP アドレスの資源が 1 つ', () => {
    const a = analyzeExternalConnections('https://app.example.test/', [
      'https://app.example.test/',
      'https://static.example.test/a.css',
      'http://10.0.0.5/beacon.gif',
    ]);
    expect(a.localCount).toBe(1);
    expect(a.firstPartyCount).toBe(2);
    expect(a.thirdPartyCount).toBe(0);
    expect(a.totalConnections).toBe(a.firstPartyCount + a.thirdPartyCount + (a.localCount as number));
  });

  it('複数の Local: localhost・127.0.0.1・[::1]・LAN の IP が混ざる', () => {
    const a = analyzeExternalConnections('https://app.example.test/', [
      'https://app.example.test/',
      'https://cdn.other.example/lib.js',
      'http://localhost:3000/dev.js',
      'http://127.0.0.1:8080/hmr.js',
      'http://[::1]:5173/client.js',
      'http://192.168.10.20/img.png',
    ]);
    expect(a.localCount).toBe(localOf(a));
    expect(a.localCount).toBeGreaterThanOrEqual(3);
    expect(a.totalConnections).toBe(a.firstPartyCount + a.thirdPartyCount + (a.localCount as number));
  });

  it('陰性: Local が無いページでは localCount は 0（キーはある）で、既存の数え方は変わらない', () => {
    const a = analyzeExternalConnections('https://portal.example.co.jp/', [
      'https://portal.example.co.jp/',
      'https://static.example.co.jp/a.js',
      'https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js',
    ]);
    expect(a.localCount).toBe(0);
    expect(a.firstPartyCount).toBe(2);
    expect(a.thirdPartyCount).toBe(1);
    expect(a.totalConnections).toBe(3);
  });

  it('通信先が無いとき（不正な URL だけ）: 総数・内訳・localCount はすべて 0', () => {
    const a = analyzeExternalConnections('https://example.test/', ['invalid-url', '']);
    expect(a.totalConnections).toBe(0);
    expect(a.localCount).toBe(0);
  });

  it.each([
    ['http://localhost:3000/', ['http://localhost:3000/', 'https://cdn.example.test/a.js']],
    ['http://192.168.10.1:3000/', ['http://192.168.10.1:3000/', 'http://192.168.10.1:3000/a.js', 'https://cdn.example.test/a.js']],
    ['https://www.example.test/', ['https://www.example.test/', 'https://img.example.test/a.png', 'http://printer.local/x', 'https://t.example.net/x']],
  ])('不変条件: %s で 総数 = First + Third + Local', (page, urls) => {
    const a = analyzeExternalConnections(page, urls);
    expect(a.totalConnections).toBe(a.firstPartyCount + a.thirdPartyCount + (a.localCount as number));
    expect(a.localCount).toBe(localOf(a));
  });
});

// ---------------------------------------------------------------------------
// 2. resolveLocalConnectionCount（保存済みレポートとの互換）
// ---------------------------------------------------------------------------

function item(hostname: string, partyType: ExternalConnectionItem['partyType']): ExternalConnectionItem {
  return {
    hostname,
    registrableDomain: hostname,
    publicSuffix: '',
    partyType,
    category: 'other',
    resourceCount: 1,
    sampleUrls: [`http://${hostname}/`],
  };
}
const EMPTY_BREAKDOWN = { cdn: 0, analytics: 0, advertising: 0, fonts: 0, social: 0, api: 0, other: 0 };

/** v1.8.1 以前の形（localCount なし）。総数 3 = First 1 + Third 1 + Local 1 */
function legacyAnalysis(): ExternalConnectionsAnalysis {
  return {
    totalConnections: 3,
    firstPartyCount: 1,
    thirdPartyCount: 1,
    categoryBreakdown: { ...EMPTY_BREAKDOWN, other: 3 },
    connections: [item('app.example.test', 'first-party'), item('cdn.example.net', 'third-party'), item('192.168.10.20', 'local')],
  };
}

describe('T05: resolveLocalConnectionCount — 保存済みレポートの Local の件数', () => {
  it('localCount があればその値', () => {
    expect(resolveLocalConnectionCount({ ...legacyAnalysis(), localCount: 1 })).toBe(1);
    expect(resolveLocalConnectionCount({ ...legacyAnalysis(), totalConnections: 2, connections: legacyAnalysis().connections.slice(0, 2), localCount: 0 })).toBe(0);
  });

  it('localCount が無い（v1.8.1 以前）: 総数 − First − Third で求め、総数と内訳が合う', () => {
    const a = legacyAnalysis();
    const local = resolveLocalConnectionCount(a);
    expect(local).toBe(1);
    expect(a.firstPartyCount + a.thirdPartyCount + (local as number)).toBe(a.totalConnections);
  });

  it('localCount が無く、保存の上限で表（connections）が切り詰められていても、総数と内訳が合う', () => {
    // 総数 60 = First 10 + Third 40 + Local 10。表は先頭の 3 件だけ残っている
    const a: ExternalConnectionsAnalysis = { ...legacyAnalysis(), totalConnections: 60, firstPartyCount: 10, thirdPartyCount: 40 };
    const local = resolveLocalConnectionCount(a);
    expect(local).toBe(10);
  });

  it('分からないとき（数が壊れている・無い）は null を返し、0 にしない', () => {
    expect(resolveLocalConnectionCount(undefined)).toBeNull();
    expect(resolveLocalConnectionCount(null)).toBeNull();
    expect(resolveLocalConnectionCount({ ...legacyAnalysis(), firstPartyCount: 3 })).toBeNull(); // 1+... > 総数
    expect(
      resolveLocalConnectionCount({ ...legacyAnalysis(), totalConnections: undefined } as unknown as ExternalConnectionsAnalysis)
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 3. 調査全体 → Markdown §9・ダッシュボード・R10
// ---------------------------------------------------------------------------

function dom(url: string, scriptUrls: string[]): DomSignals {
  return {
    url,
    title: 'local count test',
    metaTags: [],
    scriptUrls,
    linkUrls: [],
    domMarkers: [],
    htmlSnippets: [],
    mixedContent: [],
    cookiesFromDocument: [],
    cssAssets: [],
  } as unknown as DomSignals;
}

function makeDeps(url: string, scriptUrls: string[]): InspectionDependencies {
  return {
    tab: { id: 806, url },
    fetchDomSignals: vi.fn().mockResolvedValue(dom(url, scriptUrls)),
    fetchRuntimeVersions: vi.fn().mockResolvedValue({ versions: {}, frameworkMarkers: [] }),
    getCachedHeaders: vi.fn().mockResolvedValue({ url, headers: { 'x-content-type-options': ['nosniff'] }, observed: true }),
    getInspectedCookies: vi.fn().mockResolvedValue([]),
    getAllFindingExceptions: vi.fn().mockResolvedValue([]),
    saveReport: vi.fn().mockResolvedValue(undefined),
    updateBadge: vi.fn(),
    hasWebRequestPermission: true,
  };
}

const inspect = (url: string, scriptUrls: string[]): Promise<InspectionReport> => executeInspection(makeDeps(url, scriptUrls));

const LOCALHOST_PAGE = 'http://localhost:3000/https-only-headers';
const LAN_PAGE = 'http://192.168.10.1:3000/https-only-headers';
const MIXED_PAGE = 'https://app.example.test/';
const MIXED_SCRIPTS = [
  'https://static.example.test/a.js',
  'https://cdn.other.example/lib.js',
  'http://localhost:3000/dev.js',
  'http://192.168.10.20/img.js',
];

/** Markdown §9 の本文 */
function section9(md: string): string {
  const start = md.indexOf('## 9.');
  expect(start).toBeGreaterThan(-1);
  const next = md.indexOf('\n## ', start + 1);
  return next > 0 ? md.slice(start, next) : md.slice(start);
}

function mdCount(sec: string, label: RegExp): number | null {
  const line = sec.split('\n').find((l) => label.test(l));
  if (!line) return null;
  const m = line.match(/(\d+)\s*件/);
  return m ? Number(m[1]) : null;
}
const MD_TOTAL = /総通信先ホスト数/;
const MD_FIRST = /First-Party/;
const MD_THIRD = /Third-Party/;
const MD_LOCAL = /Local（ローカル・IP アドレス）/;

/** Markdown §9 の箇条書き（表の行を除く）から件数を読む */
function mdCounts(md: string): { total: number | null; first: number | null; third: number | null; local: number | null } {
  const bullets = section9(md)
    .split('\n')
    .filter((l) => l.trim().startsWith('- '))
    .join('\n');
  return {
    total: mdCount(bullets, MD_TOTAL),
    first: mdCount(bullets, MD_FIRST),
    third: mdCount(bullets, MD_THIRD),
    local: mdCount(bullets, MD_LOCAL),
  };
}

/** ダッシュボードの集計の行（「検出ホスト数」から「推定用途別内訳」まで）をタグを除いて返す */
function dashSummary(html: string): string {
  const start = html.indexOf('検出ホスト数');
  expect(start).toBeGreaterThan(-1);
  const end = html.indexOf('推定用途別内訳', start);
  return html.slice(start, end > 0 ? end : undefined).replace(/<[^>]+>/g, '').replace(/\s+/g, ' ');
}
function dashCount(summary: string, label: string): number | null {
  const m = summary.match(new RegExp(`${label}[^0-9]*(\\d+)`));
  return m ? Number(m[1]) : null;
}

const r10 = (report: unknown, md: string): LintResultItem | undefined =>
  lintReportPair(report, md, { includePending: true }).results.find((r) => r.id === 'R10');

describe('T05: 調査全体のレポートに localCount が入る', () => {
  it.each([LOCALHOST_PAGE, LAN_PAGE])('%s: externalConnections.localCount が表の Local の数と同じで、総数 = 内訳の合計', async (url) => {
    const report = await inspect(url, ['https://cdn.example.test/lib.js']);
    const ext = report.externalConnections!;
    expect(typeof ext.localCount).toBe('number');
    expect(ext.localCount).toBe(localOf(ext));
    expect(ext.localCount).toBeGreaterThan(0);
    expect(ext.totalConnections).toBe(ext.firstPartyCount + ext.thirdPartyCount + (ext.localCount as number));
  });

  it('履歴に保存した後も localCount が残る', async () => {
    const report = await inspect(MIXED_PAGE, MIXED_SCRIPTS);
    const saved = sanitizeReportUrls(report);
    expect(saved.externalConnections?.localCount).toBe(report.externalConnections?.localCount);
  });
});

describe('T05: Markdown §9 に Local の件数を出す', () => {
  it.each([LOCALHOST_PAGE, LAN_PAGE, MIXED_PAGE])('%s: 「Local（ローカル・IP アドレス）: N 件」があり、総数 = First + Third + Local', async (url) => {
    const report = await inspect(url, url === MIXED_PAGE ? MIXED_SCRIPTS : ['https://cdn.example.test/lib.js']);
    const c = mdCounts(generateMarkdownReport(report));
    expect(c.local).toBe(report.externalConnections!.localCount);
    expect(c.total).toBe(report.externalConnections!.totalConnections);
    expect(c.total).toBe((c.first as number) + (c.third as number) + (c.local as number));
  });

  it('陰性: Local が 0 のレポートでも Local の行は 0 件で出て、合計が合う（First/Third の行は変わらない）', async () => {
    const report = await inspect('https://app.example.test/', ['https://static.example.test/a.js', 'https://cdn.other.example/b.js']);
    expect(report.externalConnections!.localCount).toBe(0);
    const c = mdCounts(generateMarkdownReport(report));
    expect(c.local).toBe(0);
    expect(c.first).toBe(report.externalConnections!.firstPartyCount);
    expect(c.third).toBe(report.externalConnections!.thirdPartyCount);
    expect(c.total).toBe((c.first as number) + (c.third as number));
  });

  it('保存済みレポート（localCount なし）: 総数と内訳の合計が食い違わない', async () => {
    const report = await inspect(MIXED_PAGE, MIXED_SCRIPTS);
    const legacy = structuredClone(report);
    delete (legacy.externalConnections as Partial<ExternalConnectionsAnalysis>).localCount;
    const c = mdCounts(generateMarkdownReport(legacy));
    expect(c.local).toBe(localOf(report.externalConnections!));
    expect(c.total).toBe((c.first as number) + (c.third as number) + (c.local as number));
  });

  it('保存済みレポートで Local が分からない（数が壊れている）: Local の行を「0 件」で出さない', async () => {
    const report = await inspect(MIXED_PAGE, MIXED_SCRIPTS);
    const broken = structuredClone(report);
    const ext = broken.externalConnections as Partial<ExternalConnectionsAnalysis>;
    delete ext.localCount;
    ext.firstPartyCount = (ext.totalConnections as number) + 1;
    const sec = section9(generateMarkdownReport(broken));
    const localLine = sec.split('\n').find((l) => MD_LOCAL.test(l) && l.trim().startsWith('- '));
    if (localLine) {
      expect(localLine).not.toMatch(/[^0-9]0\s*件/);
    }
  });

  // テストレビューへの対応: localCount の無い保存済みレポートで Local が 0（総数 = First + Third）のときは、
  // 「0 件」の行を出さず、過去の Markdown（tests/fixtures/reports/*.md）と同じ §9 にする（§4.4「Local の行を出さない」「0 と表示しない」）
  it('保存済みレポート（localCount なし）で総数 = First + Third: Local の行を出さず、First/Third/総数の行は変わらない', async () => {
    const report = await inspect('https://app.example.test/', ['https://static.example.test/a.js', 'https://cdn.other.example/b.js']);
    expect(report.externalConnections!.localCount).toBe(0);
    const legacy = structuredClone(report);
    delete (legacy.externalConnections as Partial<ExternalConnectionsAnalysis>).localCount;
    const legacyMd = generateMarkdownReport(legacy);
    const c = mdCounts(legacyMd);
    expect(c.local).toBeNull();
    expect(section9(legacyMd)).not.toMatch(MD_LOCAL);
    expect(c.first).toBe(report.externalConnections!.firstPartyCount);
    expect(c.third).toBe(report.externalConnections!.thirdPartyCount);
    expect(c.total).toBe((c.first as number) + (c.third as number));
    // 新しいレポート（localCount 0）の §9 から Local の行を除いたものと同じ
    const newSec = section9(generateMarkdownReport(report))
      .split('\n')
      .filter((l) => !(MD_LOCAL.test(l) && l.trim().startsWith('- ')))
      .join('\n');
    expect(section9(legacyMd)).toBe(newSec);
    expect(r10(legacy, legacyMd)?.passed).toBe(true);
  });
  // 対照（保存済みで Local が 1 以上なら行を出す）は「保存済みレポート（localCount なし）: 総数と内訳の合計が食い違わない」が確かめる
});

describe('T05: ダッシュボードの集計に「ローカル N」を出す', () => {
  it.each([LOCALHOST_PAGE, MIXED_PAGE])('%s: 「自社 N, 外部 N, ローカル N」の合計が検出ホスト数と一致', async (url) => {
    const report = await inspect(url, url === MIXED_PAGE ? MIXED_SCRIPTS : ['https://cdn.example.test/lib.js']);
    const s = dashSummary(renderExternalConnectionsHtml(report.externalConnections));
    const total = dashCount(s, '検出ホスト数');
    const first = dashCount(s, '自社');
    const third = dashCount(s, '外部');
    const local = dashCount(s, 'ローカル');
    expect(local).toBe(report.externalConnections!.localCount);
    expect(total).toBe(report.externalConnections!.totalConnections);
    expect(total).toBe((first as number) + (third as number) + (local as number));
  });

  it('保存済みレポート（localCount なし）: ローカルの件数を補い、合計が検出ホスト数と一致', () => {
    const s = dashSummary(renderExternalConnectionsHtml(legacyAnalysis()));
    expect(dashCount(s, 'ローカル')).toBe(1);
    expect(dashCount(s, '検出ホスト数')).toBe((dashCount(s, '自社') as number) + (dashCount(s, '外部') as number) + 1);
  });

  it('保存済みレポートで Local が分からない: 「ローカル 0」と表示しない', () => {
    const s = dashSummary(renderExternalConnectionsHtml({ ...legacyAnalysis(), firstPartyCount: 5 }));
    expect(s).not.toMatch(/ローカル[^0-9]*0(?![0-9])/);
  });

  it('保存済みレポート（localCount なし）で総数 = First + Third: 「ローカル」を出さず、合計が検出ホスト数と一致', () => {
    const a: ExternalConnectionsAnalysis = {
      ...legacyAnalysis(),
      totalConnections: 2,
      connections: legacyAnalysis().connections.slice(0, 2),
    };
    const s = dashSummary(renderExternalConnectionsHtml(a));
    expect(s).not.toMatch(/ローカル/);
    expect(dashCount(s, '検出ホスト数')).toBe((dashCount(s, '自社') as number) + (dashCount(s, '外部') as number));
  });

  it('対照: 新しいレポート（localCount 0）では「ローカル 0」を出す', () => {
    const a: ExternalConnectionsAnalysis = {
      ...legacyAnalysis(),
      totalConnections: 2,
      connections: legacyAnalysis().connections.slice(0, 2),
      localCount: 0,
    };
    expect(dashCount(dashSummary(renderExternalConnectionsHtml(a)), 'ローカル')).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// 3b. 既存の回帰用フィクスチャ（tests/fixtures/reports/。localCount なし・Local なし）
// ---------------------------------------------------------------------------

describe('T05: 回帰用フィクスチャの §9 は変わらない（テストレビューへの対応）', () => {
  const FIXTURES_DIR = path.resolve(__dirname, 'fixtures', 'reports');
  const names = fs
    .readdirSync(FIXTURES_DIR)
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.replace(/\.json$/, ''));

  it('フィクスチャがあり、どれも localCount が無く、総数 = First + Third', () => {
    expect(names.length).toBeGreaterThan(0);
    for (const name of names) {
      const report = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, `${name}.json`), 'utf8')) as InspectionReport;
      const ext = report.externalConnections;
      if (!ext) continue;
      expect(ext.localCount).toBeUndefined();
      expect(ext.totalConnections).toBe(ext.firstPartyCount + ext.thirdPartyCount);
    }
  });

  it.each(names)('%s: 生成した Markdown の §9 に Local の行が無く、保存済み .md の §9 と同じ', (name) => {
    const report = JSON.parse(fs.readFileSync(path.join(FIXTURES_DIR, `${name}.json`), 'utf8')) as InspectionReport;
    const savedMd = fs.readFileSync(path.join(FIXTURES_DIR, `${name}.md`), 'utf8');
    const generatedMd = generateMarkdownReport(report);
    if (!report.externalConnections) return;
    expect(section9(generatedMd)).not.toMatch(MD_LOCAL);
    expect(section9(generatedMd).trim()).toBe(section9(savedMd).trim());
    expect(r10(report, generatedMd)?.passed).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 4. report-lint の R10
// ---------------------------------------------------------------------------

describe('T05: report-lint R10「総数 = First-Party + Third-Party + Local」', () => {
  it('R10 が検査項目にあり、既定で有効', () => {
    const def = CHECK_DEFINITIONS.find((d) => d.id === 'R10');
    expect(def).toBeDefined();
    expect(def!.pending).toBe(false);
    expect(def!.title).toMatch(/Local/);
  });

  it.each([LOCALHOST_PAGE, LAN_PAGE, MIXED_PAGE])('陰性（合格）: %s の調査結果と、その Markdown は R10 に合格', async (url) => {
    const report = await inspect(url, url === MIXED_PAGE ? MIXED_SCRIPTS : ['https://cdn.example.test/lib.js']);
    const res = r10(report, generateMarkdownReport(report));
    expect(res?.violations).toEqual([]);
    expect(res?.passed).toBe(true);
  });

  it('陽性（不合格）: JSON の localCount が総数と合わない', async () => {
    const report = await inspect(MIXED_PAGE, MIXED_SCRIPTS);
    const md = generateMarkdownReport(report);
    const bad = structuredClone(report);
    bad.externalConnections!.localCount = (bad.externalConnections!.localCount as number) + 1;
    expect(r10(bad, md)?.passed).toBe(false);
  });

  it('陽性（不合格）: v1.8.1 の不具合の形 — Local があるのに総数 ≠ First + Third + Local（localCount 0）', async () => {
    const report = await inspect(LOCALHOST_PAGE, ['https://cdn.example.test/lib.js']);
    const bad = structuredClone(report);
    bad.externalConnections!.localCount = 0;
    expect(r10(bad, generateMarkdownReport(report))?.passed).toBe(false);
  });

  it('陽性（不合格）: Markdown の Local の件数を書き換えると合計が合わない', async () => {
    const report = await inspect(MIXED_PAGE, MIXED_SCRIPTS);
    const md = generateMarkdownReport(report);
    const n = report.externalConnections!.localCount as number;
    const lines = md.split('\n');
    const idx = lines.findIndex((l) => MD_LOCAL.test(l) && l.trim().startsWith('- '));
    expect(idx).toBeGreaterThan(-1);
    lines[idx] = lines[idx].replace(new RegExp(`${n}(\\s*件)`), `${n + 5}$1`);
    expect(r10(report, lines.join('\n'))?.passed).toBe(false);
  });

  it('陽性（不合格）: localCount のある新しいレポートの Markdown に Local の行が無い', async () => {
    const report = await inspect(MIXED_PAGE, MIXED_SCRIPTS);
    const md = generateMarkdownReport(report)
      .split('\n')
      .filter((l) => !(MD_LOCAL.test(l) && l.trim().startsWith('- ')))
      .join('\n');
    expect(r10(report, md)?.passed).toBe(false);
  });

  it('陰性（合格）: 保存済みレポート（localCount なし）を今の版で書き出した Markdown', async () => {
    const report = await inspect(MIXED_PAGE, MIXED_SCRIPTS);
    const legacy = structuredClone(report);
    delete (legacy.externalConnections as Partial<ExternalConnectionsAnalysis>).localCount;
    expect(r10(legacy, generateMarkdownReport(legacy))?.passed).toBe(true);
  });

  it('陰性（合格）: 保存済みレポート（localCount なし）と、Local の行の無い過去の Markdown の組', async () => {
    const report = await inspect('https://app.example.test/', ['https://static.example.test/a.js', 'https://cdn.other.example/b.js']);
    const legacy = structuredClone(report);
    delete (legacy.externalConnections as Partial<ExternalConnectionsAnalysis>).localCount;
    const oldMd = generateMarkdownReport(report)
      .split('\n')
      .filter((l) => !(MD_LOCAL.test(l) && l.trim().startsWith('- ')))
      .join('\n');
    expect(r10(legacy, oldMd)?.passed).toBe(true);
  });

  it('陽性（不合格）: localCount が無く、First + Third が総数を超える（数が壊れている）', async () => {
    const report = await inspect(MIXED_PAGE, MIXED_SCRIPTS);
    const md = generateMarkdownReport(report);
    const broken = structuredClone(report);
    const ext = broken.externalConnections as Partial<ExternalConnectionsAnalysis>;
    delete ext.localCount;
    ext.thirdPartyCount = (ext.totalConnections as number) + 1;
    expect(r10(broken, md)?.passed).toBe(false);
  });

  it('陰性（合格）: externalConnections の無いレポートは R10 で落とさない', async () => {
    const report = await inspect(MIXED_PAGE, MIXED_SCRIPTS);
    const none = structuredClone(report);
    delete (none as Partial<InspectionReport>).externalConnections;
    const res = r10(none, '');
    expect(res?.passed).toBe(true);
  });
});
