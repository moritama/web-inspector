/**
 * Web Technology & Security Inspector
 * v1.8.2 T08: ヘッダー未観測のときの再読み込みの案内と、調査上の制限事項（指示書 §6 T08「D-3 の文言」、H12・H13）
 *
 * - Partial の理由「拡張機能起動前の通信のため HTTP レスポンスヘッダーが未観測です」に
 *   「ページを再読み込みしてから、もう一度調べてください」を添える（判定と Markdown §2）
 * - ポップアップとダッシュボードの「ヘッダー未取得」の案内が、ヘッダー未観測のレポート（coverage.details.unobservedPreScan）で出る
 *   （ポップアップ 450px での見え方は E2E。設計メモの「E2E に足すケース」）
 * - Markdown §15（調査上の制限事項）に「拡張機能の更新やシークレットでの実行の許可を切り替えた後は再読み込みしてから調べる」と
 *   「ダッシュボードは通常ウィンドウで開く」を足す
 *
 * 文言は、指示書が指定した案内の句（「ページを再読み込みしてから、もう一度調べてください」）だけを一字一句で確かめ、
 * ほかは要点（語）だけを確かめる。版・件数・日付は書かない。照合は固定 DB を使う。
 */
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { executeInspection, InspectionDependencies } from '../src/background/service-worker';
import { AdvisoryDatabase, setTestAdvisoryDatabase } from '../src/detection/advisory';
import { generateMarkdownReport } from '../src/export/markdown';
import { renderHeaderUnobservedNoticeHtml } from '../src/popup/render';
import { renderFullTechnologiesHtml } from '../src/dashboard/render';
import { assessInspectionCoverage, CoverageAssessmentInputs } from '../src/shared/coverage';
import type { DomSignals, InspectionCoverage, InspectionReport } from '../src/shared/types';
import rawFixtureDb from './fixtures/advisory-db.fixture.json';

/** 指示書 §6 T08 が指定した案内の句 */
const RELOAD_GUIDANCE = 'ページを再読み込みしてから、もう一度調べてください';
/** 既存の Partial の理由（§6 T08「…未観測です」に添える。元の文は残す） */
const PRESCAN_REASON_HEAD = '拡張機能起動前の通信のため';

const baseInputs = (overrides: Partial<CoverageAssessmentInputs> = {}): CoverageAssessmentInputs => ({
  hasDom: true,
  hasHeaders: true,
  hasCookiesPermission: true,
  cookieCount: 1,
  hasWebRequestPermission: true,
  unobservedPreScan: false,
  ...overrides,
});

const reasonsOf = (cov: InspectionCoverage): string[] => cov.details?.partialReasons ?? [];

const createReport = (coverage: InspectionCoverage): InspectionReport => ({
  id: 'rep-t08',
  url: 'http://localhost.example.test/https-only-headers',
  hostname: 'localhost.example.test',
  inspectedAt: '2026-01-01T00:00:00.000Z',
  extensionVersion: '0.0.1',
  rulesVersion: '0.0.1',
  technologies: [],
  securityChecks: [],
  cookies: [],
  mixedContent: [],
  summary: {
    totalTechnologies: 0,
    requiresAttentionCount: 0,
    securityFindings: { high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
    librarySecurity: { eolCount: 0, vulnerableLibraryCount: 0, mismatchCount: 0 },
    isHttps: false,
    mixedContentCount: 0,
  },
  coverage,
});

/** Markdown の「## n.」の節を切り出す（次の「## 」の見出しの前まで） */
const sectionOf = (md: string, headingPrefix: string): string => {
  const start = md.indexOf(headingPrefix);
  if (start < 0) return '';
  const rest = md.slice(start + headingPrefix.length);
  const next = rest.search(/^## /m);
  return next >= 0 ? rest.slice(0, next) : rest;
};

/** HTML のタグを外した文字列（文言の確認用） */
const textOf = (html: string): string => html.replace(/<[^>]*>/g, '');

describe('T08: Partial の理由に再読み込みの案内が出ること（coverage.ts）', () => {
  it('陽性: ヘッダー未観測（拡張機能起動前の通信）の理由に、元の文と再読み込みの案内の両方があること', () => {
    const cov = assessInspectionCoverage(baseInputs({ hasHeaders: false, unobservedPreScan: true }));
    expect(cov.headers).toBe('partial');
    expect(cov.overallStatus).toBe('partial');
    const reason = reasonsOf(cov).find((r) => r.includes(PRESCAN_REASON_HEAD));
    expect(reason, reasonsOf(cov).join(' / ')).toBeDefined();
    expect(reason).toContain('未観測');
    expect(reason).toContain(RELOAD_GUIDANCE);
  });

  it('陽性: 案内は理由の 1 か所だけに付き、同じ理由が重複しないこと', () => {
    const cov = assessInspectionCoverage(baseInputs({ hasHeaders: false, unobservedPreScan: true }));
    const withGuidance = reasonsOf(cov).filter((r) => r.includes(RELOAD_GUIDANCE));
    expect(withGuidance.length).toBe(1);
    expect(new Set(reasonsOf(cov)).size).toBe(reasonsOf(cov).length);
  });

  it('陽性: ほかの Partial の理由（DOM の収集の失敗・ページ遷移）と同時でも、ヘッダーの理由に案内が付くこと（理由が複数のケース）', () => {
    const cov = assessInspectionCoverage(
      baseInputs({
        hasHeaders: false,
        unobservedPreScan: true,
        domCollectionPartial: true,
        domCollectionReasons: ['Content Script の収集が中断されました'],
        pageNavigatedDuringScan: true,
      })
    );
    expect(reasonsOf(cov).length).toBeGreaterThanOrEqual(3);
    const withGuidance = reasonsOf(cov).filter((r) => r.includes(RELOAD_GUIDANCE));
    expect(withGuidance.length).toBe(1);
    expect(withGuidance[0]).toContain(PRESCAN_REASON_HEAD);
  });

  it('陰性: ヘッダーを観測できた（complete）ときは、再読み込みの案内が理由に出ないこと', () => {
    const cov = assessInspectionCoverage(baseInputs());
    expect(cov.overallStatus).toBe('complete');
    expect(reasonsOf(cov).some((r) => r.includes('再読み込み'))).toBe(false);
  });

  it('陰性: ヘッダーは観測できていて DOM の収集だけが失敗したときは、再読み込みの案内を付けないこと（警告を増やしすぎない）', () => {
    const cov = assessInspectionCoverage(
      baseInputs({ domCollectionPartial: true, domCollectionReasons: ['Content Script の収集が中断されました'] })
    );
    expect(cov.overallStatus).toBe('partial');
    expect(reasonsOf(cov).some((r) => r.includes(RELOAD_GUIDANCE))).toBe(false);
  });
});

describe('T08: 調査の統括（executeInspection）でヘッダー未観測のとき、理由に案内が入ること', () => {
  beforeAll(() => {
    setTestAdvisoryDatabase(rawFixtureDb as unknown as AdvisoryDatabase);
  });

  const dom = (): DomSignals => ({
    url: 'http://app.example.test/',
    title: 'Example',
    metaTags: [],
    scriptUrls: [],
    linkUrls: [],
    domMarkers: [],
    htmlSnippets: [],
    mixedContent: [],
    cookiesFromDocument: [],
    cssAssets: [],
  });

  const deps = (getCachedHeaders: InspectionDependencies['getCachedHeaders']): InspectionDependencies => ({
    tab: { id: 808, url: 'http://app.example.test/' },
    fetchDomSignals: vi.fn().mockResolvedValue(dom()),
    fetchRuntimeVersions: vi.fn().mockResolvedValue({ versions: {}, frameworkMarkers: [] }),
    getCachedHeaders,
    getInspectedCookies: vi.fn().mockResolvedValue([]),
    getAllFindingExceptions: vi.fn().mockResolvedValue([]),
    saveReport: vi.fn().mockResolvedValue(undefined),
    updateBadge: vi.fn(),
    hasWebRequestPermission: true,
  });

  it('陽性: ヘッダーの記録が無い（拡張機能の再読み込みの後など）とき、Partial の理由に案内が入り、Markdown §2 に出ること', async () => {
    const report = await executeInspection(deps(vi.fn().mockResolvedValue(undefined)));
    expect(report.coverage?.details?.unobservedPreScan).toBe(true);
    expect(report.coverage?.overallStatus).toBe('partial');
    expect((report.coverage?.details?.partialReasons ?? []).some((r) => r.includes(RELOAD_GUIDANCE))).toBe(true);

    const sec2 = sectionOf(generateMarkdownReport(report), '## 2.');
    expect(sec2).toContain('部分的となった理由');
    expect(sec2).toContain(RELOAD_GUIDANCE);
  });

  it('陰性: ヘッダーを観測できたとき、Partial の理由にも Markdown §2 にも案内が出ないこと', async () => {
    const report = await executeInspection(
      deps(
        vi.fn().mockResolvedValue({
          url: 'http://app.example.test/',
          headers: { 'x-content-type-options': ['nosniff'] },
          observed: true,
        })
      )
    );
    expect(report.coverage?.details?.unobservedPreScan).toBe(false);
    expect((report.coverage?.details?.partialReasons ?? []).some((r) => r.includes(RELOAD_GUIDANCE))).toBe(false);
    expect(sectionOf(generateMarkdownReport(report), '## 2.')).not.toContain(RELOAD_GUIDANCE);
  });
});

describe('T08: Markdown §2 は保存済みの理由をそのまま出すこと', () => {
  it('陽性: Partial のレポートの §2 に、理由の再読み込みの案内が出ること', () => {
    const cov = assessInspectionCoverage(baseInputs({ hasHeaders: false, unobservedPreScan: true }));
    const sec2 = sectionOf(generateMarkdownReport(createReport(cov)), '## 2.');
    expect(sec2).toContain(PRESCAN_REASON_HEAD);
    expect(sec2).toContain(RELOAD_GUIDANCE);
  });

  it('陰性（互換）: 案内の無い古い理由を保存したレポートは、保存された文のまま出し、案内を作り足さないこと', () => {
    const legacy: InspectionCoverage = {
      dom: 'complete',
      headers: 'partial',
      cookies: 'complete',
      iframes: 'not-applicable',
      network: 'complete',
      overallStatus: 'partial',
      details: {
        unobservedPreScan: true,
        partialReasons: ['拡張機能起動前の通信のため HTTP レスポンスヘッダーが未観測です'],
      },
    };
    const sec2 = sectionOf(generateMarkdownReport(createReport(legacy)), '## 2.');
    expect(sec2).toContain('拡張機能起動前の通信のため HTTP レスポンスヘッダーが未観測です');
    expect(sec2).not.toContain(RELOAD_GUIDANCE);
  });
});

describe('T08: ポップアップの「ヘッダー未取得」の案内（src/popup/render.ts の renderHeaderUnobservedNoticeHtml）', () => {
  const unobserved = (): InspectionCoverage =>
    assessInspectionCoverage(baseInputs({ hasHeaders: false, unobservedPreScan: true }));

  it('陽性: ヘッダー未観測のレポートで案内が出て、再読み込みの案内の句があること', () => {
    const html = renderHeaderUnobservedNoticeHtml(unobserved());
    expect(html).not.toBe('');
    expect(textOf(html)).toContain(RELOAD_GUIDANCE);
  });

  it('陽性: E2E が探す印（class の notice-banner と header-unobserved-banner）があること', () => {
    const html = renderHeaderUnobservedNoticeHtml(unobserved());
    expect(html).toMatch(/class="[^"]*\bnotice-banner\b[^"]*"/);
    expect(html).toMatch(/class="[^"]*\bheader-unobserved-banner\b[^"]*"/);
  });

  it('陽性: 案内は 1 つだけで、インラインのイベントハンドラを使わないこと', () => {
    const html = renderHeaderUnobservedNoticeHtml(unobserved());
    expect(html.match(/header-unobserved-banner/g)?.length).toBe(1);
    expect(html).not.toMatch(/\son[a-z]+\s*=/i);
  });

  it('陰性: ヘッダーを観測できたレポート・coverage が無いレポートでは、案内を出さない（空文字）こと', () => {
    expect(renderHeaderUnobservedNoticeHtml(assessInspectionCoverage(baseInputs()))).toBe('');
    expect(renderHeaderUnobservedNoticeHtml(undefined)).toBe('');
    expect(renderHeaderUnobservedNoticeHtml(null)).toBe('');
  });

  it('陰性: DOM の収集だけが失敗した Partial では、ヘッダー未取得の案内を出さないこと', () => {
    const cov = assessInspectionCoverage(
      baseInputs({ domCollectionPartial: true, domCollectionReasons: ['Content Script の収集が中断されました'] })
    );
    expect(cov.overallStatus).toBe('partial');
    expect(renderHeaderUnobservedNoticeHtml(cov)).toBe('');
  });
});

describe('T08: ダッシュボードの「ヘッダー未取得」の案内（renderFullTechnologiesHtml）', () => {
  it('陽性: ヘッダー未観測のレポートで、技術の一覧の前に再読み込みの案内が出ること', () => {
    const cov = assessInspectionCoverage(baseInputs({ hasHeaders: false, unobservedPreScan: true }));
    const html = renderFullTechnologiesHtml([], cov);
    expect(textOf(html)).toContain('再読み込み');
  });

  it('陰性: ヘッダーを観測できたレポート・coverage の無い呼び出しでは、案内が出ないこと', () => {
    expect(textOf(renderFullTechnologiesHtml([], assessInspectionCoverage(baseInputs())))).not.toContain('再読み込み');
    expect(textOf(renderFullTechnologiesHtml([]))).not.toContain('再読み込み');
  });
});

describe('T08: Markdown §15（調査上の制限事項）に D-3 の 2 項目を足すこと', () => {
  const md = generateMarkdownReport(createReport(assessInspectionCoverage(baseInputs())));
  const sec15 = sectionOf(md, '## 15. 調査上の制限事項・免責事項');
  /** 番号付きの項目ごとに分ける（「1. **見出し:**」から次の項目の前まで） */
  const items = sec15.split(/\n(?=\d+\.\s)/).filter((s) => /^\s*\d+\.\s/.test(s));

  it('§15 が見つかり、番号付きの項目に分けられること（検査自身の確認）', () => {
    expect(sec15.length).toBeGreaterThan(0);
    expect(items.length).toBeGreaterThan(1);
  });

  it('陽性: 拡張機能の更新やシークレットでの実行の許可を切り替えた後は、ページを再読み込みしてから調べる項目があること', () => {
    const item = items.find((s) => s.includes('拡張機能の更新') && s.includes('シークレットでの実行'));
    expect(item, sec15).toBeDefined();
    expect(item).toContain('再読み込み');
  });

  it('陽性: ダッシュボードは通常ウィンドウで開く項目があること', () => {
    const item = items.find((s) => s.includes('ダッシュボード') && s.includes('通常ウィンドウ'));
    expect(item, sec15).toBeDefined();
  });

  it('陽性: 制限事項の項目は、調査の結果（complete / partial）によらず出ること', () => {
    const partialMd = generateMarkdownReport(
      createReport(assessInspectionCoverage(baseInputs({ hasHeaders: false, unobservedPreScan: true })))
    );
    const partialSec15 = sectionOf(partialMd, '## 15. 調査上の制限事項・免責事項');
    expect(partialSec15).toContain('通常ウィンドウ');
    // 既存の項目 4 に「シークレット情報」があるので、足す項目の語（シークレットでの実行）で確かめる
    expect(partialSec15).toContain('シークレットでの実行');
  });

  it('陰性: 既存の項目（受動的解析のスコープ・証明書の有効性は対象外）は残り、§16 の出典の節は §15 の後のままであること', () => {
    expect(sec15).toContain('受動的解析のスコープ');
    expect(sec15).toContain('証明書の有効性は対象外');
    expect(md.indexOf('## 15. 調査上の制限事項・免責事項')).toBeLessThan(md.indexOf('## 16.'));
  });

  it('陰性: 項目の番号が重複しないこと（足した項目の番号を既存の項目とぶつけない）', () => {
    const numbers = (sec15.match(/^\d+(?=\.\s)/gm) ?? []).map(Number);
    expect(numbers.length).toBeGreaterThan(0);
    expect(new Set(numbers).size).toBe(numbers.length);
  });
});
