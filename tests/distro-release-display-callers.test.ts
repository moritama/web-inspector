/**
 * v1.8.1 T06 受け入れ条件 5: 4 つの出力経路（popup・dashboard・markdown・csv）が、リリースの表示名を共通の関数で作っている
 *
 * src/shared/distro-display の formatDistroReleaseDisplay を目印の文字列を返す関数に差し替え、
 * 4 つの出力のどれにもその目印が出ることを確かめる（自前で表示名を作っていれば目印は出ない）。
 * 差し替えはこのファイルの中だけで効く（vi.mock）。関数そのものの振る舞いは tests/distro-release-display.test.ts で確かめる。
 */
import { describe, expect, it, vi } from 'vitest';

const SENTINEL = 'ReleaseDisplaySentinelForT06';

vi.mock('../src/shared/distro-display', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/shared/distro-display')>();
  return { ...actual, formatDistroReleaseDisplay: vi.fn(() => SENTINEL) };
});

import { executeInspection, InspectionDependencies } from '../src/background/service-worker';
import { exportReportToCsv } from '../src/export/csv';
import { generateMarkdownReport } from '../src/export/markdown';
import { renderFullTechnologiesHtml } from '../src/dashboard/render';
import { renderTechModalHtml } from '../src/popup/render';
import { formatDistroReleaseDisplay } from '../src/shared/distro-display';
import type { DetectedTechnology, DomSignals, InspectionReport } from '../src/shared/types';

const HOST = 'https://www.example.test/';

const emptyDom = (): DomSignals => ({
  url: HOST,
  title: 'Release display callers test',
  metaTags: [],
  scriptUrls: ['https://www.example.test/assets/app.js'],
  linkUrls: [],
  domMarkers: [],
  htmlSnippets: [],
  mixedContent: [],
  cookiesFromDocument: [],
  cssAssets: [],
});

function deps(headers: Record<string, string[]>): InspectionDependencies {
  return {
    tab: { id: 7, url: HOST },
    fetchDomSignals: vi.fn().mockResolvedValue(emptyDom()),
    fetchRuntimeVersions: vi.fn().mockResolvedValue({ versions: {}, frameworkMarkers: [] }),
    getCachedHeaders: vi.fn().mockResolvedValue({ url: HOST, headers }),
    getInspectedCookies: vi.fn().mockResolvedValue([]),
    getAllFindingExceptions: vi.fn().mockResolvedValue([]),
    saveReport: vi.fn().mockResolvedValue(undefined),
    updateBadge: vi.fn(),
    hasWebRequestPermission: true,
  };
}

async function inferredReport(): Promise<{ report: InspectionReport; apache: DetectedTechnology }> {
  const report = await executeInspection(deps({ server: ['Apache/2.4.41 (Ubuntu)'] }));
  const apache = report.technologies.find((t) => t.technology === 'Apache');
  if (!apache?.distroInference) throw new Error('前提: Apache に distroInference が付いていない');
  return { report, apache };
}

describe('T06: 4 つの出力経路がリリースの表示名を共通の関数で作る', () => {
  it('前提: 差し替えた関数が目印を返す', () => {
    expect(formatDistroReleaseDisplay({})).toBe(SENTINEL);
  });

  it('ポップアップの技術の詳細（renderTechModalHtml）', async () => {
    const { apache } = await inferredReport();
    expect(renderTechModalHtml(apache)).toContain(SENTINEL);
  });

  it('ダッシュボードの技術一覧（renderFullTechnologiesHtml）', async () => {
    const { apache } = await inferredReport();
    expect(renderFullTechnologiesHtml([apache])).toContain(SENTINEL);
  });

  it('Markdown レポート（generateMarkdownReport）', async () => {
    const { report } = await inferredReport();
    expect(generateMarkdownReport(report)).toContain(SENTINEL);
  });

  it('CSV エクスポート（exportReportToCsv）', async () => {
    const { report } = await inferredReport();
    expect(exportReportToCsv(report)).toContain(SENTINEL);
  });
});
