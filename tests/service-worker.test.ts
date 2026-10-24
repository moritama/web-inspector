import { describe, expect, it, vi } from 'vitest';
import { executeInspection, InspectionDependencies } from '../src/background/service-worker';
import { DomSignals, FindingException, InspectedCookieInfo } from '../src/shared/types';

describe('Service Worker 調査統合テスト (executeInspection)', () => {
  const createMockDomSignals = (overrides: Partial<DomSignals> = {}): DomSignals => ({
    url: 'https://example.com/',
    title: 'Example Domain',
    metaTags: [{ name: 'generator', content: 'WordPress 6.4.2' }],
    scriptUrls: ['https://unpkg.com/react@18.2.0/umd/react.production.min.js'],
    linkUrls: [],
    domMarkers: [],
    htmlSnippets: [],
    mixedContent: [],
    cookiesFromDocument: [],
    cssAssets: [],
    ...overrides,
  });

  const createMockDeps = (overrides: Partial<InspectionDependencies> = {}): InspectionDependencies => ({
    tab: { id: 101, url: 'https://example.com/' },
    fetchDomSignals: vi.fn().mockResolvedValue(createMockDomSignals()),
    fetchRuntimeVersions: vi.fn().mockResolvedValue({
      versions: { react: '18.2.0' },
      frameworkMarkers: ['__reactContainer$'],
    }),
    getCachedHeaders: vi.fn().mockResolvedValue({
      url: 'https://example.com/',
      headers: {
        server: ['Apache/2.4.58 (Ubuntu)'],
        'x-powered-by': ['PHP/8.2.10'],
      },
    }),
    getInspectedCookies: vi.fn().mockResolvedValue([
      {
        name: 'laravel_session',
        domain: 'example.com',
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'lax',
        session: true,
        issues: [],
      } as InspectedCookieInfo,
    ]),
    getAllFindingExceptions: vi.fn().mockResolvedValue([] as FindingException[]),
    saveReport: vi.fn().mockResolvedValue(undefined),
    updateBadge: vi.fn(),
    hasWebRequestPermission: true,
    ...overrides,
  });

  it('DOM、MAINワールドランタイム、HTTPヘッダー、Cookieを総合して例外なく完全なレポートを生成すること', async () => {
    const deps = createMockDeps();
    const report = await executeInspection(deps);

    // 基本構造の検証
    expect(report).toBeDefined();
    expect(report.url).toBe('https://example.com/');
    expect(report.hostname).toBe('example.com');
    expect(report.technologies.length).toBeGreaterThan(0);

    // React (MAINワールド実行時情報由来) の検出確認
    const reactTech = report.technologies.find((t) => t.technology === 'React');
    expect(reactTech).toBeDefined();
    expect(reactTech?.version).toBe('18.2.0');
    expect(reactTech?.detectionMethod).toBe('direct');
    expect(reactTech?.runtimeStatus).toBe('confirmed');

    // Apache (Serverヘッダー由来) の肯定検出確認
    const apacheTech = report.technologies.find((t) => t.technology === 'Apache');
    expect(apacheTech).toBeDefined();
    expect(apacheTech?.version).toBe('2.4.58');

    // PHP (X-Powered-Byヘッダー由来) の肯定検出確認
    const phpTech = report.technologies.find((t) => t.technology === 'PHP');
    expect(phpTech).toBeDefined();

    // 履歴保存とバッジ更新の呼び出し確認
    expect(deps.saveReport).toHaveBeenCalledWith(report);
    expect(deps.updateBadge).toHaveBeenCalled();
  });

  it('chrome:// などのブラウザ管理ページでは速やかに例外をスローすること', async () => {
    const deps = createMockDeps({
      tab: { id: 999, url: 'chrome://extensions' },
    });

    await expect(executeInspection(deps)).rejects.toThrow('ブラウザの内部管理ページは調査対象外です');
    expect(deps.fetchDomSignals).not.toHaveBeenCalled();
  });

  it('未定義変数の参照エラー (ReferenceError: runtimeVersions is not defined) が発生せず、安全に完了すること', async () => {
    // 過去にクラッシュしたランタイム情報渡しの回帰テスト
    const deps = createMockDeps({
      fetchRuntimeVersions: vi.fn().mockResolvedValue({
        versions: { jquery: '3.6.0', bootstrap5: '5.3.2' },
        frameworkMarkers: [],
      }),
    });

    const report = await executeInspection(deps);
    expect(report).toBeDefined();
    expect(report.summary.totalTechnologies).toBeGreaterThanOrEqual(1);
  });

  it('AngularJS 1.7.9のように修正版ありと修正版なしが混在する場合でも、移行推奨の文言が生成されること', async () => {
    // 1.7.9 では CVE-2020-7676 (fix: 1.8.0) と CVE-2022-25869 (fix: null) が併発する
    const deps = createMockDeps({
      fetchDomSignals: vi.fn().mockResolvedValue(createMockDomSignals({
        scriptUrls: ['https://ajax.googleapis.com/ajax/libs/angularjs/1.7.9/angular.min.js'],
        domMarkers: ['ng-app'],
      })),
      fetchRuntimeVersions: vi.fn().mockResolvedValue({
        versions: { angularjs: '1.7.9' },
        frameworkMarkers: [],
      }),
    });

    const report = await executeInspection(deps);
    const cveCheck = report.securityChecks.find((c) => c.checkId === 'SEC-CVE-ANGULARJS');
    expect(cveCheck).toBeDefined();
    // 1件でも修正版なしまたはEOLの場合は「移行」を含み「更新」を含まないこと
    expect(cveCheck?.recommendation).toContain('移行');
    expect(cveCheck?.recommendation).not.toContain('更新');
    expect(cveCheck?.recommendation).toContain('Angularなどへの移行');
    // CVSSフォールバック値表示の検証: 不正確な「CVSS: 6」を含まず一次情報通りの「重大度: MEDIUM」を表示すること
    expect(cveCheck?.observed).not.toContain('CVSS: 6');
    expect(cveCheck?.observed).toContain('重大度: MEDIUM');
  });
});
