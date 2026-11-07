// @vitest-environment happy-dom
/**
 * Web Technology & Security Inspector
 * ダッシュボード調査履歴機能のテスト (tests/dashboard-history.test.ts) - IMPL-01
 */

import fs from 'node:fs';
import path from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { initDashboard } from '../src/dashboard/dashboard';
import {
  renderCookiesTableHtml,
  renderFullTechnologiesHtml,
  renderHistoryListHtml,
  renderLibrarySecurityTableHtml,
  renderOverviewLibrarySecHtml,
} from '../src/dashboard/render';
import { renderCookieModalHtml, renderTechModalHtml } from '../src/popup/render';
import { DetectedTechnology, InspectionReport } from '../src/shared/types';

const createMockReport = (overrides: Partial<InspectionReport> = {}): InspectionReport => ({
  id: 'rep-001',
  url: 'https://example.com/',
  hostname: 'example.com',
  inspectedAt: '2026-10-31T09:00:00.000Z',
  extensionVersion: '1.6.6',
  rulesVersion: '1.6.6',
  technologies: [
    {
      technology: 'Nginx',
      category: 'web-server',
      detected: true,
      version: '1.24.0',
      confidence: 100,
      confidenceLevel: 'high',
      evidence: [],
      detectionMethod: 'direct',
    },
  ],
  securityChecks: [],
  cookies: [],
  mixedContent: [],
  summary: {
    totalTechnologies: 1,
    requiresAttentionCount: 0,
    securityFindings: { high: 0, medium: 0, low: 0, info: 0, unknown: 0 },
    librarySecurity: {
      eolCount: 0,
      vulnerableLibraryCount: 0,
      mismatchCount: 0,
    },
    isHttps: true,
    mixedContentCount: 0,
  },
  coverage: {
    overallStatus: 'complete',
    dom: 'complete',
    headers: 'complete',
    cookies: 'complete',
    iframes: 'complete',
    network: 'complete',
  },
  ...overrides,
});

describe('IMPL-01: 履歴一覧描画関数の単体テスト (renderHistoryListHtml)', () => {
  it('履歴が空の場合は空表示のメッセージを出力すること', () => {
    const html = renderHistoryListHtml([]);
    expect(html).toContain('保存された履歴はありません');
  });

  it('出力 HTML に onclick 等のインラインイベントハンドラが一切含まれないこと', () => {
    const reports = [createMockReport({ id: 'rep-1' }), createMockReport({ id: 'rep-2' })];
    const html = renderHistoryListHtml(reports);

    // インラインイベントハンドラ（onclick, onchange 等）が含まれていないことを検証
    expect(html).not.toMatch(/\bon(click|change|input|submit|load|error)\s*=/i);
  });

  it('表示ボタンと削除ボタンに適切なクラスと data-id 属性が付与されていること', () => {
    const reports = [createMockReport({ id: 'rep-12345' })];
    const html = renderHistoryListHtml(reports);

    expect(html).toContain('class="btn btn-secondary btn-sm history-view-btn" data-id="rep-12345"');
    expect(html).toContain('class="btn btn-danger btn-sm history-delete-btn" data-id="rep-12345"');
  });

  it('悪意のある ID やホスト名が安全にエスケープされること (XSS 防止)', () => {
    const maliciousReport = createMockReport({
      id: 'rep-xss" onmouseover="alert(1)',
      hostname: 'evil.com<script>alert(2)</script>',
    });
    const html = renderHistoryListHtml([maliciousReport]);

    expect(html).not.toContain('<script>');
    // 属性脱出されて単独の onmouseover 属性が生成されていないこと
    expect(html).not.toContain('onmouseover="alert(1)"');
    expect(html).toContain('&lt;script&gt;alert(2)&lt;/script&gt;');
    expect(html).toContain('&quot;');
    expect(html).toContain('data-id="rep-xss&quot; onmouseover=&quot;alert(1)"');

    // DOM にパースした際に、属性脱出されて別属性が生じていないこと
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = html;
    const viewBtn = tempDiv.querySelector('.history-view-btn') as HTMLButtonElement;
    expect(viewBtn).not.toBeNull();
    expect(viewBtn.getAttribute('data-id')).toBe('rep-xss" onmouseover="alert(1)');
    expect(viewBtn.hasAttribute('onmouseover')).toBe(false);
  });
});

describe('IMPL-01: ダッシュボード初期化とイベント委譲による削除・表示処理の統合テスト', () => {
  let sendMessageMock: any;

  beforeEach(() => {
    // dashboard.html 相当の DOM 要素を配置（<script>タグは除去して happy-dom のロードエラーを防止）
    const htmlPath = path.resolve(__dirname, '../dashboard.html');
    const fullHtml = fs.readFileSync(htmlPath, 'utf-8');
    const bodyMatch = fullHtml.match(/<body[^>]*>([\s\S]*)<\/body>/i);
    const bodyHtml = bodyMatch ? bodyMatch[1] : fullHtml;
    document.body.innerHTML = bodyHtml.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');

    // chrome API のモック
    sendMessageMock = vi.fn().mockImplementation((message: { type: string; id?: string }) => {
      if (message.type === 'GET_ALL_REPORTS') {
        return Promise.resolve({
          success: true,
          reports: [createMockReport({ id: 'rep-target' })],
        });
      }
      if (message.type === 'DELETE_HISTORY_ITEM') {
        return Promise.resolve({ success: true });
      }
      return Promise.resolve({ success: true });
    });

    (globalThis as any).chrome = {
      runtime: {
        getManifest: () => ({ version: '1.6.6' }),
        sendMessage: sendMessageMock,
      },
    };

    // window.confirm をモック（デフォルトは true を返す）
    window.confirm = vi.fn().mockReturnValue(true);
  });

  it('ダッシュボード初期化後に window.viewReport / deleteReport がグローバル公開されていないこと', async () => {
    await initDashboard();

    expect((window as any).viewReport).toBeUndefined();
    expect((window as any).deleteReport).toBeUndefined();
  });

  it('削除ボタンをクリックしたとき、DELETE_HISTORY_ITEM メッセージが送信されること', async () => {
    await initDashboard();

    const historyContainer = document.getElementById('historyListContainer');
    expect(historyContainer).not.toBeNull();

    const deleteBtn = historyContainer?.querySelector('.history-delete-btn') as HTMLButtonElement | null;
    expect(deleteBtn).not.toBeNull();
    expect(deleteBtn?.getAttribute('data-id')).toBe('rep-target');

    // 削除ボタンをクリック
    deleteBtn?.click();

    expect(window.confirm).toHaveBeenCalledWith('この調査レポートを削除しますか？');
    expect(sendMessageMock).toHaveBeenCalledWith({
      type: 'DELETE_HISTORY_ITEM',
      id: 'rep-target',
    });
  });

  it('ユーザーが確認ダイアログをキャンセルした場合、削除メッセージが送信されないこと', async () => {
    (window.confirm as any).mockReturnValue(false);

    await initDashboard();

    const historyContainer = document.getElementById('historyListContainer');
    const deleteBtn = historyContainer?.querySelector('.history-delete-btn') as HTMLButtonElement | null;

    // 既存の sendMessage 呼び出し履歴をクリア
    sendMessageMock.mockClear();

    deleteBtn?.click();

    expect(window.confirm).toHaveBeenCalled();
    expect(sendMessageMock).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: 'DELETE_HISTORY_ITEM' })
    );
  });

  it('表示ボタンをクリックしたとき、overviewView へ遷移すること', async () => {
    await initDashboard();

    const historyContainer = document.getElementById('historyListContainer');
    const viewBtn = historyContainer?.querySelector('.history-view-btn') as HTMLButtonElement | null;
    expect(viewBtn).not.toBeNull();

    viewBtn?.click();

    const overviewNav = document.querySelector('.nav-item[data-view="overviewView"]');
    expect(overviewNav?.classList.contains('active')).toBe(true);
  });

  it('T08 (SPEC-10): 複数バージョンがある技術は「jQuery 1.12.4 / 3.7.1（2 つのバージョン）」と表示され、展開時にインスタンスごとの結果が見られること、および instances がない v1.6.6 形式の履歴もエラーにならず表示できること', () => {
    const multiVerTech: DetectedTechnology = {
      technology: 'jQuery',
      category: 'js-css-library',
      detected: true,
      version: '1.12.4',
      confidence: 95,
      confidenceLevel: 'high',
      supportStatus: 'EOL',
      eolDate: '2016-06',
      advisories: [
        {
          id: 'CVE-2020-11022',
          title: 'XSS in jQuery',
          severity: 'medium',
          affectedRange: '< 3.5.0',
          fixedVersion: '3.5.0',
          summary: 'XSS',
          referenceUrls: [],
        },
      ],
      evidence: [
        {
          type: 'script-url',
          name: 'Script URL (jQuery)',
          value: '/js/jquery-1.12.4.min.js',
          source: 'https://example.com/',
          weight: 90,
        },
      ],
      instances: [
        {
          version: '1.12.4',
          evidence: [
            {
              type: 'script-url',
              name: 'Script URL (jQuery)',
              value: '/js/jquery-1.12.4.min.js',
              source: 'https://example.com/',
              weight: 90,
            },
          ],
          advisories: [
            {
              id: 'CVE-2020-11022',
              title: 'XSS in jQuery',
              severity: 'medium',
              affectedRange: '< 3.5.0',
              fixedVersion: '3.5.0',
              summary: 'XSS',
              referenceUrls: [],
            },
          ],
          eol: {
            status: 'EOL',
            eolDate: '2016-06',
            source: 'Internal Policy',
            recommendation: '移行推奨',
          },
          supportStatus: 'EOL',
          eolDate: '2016-06',
        },
        {
          version: '3.7.1',
          evidence: [
            {
              type: 'script-url',
              name: 'Script URL (jQuery)',
              value: '/js/jquery-3.7.1.min.js',
              source: 'https://example.com/',
              weight: 90,
            },
          ],
          advisories: [],
          eol: {
            status: 'Supported',
            eolDate: null,
            source: 'Internal Policy',
            recommendation: 'サポート継続中',
          },
          supportStatus: 'Supported',
        },
      ],
    };

    // 1. ダッシュボード技術詳細・ライブラリセキュリティ表・概要・ポップアップ詳細モーダルでの複数バージョン表示
    const fullTechHtml = renderFullTechnologiesHtml([multiVerTech]);
    expect(fullTechHtml).toContain('jQuery 1.12.4 / 3.7.1（2 つのバージョン）');
    expect(fullTechHtml).toContain('v1.12.4');
    expect(fullTechHtml).toContain('v3.7.1');
    expect(fullTechHtml).toContain('CVE-2020-11022');

    const libSecTableHtml = renderLibrarySecurityTableHtml([multiVerTech]);
    expect(libSecTableHtml).toContain('jQuery 1.12.4 / 3.7.1（2 つのバージョン）');
    expect(libSecTableHtml).toContain('v1.12.4');
    expect(libSecTableHtml).toContain('v3.7.1');

    const overviewLibHtml = renderOverviewLibrarySecHtml([multiVerTech]);
    expect(overviewLibHtml).toContain('jQuery 1.12.4 / 3.7.1（2 つのバージョン）');

    const popupModalHtml = renderTechModalHtml(multiVerTech);
    expect(popupModalHtml).toContain('1.12.4 / 3.7.1（2 つのバージョン）');
    expect(popupModalHtml).toContain('v1.12.4');
    expect(popupModalHtml).toContain('v3.7.1');

    // 2. instances フィールドが存在しない v1.6.6 形式の過去履歴データでもエラーにならず描画できること
    const legacyV166Tech: DetectedTechnology = {
      technology: 'Bootstrap',
      category: 'js-css-library',
      detected: true,
      version: '4.3.1',
      confidence: 90,
      confidenceLevel: 'high',
      evidence: [
        {
          type: 'css-url',
          name: 'Stylesheet URL',
          value: '/css/bootstrap-4.3.1.min.css',
          source: 'https://example.com/',
          weight: 90,
        },
      ],
    };

    expect(() => renderFullTechnologiesHtml([legacyV166Tech])).not.toThrow();
    expect(() => renderLibrarySecurityTableHtml([legacyV166Tech])).not.toThrow();
    expect(() => renderOverviewLibrarySecHtml([legacyV166Tech])).not.toThrow();
    expect(() => renderTechModalHtml(legacyV166Tech)).not.toThrow();
    expect(renderFullTechnologiesHtml([legacyV166Tech])).toContain('Bootstrap');
    expect(renderFullTechnologiesHtml([legacyV166Tech])).toContain('v4.3.1');
  });

  it('v1.7.1 T07: v1.7.0 形式の履歴（新しい用途を含まない・category 未設定）および新用途 (advertising / consent) や未知の用途をダッシュボードで表示できること', async () => {
    const v170HistoryReport = createMockReport({
      id: 'rep-v170-cookies',
      extensionVersion: '1.7.0',
      rulesVersion: '1.7.0',
      cookies: [
        {
          name: 'PHPSESSID',
          domain: 'legacy.example.test',
          path: '/',
          secure: true,
          httpOnly: true,
          sameSite: 'lax',
          session: true,
          category: 'authentication',
          issues: [],
        },
        {
          name: '_ga',
          domain: '.example.test',
          path: '/',
          secure: true,
          httpOnly: false,
          sameSite: 'lax',
          session: false,
          category: 'analytics',
          issues: [],
        },
        {
          // category が未設定の古い履歴エントリ
          name: 'old_cookie_without_cat',
          domain: 'legacy.example.test',
          path: '/',
          secure: true,
          httpOnly: true,
          sameSite: 'strict',
          session: false,
          issues: [],
        },
        {
          // 未知の用途値が入ったデータ
          name: 'unknown_cat_cookie',
          domain: 'legacy.example.test',
          path: '/',
          secure: false,
          httpOnly: false,
          sameSite: 'unspecified',
          session: true,
          category: 'some_unknown_category' as any,
          issues: ['Secure属性未設定'],
        },
        {
          // v1.7.1 の新用途
          name: '_fbp',
          domain: '.example.test',
          path: '/',
          secure: true,
          httpOnly: false,
          sameSite: 'lax',
          session: false,
          category: 'advertising',
          issues: [],
        },
        {
          name: 'OptanonConsent',
          domain: '.example.test',
          path: '/',
          secure: true,
          httpOnly: false,
          sameSite: 'lax',
          session: false,
          category: 'consent',
          issues: [],
        },
      ],
    });

    sendMessageMock.mockImplementation((message: { type: string }) => {
      if (message.type === 'GET_ALL_REPORTS') {
        return Promise.resolve({
          success: true,
          reports: [v170HistoryReport],
        });
      }
      return Promise.resolve({ success: true });
    });

    await initDashboard();

    const cookiesTableBody = document.getElementById('cookiesTableBody');
    expect(cookiesTableBody).not.toBeNull();
    const tableHtml = cookiesTableBody?.innerHTML || '';
    expect(tableHtml).toContain('PHPSESSID');
    expect(tableHtml).toContain('認証・セッション (authentication)');
    expect(tableHtml).toContain('トラッキング・解析 (analytics)');
    expect(tableHtml).toContain('old_cookie_without_cat');
    expect(tableHtml).toContain('unknown_cat_cookie');
    expect(tableHtml).toContain('一般・未分類 (general)');
    expect(tableHtml).toContain('広告・マーケティング (advertising)');
    expect(tableHtml).toContain('同意管理 (consent)');

    // 純粋描画関数でも例外なく描画できること
    expect(() => renderCookiesTableHtml(v170HistoryReport.cookies)).not.toThrow();
    for (const cookie of v170HistoryReport.cookies) {
      expect(() => renderCookieModalHtml(cookie)).not.toThrow();
    }
  });
});
