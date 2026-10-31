// @vitest-environment happy-dom
/**
 * Web Technology & Security Inspector
 * ダッシュボード調査履歴機能のテスト (tests/dashboard-history.test.ts) - IMPL-01
 */

import fs from 'node:fs';
import path from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { initDashboard } from '../src/dashboard/dashboard';
import { renderHistoryListHtml } from '../src/dashboard/render';
import { InspectionReport } from '../src/shared/types';

const createMockReport = (overrides: Partial<InspectionReport> = {}): InspectionReport => ({
  id: 'rep-001',
  url: 'https://example.com/',
  hostname: 'example.com',
  inspectedAt: '2026-10-31T09:00:00.000Z',
  extensionVersion: '1.6.5',
  rulesVersion: '1.6.5',
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
        getManifest: () => ({ version: '1.6.5' }),
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
});
