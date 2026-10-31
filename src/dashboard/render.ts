/**
 * Web Technology & Security Inspector
 * ダッシュボード描画純粋関数 (src/dashboard/render.ts)
 */

import { InspectionReport } from '../shared/types';

/**
 * HTML特殊文字をエスケープする
 */
export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * 調査履歴一覧のHTML文字列を生成する
 */
export function renderHistoryListHtml(reports: InspectionReport[]): string {
  if (reports.length === 0) {
    return '<div class="empty-state">保存された履歴はありません</div>';
  }

  return reports
    .map(
      (r) => `
    <div style="display:flex;align-items:center;justify-content:space-between;padding:12px;border:1px solid var(--border-color);border-radius:var(--radius-sm);margin-bottom:8px;background:var(--bg-surface);">
      <div>
        <strong>${escapeHtml(r.hostname)}</strong>
        <span style="font-size:12px;color:var(--text-muted);margin-left:8px;">${new Date(r.inspectedAt).toLocaleString('ja-JP')}</span>
        <div style="font-size:12px;color:var(--text-sub);margin-top:2px;">
          技術: ${r.technologies.length}件 / 要確認: ${r.summary.requiresAttentionCount}件 / EOL: ${r.summary.librarySecurity?.eolCount ?? 0}件 / ${r.summary.isHttps ? 'HTTPS' : 'HTTP'}
        </div>
      </div>
      <div style="display:flex;gap:6px;">
        <button class="btn btn-secondary btn-sm history-view-btn" data-id="${escapeHtml(r.id)}">表示</button>
        <button class="btn btn-danger btn-sm history-delete-btn" data-id="${escapeHtml(r.id)}">削除</button>
      </div>
    </div>
  `
    )
    .join('');
}
