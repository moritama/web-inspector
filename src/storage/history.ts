/**
 * Web Technology & Security Inspector
 * 調査履歴ストレージ管理 (src/storage/history.ts)
 */

import { HistoryEntrySummary, InspectionReport } from '../shared/types';

const STORAGE_KEY_HISTORY = 'web_inspector_history';
const DEFAULT_MAX_HISTORY = 50;

/**
 * 調査レポートを履歴に保存する
 *
 * @param report 調査レポート
 * @param maxEntries 保持する最大件数
 */
export async function saveReportToHistory(
  report: InspectionReport,
  maxEntries = DEFAULT_MAX_HISTORY
): Promise<void> {
  const history = await getAllHistoryReports();
  // 既存の同一URLの最新調査があれば先頭に追加し、重複を整理
  const updated = [report, ...history.filter((h) => h.id !== report.id)].slice(0, maxEntries);

  await chrome.storage.local.set({ [STORAGE_KEY_HISTORY]: updated });
}

/**
 * 保存されているすべての調査レポートを取得する
 */
export async function getAllHistoryReports(): Promise<InspectionReport[]> {
  const data = await chrome.storage.local.get(STORAGE_KEY_HISTORY);
  return (data[STORAGE_KEY_HISTORY] as InspectionReport[]) || [];
}

/**
 * 履歴一覧用のサマリーリストを取得する
 */
export async function getHistorySummaries(): Promise<HistoryEntrySummary[]> {
  const reports = await getAllHistoryReports();
  return reports.map((r) => ({
    id: r.id,
    url: r.url,
    hostname: r.hostname,
    inspectedAt: r.inspectedAt,
    technologyCount: r.technologies.length,
    requiresAttentionCount: r.summary.requiresAttentionCount,
    isHttps: r.summary.isHttps,
  }));
}

/**
 * 指定したIDの調査レポートを取得する
 */
export async function getReportById(id: string): Promise<InspectionReport | null> {
  const reports = await getAllHistoryReports();
  return reports.find((r) => r.id === id) || null;
}

/**
 * 指定したIDの履歴を削除する
 */
export async function deleteReportById(id: string): Promise<void> {
  const reports = await getAllHistoryReports();
  const filtered = reports.filter((r) => r.id !== id);
  await chrome.storage.local.set({ [STORAGE_KEY_HISTORY]: filtered });
}

/**
 * すべての調査履歴をクリアする
 */
export async function clearAllHistory(): Promise<void> {
  await chrome.storage.local.remove(STORAGE_KEY_HISTORY);
}

export { compareReportsEnhanced } from './diff';
import { compareReportsEnhanced } from './diff';

/**
 * 2つの調査結果レポートを比較する（差分比較Diff）
 */
export interface ReportComparison {
  reportA: InspectionReport;
  reportB: InspectionReport;
  addedTechnologies: string[];
  removedTechnologies: string[];
  versionChanges: Array<{ technology: string; before: string | null; after: string | null }>;
  newSecurityIssues: string[];
  resolvedSecurityIssues: string[];
}

export function compareReports(
  reportA: InspectionReport, // 古い方
  reportB: InspectionReport  // 新しい方
): ReportComparison {
  return compareReportsEnhanced(reportA, reportB);
}
