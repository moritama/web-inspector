/**
 * Web Technology & Security Inspector
 * JSONエクスポート (src/export/json.ts)
 */

import { InspectionReport } from '../shared/types';

/**
 * 調査レポートをJSON文字列としてエクスポートする
 *
 * @param report 調査レポート
 * @returns インデント整形されたJSON文字列
 */
export function exportReportToJson(report: InspectionReport): string {
  return JSON.stringify(report, null, 2);
}

/**
 * ブラウザ上でJSONファイルをダウンロードさせる
 */
export function downloadJsonFile(report: InspectionReport, filename?: string): void {
  const jsonContent = exportReportToJson(report);
  const blob = new Blob([jsonContent], { type: 'application/json;charset=utf-8' });
  const url = URL.createObjectURL(blob);

  const safeHostname = report.hostname.replace(/[^a-zA-Z0-9.-]/g, '_');
  const dateStr = new Date(report.inspectedAt).toISOString().slice(0, 10);
  const name = filename || `web-inspector_${safeHostname}_${dateStr}.json`;

  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
