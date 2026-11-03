/**
 * Web Technology & Security Inspector
 * JSONエクスポート (src/export/json.ts)
 */

import { resolveTechAdvisoryDisplayInfo } from '../detection/advisory';
import { InspectionReport } from '../shared/types';

/**
 * 調査レポートをJSON文字列としてエクスポートする (v1.7.0 T04 / SPEC-03)
 *
 * @param report 調査レポート
 * @returns インデント整形されたJSON文字列
 */
export function exportReportToJson(report: InspectionReport): string {
  const enrichedTechnologies = (report.technologies || []).map((tech) => {
    const displayInfo = resolveTechAdvisoryDisplayInfo(tech);
    const exportMatchStatus =
      tech.advisoryMatchStatus === 'Not Affected'
        ? displayInfo.statusLabel
        : tech.advisoryMatchStatus || displayInfo.statusLabel;
    const exportOfflineStatus =
      tech.offlineMatchStatus === 'No Match'
        ? '収録 DB 上は該当なし (No Match)'
        : tech.offlineMatchStatus;

    return {
      ...tech,
      advisoryMatchStatus: exportMatchStatus,
      ...(exportOfflineStatus ? { offlineMatchStatus: exportOfflineStatus } : {}),
      productAdvisoryCount: displayInfo.count,
      productSources: displayInfo.sources,
      advisoryDataVersion: displayInfo.dataVersion,
      ...(typeof displayInfo.upstreamAdvisoriesCount === 'number'
        ? { upstreamAdvisoriesCount: displayInfo.upstreamAdvisoriesCount }
        : {}),
      advisoryStatusLabel: displayInfo.statusLabel,
    };
  });

  const exportPayload = {
    ...report,
    technologies: enrichedTechnologies,
  };

  return JSON.stringify(exportPayload, null, 2);
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
