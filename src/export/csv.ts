/**
 * Web Technology & Security Inspector
 * CSVエクスポート (src/export/csv.ts)
 * Excelで文字化けしないUTF-8 BOM付きCSVを生成します
 */

import { InspectionReport } from '../shared/types';

/**
 * CSVセルのエスケープ処理（カンマ、改行、ダブルクォート対応）
 */
function escapeCsv(cell: string | number | boolean | null | undefined): string {
  if (cell === null || cell === undefined) return '""';
  const str = String(cell).replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  return `"${str.replace(/"/g, '""')}"`;
}

/**
 * 調査レポートからExcel対応UTF-8 BOM付きCSVを生成する
 */
export function exportReportToCsv(report: InspectionReport): string {
  const rows: string[] = [];

  // UTF-8 BOM
  const BOM = '\uFEFF';

  // 1. ヘッダーサマリー
  rows.push(['Web Technology & Security Inspector 調査レポート'].map(escapeCsv).join(','));
  rows.push(['調査日時', report.inspectedAt].map(escapeCsv).join(','));
  rows.push(['調査対象URL', report.url].map(escapeCsv).join(','));
  rows.push(['ホスト名', report.hostname].map(escapeCsv).join(','));
  rows.push(['ツールバージョン', report.extensionVersion].map(escapeCsv).join(','));
  rows.push(['ルールバージョン', report.rulesVersion].map(escapeCsv).join(','));
  rows.push(['HTTPS利用', report.summary.isHttps ? 'はい' : 'いいえ (HTTP)'].map(escapeCsv).join(','));
  rows.push(['混在コンテンツ件数', report.summary.mixedContentCount].map(escapeCsv).join(','));
  rows.push(['要確認項目数', report.summary.requiresAttentionCount].map(escapeCsv).join(','));
  rows.push([]);

  // 2. 検出技術一覧
  rows.push(['--- 検出されたWeb技術 ---'].map(escapeCsv).join(','));
  rows.push(
    ['技術名', 'カテゴリ', 'バージョン', '確信度スコア', '確信度レベル', '判定根拠の概要', '公式サイト'].map(escapeCsv).join(',')
  );

  if (report.technologies.length === 0) {
    rows.push(['明確な固有シグナルは検出されませんでした', '', '', '', '', '', ''].map(escapeCsv).join(','));
  } else {
    for (const tech of report.technologies) {
      const evidenceSummary = tech.evidence
        .map((e) => `[${e.type}] ${e.name}: ${e.value}`)
        .join('; ');
      rows.push(
        [
          tech.technology,
          tech.category,
          tech.version || 'バージョン不明',
          tech.confidence,
          tech.confidenceLevel,
          evidenceSummary,
          tech.website || '',
        ].map(escapeCsv).join(',')
      );
    }
  }

  rows.push([]);

  // 3. セキュリティ診断結果
  rows.push(['--- セキュリティ設定診断結果 ---'].map(escapeCsv).join(','));
  rows.push(
    ['項目ID', 'カテゴリ', '診断項目名', 'ステータス', '重大度', '観測された設定', '現状・問題点の説明', '推奨対応・改善策', '参考資料URL'].map(escapeCsv).join(',')
  );

  for (const check of report.securityChecks) {
    rows.push(
      [
        check.checkId,
        check.category,
        check.name,
        check.status,
        check.severity,
        check.observed,
        check.description,
        check.recommendation,
        check.referenceUrls.join(' | '),
      ].map(escapeCsv).join(',')
    );
  }

  rows.push([]);

  // 4. Cookie属性一覧 (※値は除外)
  if (report.cookies && report.cookies.length > 0) {
    rows.push(['--- 観測されたCookie属性 (値は除外) ---'].map(escapeCsv).join(','));
    rows.push(
      ['Cookie名', 'ドメイン', 'パス', 'Secure', 'HttpOnly', 'SameSite', '種別', '検出された課題'].map(escapeCsv).join(',')
    );

    for (const c of report.cookies) {
      rows.push(
        [
          c.name,
          c.domain,
          c.path,
          c.secure ? '有効' : '未設定',
          c.httpOnly ? '有効' : '未設定',
          c.sameSite,
          c.session ? 'セッション' : '永続',
          c.issues.join('; '),
        ].map(escapeCsv).join(',')
      );
    }
  }

  return BOM + rows.join('\r\n');
}

/**
 * ブラウザ上でUTF-8 BOM付きCSVファイルをダウンロードさせる
 */
export function downloadCsvFile(report: InspectionReport, filename?: string): void {
  const csvContent = exportReportToCsv(report);
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);

  const safeHostname = report.hostname.replace(/[^a-zA-Z0-9.-]/g, '_');
  const dateStr = new Date(report.inspectedAt).toISOString().slice(0, 10);
  const name = filename || `web-inspector_${safeHostname}_${dateStr}.csv`;

  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}
