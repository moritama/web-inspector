/**
 * Web Technology & Security Inspector
 * 拡張CSVエクスポート (src/export/csv.ts) - Version 1.1.0
 * Excel文字化け防止 UTF-8 BOM付き、数式インジェクション対策、Version 1.1 新規フィールド対応
 */

import { InspectionReport } from '../shared/types';

/**
 * CSVセルのエスケープ処理
 * - ダブルクォートの二重化
 * - カンマ・改行対応
 * - 数式インジェクション対策 (先頭が =, +, -, @, \t の場合にプレフィックス付与)
 */
function escapeCsv(cell: string | number | boolean | null | undefined): string {
  if (cell === null || cell === undefined) return '""';
  let str = String(cell).replace(/\r\n/g, '\n').replace(/\r/g, '\n');

  // 数式インジェクション（CSV Injection）対策
  if (/^[=+\-@\t\r]/.test(str)) {
    str = `'${str}`;
  }

  return `"${str.replace(/"/g, '""')}"`;
}

/**
 * 調査レポートからExcel対応UTF-8 BOM付きCSVを生成する (Version 1.1)
 */
export function exportReportToCsv(report: InspectionReport): string {
  const rows: string[] = [];
  const BOM = '\uFEFF';

  // 1. レポートヘッダーサマリー
  rows.push([`Web Technology & Security Inspector 調査レポート (v${report.extensionVersion || '1.2.0'})`].map(escapeCsv).join(','));
  rows.push(['調査日時', report.inspectedAt].map(escapeCsv).join(','));
  rows.push(['調査対象URL', report.url].map(escapeCsv).join(','));
  rows.push(['ホスト名', report.hostname].map(escapeCsv).join(','));
  rows.push(['ツールバージョン', report.extensionVersion || '1.2.0'].map(escapeCsv).join(','));
  rows.push(['ルールバージョン', report.rulesVersion].map(escapeCsv).join(','));
  rows.push(['脆弱性DBバージョン', report.advisoryDatabaseVersion || '2026.10'].map(escapeCsv).join(','));
  rows.push(['HTTPS利用', report.summary.isHttps ? 'はい' : 'いいえ (HTTP)'].map(escapeCsv).join(','));
  rows.push(['要確認項目数', report.summary.requiresAttentionCount].map(escapeCsv).join(','));
  rows.push(['EOL該当数', report.summary.librarySecurity?.eolCount ?? 0].map(escapeCsv).join(','));
  rows.push(['脆弱性該当数', report.summary.librarySecurity?.vulnerableLibraryCount ?? 0].map(escapeCsv).join(','));
  rows.push('');

  // 2. 検出技術・ライブラリセキュリティ一覧 (ADD-08)
  rows.push(['--- 検出技術 & ライブラリセキュリティ ---'].map(escapeCsv).join(','));
  rows.push(
    [
      '技術名',
      'カテゴリ',
      '代表バージョン',
      'バージョン検出元',
      'ディストリ版ヒント',
      '確信度スコア',
      '検出方式',
      '連動種別',
      '推論元',
      'ランタイム状態',
      'CSS側バージョン',
      'JS側バージョン',
      'バージョン整合性',
      'サポート状態 (EOL)',
      'EOL日付',
      '脆弱性照合状態',
      '該当CVE/GHSA識別子',
      '最大CVSS',
      '判定根拠の概要',
      '推奨対応',
    ].map(escapeCsv).join(',')
  );

  if (report.technologies.length === 0) {
    rows.push(['明確な固有シグナルは検出されませんでした', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', ''].map(escapeCsv).join(','));
  } else {
    for (const tech of report.technologies) {
      const evidenceSummary = tech.evidence
        .map((e) => `[${e.type}] ${e.name}: ${e.value}`)
        .join('; ');

      const advisoryIds = tech.advisories && tech.advisories.length > 0
        ? tech.advisories.map((a) => a.id).join('; ')
        : 'なし';

      const mismatchStatusText = tech.versionIntegrity
        ? tech.versionIntegrity.status === 'match'
          ? '一致'
          : tech.versionIntegrity.status === 'mismatch'
          ? '要確認 (不一致)'
          : '判定不能'
        : '-';

      const recommendation = tech.advisories && tech.advisories.length > 0
        ? `脆弱性あり: ${tech.advisories[0].fixedVersion ? `v${tech.advisories[0].fixedVersion}以上へ更新` : '更新検討'}`
        : tech.supportStatus === 'EOL'
        ? 'EOLのため移行・更新推奨'
        : '現状維持';

      const detectionMethodText = tech.isCandidateGroup || tech.detectionMethod === 'associated'
        ? '候補・関連'
        : tech.detectionMethod === 'inferred'
        ? '連動検知'
        : '直接検出';
      const implicationTypeText = tech.implicationType || '-';
      const inferredFromText = tech.inferredFrom || '-';
      const runtimeStatusText = tech.runtimeStatus === 'confirmed'
        ? '稼働確認済'
        : tech.runtimeStatus === 'possible'
        ? '稼働可能性あり'
        : tech.runtimeStatus === 'unknown'
        ? '稼働未確認'
        : tech.runtimeStatus === 'not-applicable'
        ? '該当なし'
        : '-';

      rows.push(
        [
          tech.technology,
          tech.category,
          tech.version || 'バージョン不明',
          tech.versionSource || 'pattern',
          tech.distroHint || '-',
          tech.confidence,
          detectionMethodText,
          implicationTypeText,
          inferredFromText,
          runtimeStatusText,
          tech.cssVersion || '-',
          tech.jsVersion || '-',
          mismatchStatusText,
          tech.supportStatus || 'Unknown',
          tech.eolDate || '-',
          tech.advisoryMatchStatus || 'No Data',
          advisoryIds,
          tech.maxCvss ?? '-',
          evidenceSummary,
          recommendation,
        ].map(escapeCsv).join(',')
      );
    }
  }

  rows.push('');

  // 3. HTTP・セキュリティ診断結果
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

  rows.push('');

  // 4. Cookie属性一覧
  if (report.cookies && report.cookies.length > 0) {
    rows.push(['--- 観測されたCookie属性 (値は非保持) ---'].map(escapeCsv).join(','));
    rows.push(
      ['Cookie名', 'ドメイン', 'パス', 'Secure', 'HttpOnly', 'SameSite', '種別', '検出された課題'].map(escapeCsv).join(',')
    );

    for (const c of report.cookies) {
      rows.push(
        [
          c.name,
          c.domain || '',
          c.path || '',
          c.secure ? '有効' : '未設定',
          c.httpOnly ? '有効' : '未設定',
          c.sameSite || '',
          c.session ? 'セッション' : '永続',
          (c.issues || []).join('; '),
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
