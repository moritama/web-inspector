/**
 * Web Technology & Security Inspector
 * 拡張差分比較・原因分析エンジン (src/storage/diff.ts) - IMP-09
 * 
 * 過去の調査レポートと現在の調査レポートを比較し、
 * 変化の種別（Added, Removed, Changed, Resolved, Regressed）および
 * 変化の推定原因（Site Change, Advisory Update, Inspection Difference等）を体系的に分類します。
 */

import {
  DetailedDiffItem,
  DiffCause,
  DiffType,
  EnhancedReportComparison,
  InspectionReport,
} from '../shared/types';

/**
 * 2つの調査結果レポートを比較し、詳細な差分と推定原因を分析する (Rev.2.1 IMP-09)
 *
 * @param reportA 比較元のレポート（過去の調査結果）
 * @param reportB 比較対象のレポート（新しい調査結果）
 * @returns EnhancedReportComparison
 */
export function compareReportsEnhanced(
  reportA: InspectionReport,
  reportB: InspectionReport
): EnhancedReportComparison {
  const diffItems: DetailedDiffItem[] = [];

  // 1. 調査完全性・スコープの違いチェック (Inspection Difference)
  const coverageDifference = isCoverageDifferent(reportA, reportB);

  // 2. 技術スタック & バージョン差分の分析
  const techMapA = new Map(reportA.technologies.map((t) => [t.technology, t]));
  const techMapB = new Map(reportB.technologies.map((t) => [t.technology, t]));

  // 新規検出された技術 (Added)
  for (const [name, tB] of techMapB) {
    if (!techMapA.has(name)) {
      diffItems.push({
        id: `tech:add:${name}`,
        category: 'technology',
        target: name,
        diffType: 'Added',
        diffCause: coverageDifference ? 'unknown' : 'site-change',
        causeExplanation: coverageDifference
          ? '調査範囲の違い、またはサイト側の技術追加による可能性があります。'
          : `サイト側で ${name} (${tB.version ? `v${tB.version}` : 'バージョン不明'}) が新たに導入されました。`,
        before: null,
        after: tB.version ? `v${tB.version}` : '検出',
      });
    }
  }

  // 消失した技術 (Removed)
  for (const [name, tA] of techMapA) {
    if (!techMapB.has(name)) {
      diffItems.push({
        id: `tech:rem:${name}`,
        category: 'technology',
        target: name,
        diffType: 'Removed',
        diffCause: coverageDifference ? 'inspection-difference' : 'site-change',
        causeExplanation: coverageDifference
          ? '調査権限または取得対象範囲の違いにより検出されなかった可能性があります。'
          : `サイト側で ${name} の使用が停止または別技術へ移行されました。`,
        before: tA.version ? `v${tA.version}` : '検出',
        after: null,
      });
    }
  }

  // バージョン変化 (Changed) および 脆弱性DB更新要因 (Advisory Update) の分析
  for (const [name, tB] of techMapB) {
    const tA = techMapA.get(name);
    if (!tA) continue;

    // バージョン番号の変化
    if (tA.version !== tB.version) {
      diffItems.push({
        id: `tech:ver:${name}`,
        category: 'technology',
        target: name,
        diffType: 'Changed',
        diffCause: 'site-change',
        causeExplanation: `サイト側でバージョンが ${tA.version || '不明'} から ${tB.version || '不明'} へ更新されました。`,
        before: tA.version || '不明',
        after: tB.version || '不明',
      });
    } else {
      // バージョンは不変だが、既知脆弱性 (CVE) の該当件数が変化した場合
      const advCountA = tA.advisories?.length ?? 0;
      const advCountB = tB.advisories?.length ?? 0;
      if (advCountA !== advCountB) {
        const isIncreased = advCountB > advCountA;
        diffItems.push({
          id: `advisory:${name}`,
          category: 'security',
          target: `${name} 既知脆弱性情報`,
          diffType: isIncreased ? 'Regressed' : 'Resolved',
          diffCause: 'advisory-update',
          causeExplanation: `サイトのバージョンは不変ですが、オフライン脆弱性DBの更新により該当アドバイザリが ${advCountA}件 から ${advCountB}件 へ変化しました。`,
          before: `${advCountA} 件`,
          after: `${advCountB} 件`,
        });
      }
    }
  }

  // 3. セキュリティ診断項目の変化 (Resolved / Regressed)
  const checkMapA = new Map(reportA.securityChecks.map((c) => [c.checkId || c.name, c]));
  const checkMapB = new Map(reportB.securityChecks.map((c) => [c.checkId || c.name, c]));

  for (const [id, cB] of checkMapB) {
    const cA = checkMapA.get(id);
    if (!cA) continue;

    const isIssueA = cA.status === 'warning' || cA.status === 'fail';
    const isIssueB = cB.status === 'warning' || cB.status === 'fail';

    if (!isIssueA && isIssueB) {
      // 新たに警告・不備が検出された (Regressed)
      diffItems.push({
        id: `sec:reg:${id}`,
        category: 'security',
        target: cB.name,
        diffType: 'Regressed',
        diffCause: coverageDifference ? 'unknown' : 'site-change',
        causeExplanation: coverageDifference
          ? '調査範囲の違い、またはサイト設定の変更により警告が検出されました。'
          : `サイトの設定変更またはヘッダーの変更により、新たに指摘項目が発生しました。`,
        before: cA.observed,
        after: cB.observed,
      });
    } else if (isIssueA && !isIssueB) {
      // 以前の警告が解消された (Resolved)
      diffItems.push({
        id: `sec:res:${id}`,
        category: 'security',
        target: cB.name,
        diffType: 'Resolved',
        diffCause: 'site-change',
        causeExplanation: `セキュリティヘッダーまたは属性設定が修正され、問題が解消されました。`,
        before: cA.observed,
        after: cB.observed,
      });
    }
  }

  // 4. サマリー集計
  let addedCount = 0;
  let removedCount = 0;
  let changedCount = 0;
  let resolvedCount = 0;
  let regressedCount = 0;
  const causes: Record<DiffCause, number> = {
    'site-change': 0,
    'advisory-update': 0,
    'rule-update': 0,
    'inspection-difference': 0,
    'unknown': 0,
  };

  for (const item of diffItems) {
    if (item.diffType === 'Added') addedCount++;
    else if (item.diffType === 'Removed') removedCount++;
    else if (item.diffType === 'Changed') changedCount++;
    else if (item.diffType === 'Resolved') resolvedCount++;
    else if (item.diffType === 'Regressed') regressedCount++;

    causes[item.diffCause] = (causes[item.diffCause] || 0) + 1;
  }

  // 後方互換フィールドの作成
  const techsA = new Set(reportA.technologies.map((t) => t.technology));
  const techsB = new Set(reportB.technologies.map((t) => t.technology));
  const addedTechnologies = Array.from(techsB).filter((t) => !techsA.has(t));
  const removedTechnologies = Array.from(techsA).filter((t) => !techsB.has(t));

  const versionChanges: Array<{ technology: string; before: string | null; after: string | null }> = [];
  for (const tB of reportB.technologies) {
    const tA = techMapA.get(tB.technology);
    if (tA && tA.version !== tB.version) {
      versionChanges.push({
        technology: tB.technology,
        before: tA.version,
        after: tB.version,
      });
    }
  }

  const issuesA = new Set(
    reportA.securityChecks.filter((c) => c.status === 'warning' || c.status === 'fail').map((c) => c.name)
  );
  const issuesB = new Set(
    reportB.securityChecks.filter((c) => c.status === 'warning' || c.status === 'fail').map((c) => c.name)
  );
  const newSecurityIssues = Array.from(issuesB).filter((name) => !issuesA.has(name));
  const resolvedSecurityIssues = Array.from(issuesA).filter((name) => !issuesB.has(name));

  return {
    reportA,
    reportB,
    diffItems,
    summary: {
      addedCount,
      removedCount,
      changedCount,
      resolvedCount,
      regressedCount,
      causes,
    },
    addedTechnologies,
    removedTechnologies,
    versionChanges,
    newSecurityIssues,
    resolvedSecurityIssues,
  };
}

/**
 * 2つのレポート間で調査完全性（Coverage）や収集状態に有意な差があるか判定
 */
function isCoverageDifferent(reportA: InspectionReport, reportB: InspectionReport): boolean {
  if (reportA.coverage?.completeness !== reportB.coverage?.completeness) {
    return true;
  }
  // DOM取得の有無の違い
  if (reportA.coverage?.sources?.dom !== reportB.coverage?.sources?.dom) {
    return true;
  }
  return false;
}
