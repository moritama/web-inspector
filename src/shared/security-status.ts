/**
 * Web Technology & Security Inspector
 * セキュリティ診断のステータス表示・件数集計ルール共通定義 (src/shared/security-status.ts) - v1.7.1 T01
 *
 * 「要確認」「重大度の内訳（CRITICAL〜LOW）」「INFO行」「表のステータス表示」のルールを1箇所に集約し、
 * バックグラウンド集計・Markdown出力・CSV出力・ポップアップ・ダッシュボード間で整合性を保証します。
 */

import { InspectionReport, SecurityCheckResult, SecurityStatus } from './types';

/**
 * セキュリティ診断項目が許容・除外設定によってアクティブな警告対象から除外されているか判定する
 */
export function isFindingExcludedByException(
  check: Pick<SecurityCheckResult, 'exceptionStatus'>
): boolean {
  return (
    check.exceptionStatus === 'accepted' ||
    check.exceptionStatus === 'false-positive' ||
    check.exceptionStatus === 'muted'
  );
}

/**
 * セキュリティ診断項目が「要確認」に該当するか判定する
 * - status が 'warning' または 'fail' であり、かつ例外設定で除外されていない項目のみ true
 */
export function isRequiresAttention(
  check: Pick<SecurityCheckResult, 'status' | 'exceptionStatus'>
): boolean {
  const isIssue = check.status === 'warning' || check.status === 'fail';
  return isIssue && !isFindingExcludedByException(check);
}

/**
 * セキュリティ診断結果リストから「要確認件数」と「重大度別件数の内訳」を集計する
 * - CRITICAL〜LOW は「要確認」に該当する項目のみを数え、その合計は常に requiresAttentionCount と一致する
 * - INFO は status が 'pass' または 'info' の項目の件数を数える
 * - UNKNOWN は status が 'unknown' の項目の件数を数える
 */
export function summarizeSecurityChecks(checks: readonly SecurityCheckResult[]): {
  requiresAttentionCount: number;
  securityFindings: InspectionReport['summary']['securityFindings'];
} {
  let requiresAttentionCount = 0;
  let critical = 0;
  let high = 0;
  let medium = 0;
  let low = 0;
  let info = 0;
  let unknown = 0;

  for (const check of checks) {
    if (isRequiresAttention(check)) {
      requiresAttentionCount += 1;
      if (check.severity === 'critical') {
        critical += 1;
      } else if (check.severity === 'high') {
        high += 1;
      } else if (check.severity === 'medium') {
        medium += 1;
      } else {
        low += 1;
      }
    }

    if (check.status === 'pass' || check.status === 'info') {
      info += 1;
    } else if (check.status === 'unknown') {
      unknown += 1;
    }
  }

  return {
    requiresAttentionCount,
    securityFindings: {
      critical,
      high,
      medium,
      low,
      info,
      unknown,
    },
  };
}

/**
 * SecurityStatus をプレーンなステータス表記（PASS / INFO / WARN / FAIL / UNKNOWN）に変換する
 */
export function formatPlainStatusCode(status: SecurityStatus): string {
  switch (status) {
    case 'pass':
      return 'PASS';
    case 'info':
      return 'INFO';
    case 'warning':
      return 'WARN';
    case 'fail':
      return 'FAIL';
    case 'unknown':
      return 'UNKNOWN';
  }
}

/**
 * SecurityStatus を Markdown 表の判定バッジ表記に変換する
 * - pass -> PASS
 * - info -> INFO
 * - warning -> **WARN**
 * - fail -> **FAIL**
 * - unknown -> UNKNOWN
 */
export function formatMarkdownStatusBadge(status: SecurityStatus): string {
  switch (status) {
    case 'pass':
      return 'PASS';
    case 'info':
      return 'INFO';
    case 'warning':
      return '**WARN**';
    case 'fail':
      return '**FAIL**';
    case 'unknown':
      return 'UNKNOWN';
  }
}

/**
 * UI（ポップアップ・ダッシュボード）およびレポート出力向けのステータス・バッジ表示情報を取得する
 * - status が 'info' / 'pass' / 'unknown' の場合は severity に引きずられず status に対応する表示を返す
 */
export function getSecurityCheckDisplayBadge(
  check: Pick<SecurityCheckResult, 'status' | 'severity'>
): {
  badgeClass: string;
  dashLabel: string;
  popupLabel: string;
  statusCode: string;
  markdownBadge: string;
} {
  const statusCode = formatPlainStatusCode(check.status);
  const markdownBadge = formatMarkdownStatusBadge(check.status);

  if (check.status === 'unknown') {
    return {
      badgeClass: 'sev-unknown',
      dashLabel: '未観測',
      popupLabel: '未観測',
      statusCode,
      markdownBadge,
    };
  }

  if (check.status === 'pass') {
    return {
      badgeClass: 'sev-pass',
      dashLabel: 'PASS',
      popupLabel: '適正',
      statusCode,
      markdownBadge,
    };
  }

  if (check.status === 'info') {
    return {
      badgeClass: 'sev-info',
      dashLabel: 'INFO',
      popupLabel: '情報',
      statusCode,
      markdownBadge,
    };
  }

  // warning または fail の場合は重大度に応じたバッジを返す
  if (check.severity === 'critical') {
    return {
      badgeClass: 'sev-critical',
      dashLabel: 'CRITICAL',
      popupLabel: '緊急',
      statusCode,
      markdownBadge,
    };
  }

  if (check.severity === 'high') {
    return {
      badgeClass: 'sev-high',
      dashLabel: 'HIGH',
      popupLabel: '危険',
      statusCode,
      markdownBadge,
    };
  }

  if (check.severity === 'medium') {
    return {
      badgeClass: 'sev-medium',
      dashLabel: 'MEDIUM',
      popupLabel: '警告',
      statusCode,
      markdownBadge,
    };
  }

  return {
    badgeClass: 'sev-low',
    dashLabel: 'LOW',
    popupLabel: '注意',
    statusCode,
    markdownBadge,
  };
}
