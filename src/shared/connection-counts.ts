/**
 * Web Technology & Security Inspector
 * 外部通信先集計・Local ホスト数判定ヘルパー (src/shared/connection-counts.ts)
 */

import type { ExternalConnectionsAnalysis } from './types';

/**
 * 通信先の Local の件数を返す (v1.8.2 T05 / §4.4)
 * localCount があればその値。無い（v1.8.1 以前の保存済みレポート）ときは 総数 − First − Third。
 * 求められないときは null（0 にしない）
 *
 * @param analysis 通信先分析オブジェクト
 * @returns Local 件数。算出できない場合は null
 */
export function resolveLocalConnectionCount(
  analysis: ExternalConnectionsAnalysis | null | undefined
): number | null {
  if (!analysis) {
    return null;
  }

  // localCount が 0 以上の整数であればその値を返す
  if (typeof analysis.localCount === 'number' && Number.isInteger(analysis.localCount) && analysis.localCount >= 0) {
    return analysis.localCount;
  }

  // localCount が無い（v1.8.1 以前の保存済みレポート）場合: 総数 − First − Third
  const total = analysis.totalConnections;
  const first = analysis.firstPartyCount;
  const third = analysis.thirdPartyCount;

  if (
    typeof total === 'number' && Number.isInteger(total) && total >= 0 &&
    typeof first === 'number' && Number.isInteger(first) && first >= 0 &&
    typeof third === 'number' && Number.isInteger(third) && third >= 0
  ) {
    const diff = total - first - third;
    if (diff >= 0) {
      return diff;
    }
  }

  return null;
}

/**
 * Local の件数を表示（Markdown §9 やダッシュボード）すべきかを判定するヘルパー (v1.8.2 T05)
 * - localCount が 0 以上の整数（新しいレポート）: 0 でも表示 (true)
 * - localCount が無い（保存済みレポート）: resolveLocalConnectionCount が 1 以上なら表示 (true)。0 または null のときは非表示 (false)
 *
 * @param analysis 通信先分析オブジェクト
 * @returns 表示すべき場合は true、非表示の場合は false
 */
export function shouldShowLocalConnectionCount(
  analysis: ExternalConnectionsAnalysis | null | undefined
): boolean {
  if (!analysis) {
    return false;
  }

  if (typeof analysis.localCount === 'number' && Number.isInteger(analysis.localCount) && analysis.localCount >= 0) {
    return true;
  }

  const resolved = resolveLocalConnectionCount(analysis);
  return resolved !== null && resolved >= 1;
}
