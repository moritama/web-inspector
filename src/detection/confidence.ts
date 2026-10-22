/**
 * Web Technology & Security Inspector
 * 確信度計算ロジック (src/detection/confidence.ts)
 */

import { ConfidenceLevel, Evidence } from '../shared/types';

/**
 * 検出根拠（Evidence）リストから確信度スコア (0〜100) とレベルを算出する
 *
 * 【仕様書の要件】
 * - 高: 80〜100 (明確な固有シグナルがある)
 * - 中: 50〜79 (複数の間接的な証拠がある)
 * - 低: 1〜49 (可能性を示す証拠がある)
 * - 未検出: 0 (判断できる証拠がない)
 *
 * 【設計上の配慮】
 * - 同一種類の証拠が複数回あっても無制限に加算しない。
 * - 最も強い単一シグナルのweightをベーススコアとし、異なる種類のシグナルが存在する場合にのみ
 *   逓減（diminishing returns）加算を行う。
 *
 * @param evidences 観測された検出根拠リスト
 * @returns { confidence: number, level: ConfidenceLevel }
 */
export function calculateConfidence(evidences: Evidence[]): {
  confidence: number;
  level: ConfidenceLevel;
} {
  if (!evidences || evidences.length === 0) {
    return { confidence: 0, level: 'none' };
  }

  // 1. エビデンス種別（type）ごとに最大のweightを抽出（同種別での過剰加算防止）
  const maxWeightByType = new Map<string, number>();
  for (const ev of evidences) {
    const weight = ev.weight ?? 50;
    const currentMax = maxWeightByType.get(ev.type) || 0;
    if (weight > currentMax) {
      maxWeightByType.set(ev.type, weight);
    }
  }

  // 2. 重み順にソート
  const sortedWeights = Array.from(maxWeightByType.values()).sort((a, b) => b - a);
  const baseWeight = sortedWeights[0] || 0;

  // 3. 追加シグナルによるボーナス加算（異なる種別のシグナルは20%加算）
  let additionalBonus = 0;
  for (let i = 1; i < sortedWeights.length; i++) {
    additionalBonus += Math.round(sortedWeights[i] * 0.2);
  }

  // 4. 合計スコアの算出（1〜100に制限）
  const totalScore = Math.min(100, Math.max(1, baseWeight + additionalBonus));

  // 5. 確信度レベルの判定
  let level: ConfidenceLevel = 'low';
  if (totalScore >= 80) {
    level = 'high';
  } else if (totalScore >= 50) {
    level = 'medium';
  } else if (totalScore > 0) {
    level = 'low';
  } else {
    level = 'none';
  }

  return { confidence: totalScore, level };
}
