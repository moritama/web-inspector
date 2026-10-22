/**
 * Web Technology & Security Inspector
 * EOL・サポート状況照合エンジン (src/security/eol/eol-engine.ts)
 */

import { EolInfo, SupportStatus } from '../../shared/types';
import { satisfiesVersionRange } from '../version-matcher';
import rawEolDatabase from './eol-database.json';

interface EolPolicy {
  versionRange: string;
  status: SupportStatus;
  eolDate: string | null;
  releaseDate?: string | null;
  source: string;
  sourceUrl?: string;
  recommendation: string;
}

interface TechnologyEolEntry {
  technology: string;
  aliases: string[];
  policies: EolPolicy[];
}

const eolDatabase = rawEolDatabase as unknown as TechnologyEolEntry[];

/**
 * 技術名とバージョンからEOL（サポート状況）を照合する
 *
 * @param technology 技術名 (例: "Bootstrap", "jQuery")
 * @param version 検出バージョン (例: "4.3.1")
 * @returns EolInfo
 */
export function checkEolStatus(
  technology: string,
  version: string | null | undefined
): EolInfo {
  // バージョン不明の場合は仕様通り Unknown
  if (!version) {
    return {
      status: 'Unknown',
      eolDate: null,
      source: 'none',
      recommendation: 'バージョンが特定できないため、サポート状況を判定できません。',
    };
  }

  const normalizedTech = technology.toLowerCase().trim();

  // データベースから合致する技術を検索
  const entry = eolDatabase.find(
    (e) =>
      e.technology.toLowerCase() === normalizedTech ||
      e.aliases.some((a) => a.toLowerCase() === normalizedTech)
  );

  if (!entry) {
    return {
      status: 'Unknown',
      eolDate: null,
      source: 'database',
      recommendation: 'この技術のEOL判定ポリシーは未登録です。',
    };
  }

  // ポリシーを順次評価
  for (const policy of entry.policies) {
    if (satisfiesVersionRange(version, policy.versionRange)) {
      return {
        status: policy.status,
        eolDate: policy.eolDate,
        releaseDate: policy.releaseDate,
        source: policy.source,
        sourceUrl: policy.sourceUrl,
        recommendation: policy.recommendation,
      };
    }
  }

  return {
    status: 'Unknown',
    eolDate: null,
    source: 'database',
    recommendation: '検出されたバージョンに合致するサポートポリシーがありませんでした。',
  };
}
