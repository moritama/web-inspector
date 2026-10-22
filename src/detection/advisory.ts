/**
 * Web Technology & Security Inspector
 * オフライン脆弱性・EOL照合エンジン (src/detection/advisory.ts)
 * 
 * 外部通信を一切行わず、ビルド時スナップショットDB (advisory-db.json) を用いて
 * 検出されたライブラリ・ソフトウェアの既知脆弱性 (CVE) およびEOL状況を完全ローカルで判定します。
 */

import { AdvisoryMatchStatus, EolInfo, SecurityAdvisory, SupportStatus } from '../shared/types';
import { parseVersionParts, satisfiesVersionRange } from '../security/version-matcher';
import rawAdvisoryDb from './advisory-db.json';

interface LibraryVersionAdvisory {
  range: string;
  cve: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  fixedVersion?: string;
  summary?: string;
}

interface LibraryEolEntry {
  cycle: string;
  eolDate: string | null;
  status: SupportStatus;
}

interface LibraryEntry {
  aliases: string[];
  versions: LibraryVersionAdvisory[];
  eol: LibraryEolEntry[];
}

interface AdvisoryDatabase {
  version: string;
  generatedAt: string;
  libraries: Record<string, LibraryEntry>;
}

const advisoryDb = rawAdvisoryDb as unknown as AdvisoryDatabase;
export const ADVISORY_DB_VERSION = advisoryDb.version || '2026.10';

export interface OfflineAdvisoryResult {
  technology: string;
  version: string | null;
  matchStatus: AdvisoryMatchStatus;
  advisories: SecurityAdvisory[];
  maxCvss: number | null;
  eolInfo: EolInfo;
  updatedAt: string;
}

/**
 * 技術名とバージョンから、オフラインデータベースを照合してCVEおよびEOL情報を取得する
 *
 * @param technology 技術名 (例: "jQuery", "PHP", "Bootstrap")
 * @param version 検出されたバージョン文字列 (例: "3.4.1", "7.4.33")
 * @returns OfflineAdvisoryResult
 */
export function matchOfflineAdvisories(
  technology: string,
  version: string | null | undefined
): OfflineAdvisoryResult {
  const now = new Date().toISOString().slice(0, 10);
  const normalized = technology.toLowerCase().trim();

  // 1. バージョン不明時
  if (!version) {
    return {
      technology,
      version: null,
      matchStatus: 'Needs Review',
      advisories: [],
      maxCvss: null,
      eolInfo: {
        status: 'Unknown',
        eolDate: null,
        source: 'offline-db',
        recommendation: 'バージョンが特定できないため、サポート状況および既知脆弱性を判定できません。',
      },
      updatedAt: now,
    };
  }

  // 2. データベース検索 (キー直接またはaliasesから)
  let targetEntry: LibraryEntry | null = null;
  let targetKey: string | null = null;

  for (const [key, entry] of Object.entries(advisoryDb.libraries)) {
    if (key.toLowerCase() === normalized || entry.aliases.some((a) => a.toLowerCase() === normalized)) {
      targetEntry = entry;
      targetKey = key;
      break;
    }
  }

  if (!targetEntry) {
    return {
      technology,
      version,
      matchStatus: 'No Data',
      advisories: [],
      maxCvss: null,
      eolInfo: {
        status: 'Unknown',
        eolDate: null,
        source: 'offline-db',
        recommendation: 'この技術のオフライン脆弱性・EOLカタログは未登録です。',
      },
      updatedAt: now,
    };
  }

  // 3. 脆弱性 (CVE) 突合
  const matchedAdvisories: SecurityAdvisory[] = [];
  for (const adv of targetEntry.versions) {
    if (satisfiesVersionRange(version, adv.range)) {
      const sevUpper = adv.severity.toUpperCase() as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
      let defaultCvss = 5.0;
      if (sevUpper === 'CRITICAL') defaultCvss = 9.8;
      else if (sevUpper === 'HIGH') defaultCvss = 7.5;
      else if (sevUpper === 'MEDIUM') defaultCvss = 6.0;
      else if (sevUpper === 'LOW') defaultCvss = 3.5;

      matchedAdvisories.push({
        id: adv.cve,
        title: adv.title,
        severity: sevUpper,
        cvssScore: defaultCvss,
        affectedRange: adv.range,
        fixedVersion: adv.fixedVersion || null,
        summary: adv.summary || adv.title,
        referenceUrls: [`https://nvd.nist.gov/vuln/detail/${adv.cve}`],
      });
    }
  }

  // 最大CVSSスコア計算
  const maxCvss =
    matchedAdvisories.length > 0
      ? Math.max(...matchedAdvisories.map((a) => a.cvssScore || 5.0))
      : null;

  const matchStatus: AdvisoryMatchStatus =
    matchedAdvisories.length > 0 ? 'Potentially Affected' : 'Not Affected';

  // 4. EOL・サポート状況突合
  const eolInfo = matchEolPolicy(targetKey || technology, version, targetEntry.eol);

  return {
    technology,
    version,
    matchStatus,
    advisories: matchedAdvisories,
    maxCvss,
    eolInfo,
    updatedAt: now,
  };
}

/**
 * バージョン文字列とEOLエントリリストを突合する
 */
function matchEolPolicy(
  techName: string,
  version: string,
  eolEntries: LibraryEolEntry[]
): EolInfo {
  if (!eolEntries || eolEntries.length === 0) {
    return {
      status: 'Unknown',
      eolDate: null,
      source: 'offline-db',
      recommendation: 'この技術のEOL判定データがありません。',
    };
  }

  const vParts = parseVersionParts(version);
  const major = vParts ? vParts[0] : null;
  const minor = vParts ? vParts[1] : 0;
  const majorMinor = major !== null ? `${major}.${minor}` : '';

  // サイクル文字列（例: "7.4", "8.0", "3.x", "3", "3.0 - 3.4"）と照合
  for (const entry of eolEntries) {
    const cycle = entry.cycle.toLowerCase();

    // 1. 完全一致またはメジャー・マイナー一致 (例: cycle="7.4", version="7.4.33")
    if (cycle === majorMinor || cycle === String(major)) {
      return buildEolResult(techName, version, entry);
    }

    // 2. "3.x" のようなワイルドカード
    if (cycle.includes('.x') && major !== null && cycle.startsWith(String(major))) {
      return buildEolResult(techName, version, entry);
    }

    // 3. "3.5+" のような表記
    if (cycle.endsWith('+') && major !== null) {
      const baseCycle = cycle.replace('+', '');
      const baseParts = parseVersionParts(baseCycle);
      if (baseParts && major >= baseParts[0]) {
        return buildEolResult(techName, version, entry);
      }
    }
  }

  // デフォルトとして最新系列か判別
  const firstEntry = eolEntries[0];
  if (firstEntry && firstEntry.status === 'Supported') {
    return {
      status: 'Supported',
      eolDate: null,
      source: 'offline-db',
      recommendation: `${techName} ${version} は現在サポート対象のバージョン系列です。`,
    };
  }

  return {
    status: 'Unknown',
    eolDate: null,
    source: 'offline-db',
    recommendation: `${techName} ${version} の正確なサポート期限は未確認です。公式ドキュメントを参照してください。`,
  };
}

function buildEolResult(techName: string, version: string, entry: LibraryEolEntry): EolInfo {
  let recommendation = '';
  if (entry.status === 'EOL') {
    recommendation = `${techName} ${version}（${entry.cycle}系列）はサポート終了 (EOL${entry.eolDate ? `: ${entry.eolDate}` : ''}) しています。最新版への移行を強く推奨します。`;
  } else if (entry.status === 'Maintenance') {
    recommendation = `${techName} ${version} は限定保守（セキュリティ修正のみ）フェーズです。次世代バージョンへの更新準備を推奨します。`;
  } else {
    recommendation = `${techName} ${version} は現在サポートされています。`;
  }

  return {
    status: entry.status,
    eolDate: entry.eolDate,
    source: 'offline-db (endoflife.date snapshot)',
    sourceUrl: `https://endoflife.date/${techName.toLowerCase()}`,
    recommendation,
  };
}
