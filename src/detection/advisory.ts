/**
 * Web Technology & Security Inspector
 * オフライン脆弱性・EOL照合エンジン (src/detection/advisory.ts)
 * 
 * 外部通信を一切行わず、ビルド時スナップショットDB (advisory-db.json) を用いて
 * 検出されたライブラリ・ソフトウェアの既知脆弱性 (CVE) およびEOL状況を完全ローカルで判定します。
 */

import {
  AdvisoryDbMetadata,
  AdvisoryMatchStatus,
  DbFreshnessLevel,
  EolInfo,
  OfflineMatchStatus,
  SecurityAdvisory,
  SupportStatus,
} from '../shared/types';
import {
  compareVersions,
  isLinuxPackageVersion,
  parseVersionParts,
  satisfiesVersionRange,
} from '../security/version-matcher';
import rawAdvisoryDb from './advisory-db.json';

interface LibraryVersionAdvisory {
  range: string;
  cve: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvssScore?: number;
  title: string;
  fixedVersion?: string | null;
  summary?: string;
  advisoryUrl?: string;
  verifiedAt?: string;
  scoreSource?: string;
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

export interface AdvisoryDatabase {
  schemaVersion?: string;
  version?: string;
  dataVersion?: string;
  generatedAt: string;
  sources?: string[];
  coverage?: {
    technologies: string[];
    totalAdvisories?: number;
  };
  advisoryCount?: number;
  productCount?: number;
  syncStatus?: 'success' | 'partial' | 'failed';
  libraries: Record<string, LibraryEntry>;
}

const advisoryDb = rawAdvisoryDb as unknown as AdvisoryDatabase;
export const ADVISORY_DB_VERSION = advisoryDb.dataVersion || advisoryDb.version || '2026.10';

export interface OfflineAdvisoryResult {
  technology: string;
  version: string | null;
  matchStatus: AdvisoryMatchStatus;
  offlineMatchStatus: OfflineMatchStatus;
  isStale: boolean;
  dbFreshness: DbFreshnessLevel;
  advisories: SecurityAdvisory[];
  maxCvss: number | null;
  eolInfo: EolInfo;
  updatedAt: string;
  warning?: string;
}

/**
 * DBスナップショットのメタデータを取得する (Rev.2.1 IMP-06 / 5.4)
 */
export function getAdvisoryDbMetadata(): AdvisoryDbMetadata {
  const libs = advisoryDb.libraries || {};
  const computedCount = Object.values(libs).reduce(
    (acc, lib) => acc + (Array.isArray(lib.versions) ? lib.versions.length : 0),
    0
  );

  return {
    schemaVersion: advisoryDb.schemaVersion || '2.1',
    dataVersion: advisoryDb.dataVersion || advisoryDb.version || 'unknown',
    generatedAt: advisoryDb.generatedAt || new Date().toISOString(),
    sources: advisoryDb.sources || [
      'NIST NVD 2.0 API (Primary: nvd@nist.gov)',
      'GitHub Advisory Database (GHSA)',
      'endoflife.date API',
      'CISA KEV Catalog',
    ],
    coverage: advisoryDb.coverage || {
      technologies: Object.keys(libs),
      totalAdvisories: computedCount,
    },
    advisoryCount: advisoryDb.coverage?.totalAdvisories ?? computedCount,
    productCount: Object.keys(libs).length,
    syncStatus: advisoryDb.syncStatus || 'success',
  };
}

/**
 * DBの生成日から鮮度状態を計算する (Rev.2.1 IMP-06 / 5.8)
 * - 0〜7日: fresh
 * - 8〜30日: moderate
 * - 31日以上: stale (isStale: true)
 */
export function calculateDbFreshness(generatedAt: string): {
  isStale: boolean;
  freshness: DbFreshnessLevel;
  daysDiff: number;
} {
  const genTime = new Date(generatedAt).getTime();
  if (isNaN(genTime)) {
    return { isStale: false, freshness: 'unknown', daysDiff: 0 };
  }
  const now = Date.now();
  const daysDiff = Math.max(0, Math.floor((now - genTime) / (1000 * 60 * 60 * 24)));

  let freshness: DbFreshnessLevel = 'fresh';
  if (daysDiff > 30) {
    freshness = 'stale';
  } else if (daysDiff > 7) {
    freshness = 'moderate';
  } else {
    freshness = 'fresh';
  }

  return {
    isStale: daysDiff > 30,
    freshness,
    daysDiff,
  };
}

/**
 * 技術名とバージョンから、オフラインデータベースを照合してCVEおよびEOL情報を取得する (Rev.2.1 IMP-06)
 *
 * @param technology 技術名 (例: "jQuery", "PHP", "Bootstrap", "Apache")
 * @param version 検出されたバージョン文字列 (例: "3.4.1", "7.4.33", "2.4.52-1ubuntu4")
 * @param dbOverride テスト・オーバーライド用カスタムDB (任意)
 * @returns OfflineAdvisoryResult
 */
export function matchOfflineAdvisories(
  technology: string,
  version: string | null | undefined,
  dbOverride?: Partial<AdvisoryDatabase>
): OfflineAdvisoryResult {
  const activeDb: AdvisoryDatabase = {
    ...advisoryDb,
    ...dbOverride,
    libraries: dbOverride?.libraries ?? advisoryDb.libraries,
  };

  const now = new Date().toISOString().slice(0, 10);
  const normalized = technology.toLowerCase().trim();
  const freshnessInfo = calculateDbFreshness(activeDb.generatedAt);

  try {
    // 1. バージョン不明時 (空またはnull、あるいは解析不能文字列) -> Unknown Version / Needs Review (SPEC-06)
    if (!version || version.trim() === '' || parseVersionParts(version) === null) {
      return {
        technology,
        version: version ? version : null,
        matchStatus: 'Needs Review',
        offlineMatchStatus: 'Unknown Version',
        isStale: freshnessInfo.isStale,
        dbFreshness: freshnessInfo.freshness,
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

    // 2. Linuxパッケージ固有バージョンのバックポート考慮 (Rev.2.1 IMP-06 / 5.6 / D14)
    if (isLinuxPackageVersion(version)) {
      return {
        technology,
        version,
        matchStatus: 'Needs Review',
        offlineMatchStatus: 'Unknown Version',
        isStale: freshnessInfo.isStale,
        dbFreshness: freshnessInfo.freshness,
        advisories: [],
        maxCvss: null,
        eolInfo: {
          status: 'Unknown',
          eolDate: null,
          source: 'offline-db',
          recommendation: `Linuxディストリビューション固有パッケージ版 (${version}) です。ディストリビュータによるセキュリティ修正バックポートが適用されている可能性があるため、機械的断定を避けています。`,
        },
        updatedAt: now,
        warning: 'Linuxディストリビューション固有パッケージのため、バックポート修正の可能性があります。',
      };
    }

    // 3. データベース検索 (キー直接またはaliasesから)
    let targetEntry: LibraryEntry | null = null;
    let targetKey: string | null = null;

    for (const [key, entry] of Object.entries(activeDb.libraries)) {
      if (key.toLowerCase() === normalized || entry.aliases.some((a) => a.toLowerCase() === normalized)) {
        targetEntry = entry;
        targetKey = key;
        break;
      }
    }

    // カタログ未収録技術 -> Not Covered / No Data
    if (!targetEntry) {
      return {
        technology,
        version,
        matchStatus: 'No Data',
        offlineMatchStatus: 'Not Covered',
        isStale: freshnessInfo.isStale,
        dbFreshness: freshnessInfo.freshness,
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

    // 4. 脆弱性 (CVE) 突合
    const matchedAdvisories: SecurityAdvisory[] = [];
    for (const adv of targetEntry.versions) {
      if (satisfiesVersionRange(version, adv.range)) {
        const sevUpper = adv.severity.toUpperCase() as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
        let defaultCvss = 5.0;
        if (sevUpper === 'CRITICAL') defaultCvss = 9.8;
        else if (sevUpper === 'HIGH') defaultCvss = 7.5;
        else if (sevUpper === 'MEDIUM') defaultCvss = 6.0;
        else if (sevUpper === 'LOW') defaultCvss = 3.5;

        const actualCvss = typeof adv.cvssScore === 'number' ? adv.cvssScore : defaultCvss;

        matchedAdvisories.push({
          id: adv.cve,
          title: adv.title,
          severity: sevUpper,
          cvssScore: actualCvss,
          affectedRange: adv.range,
          fixedVersion: adv.fixedVersion || null,
          summary: adv.summary || adv.title,
          referenceUrls: adv.advisoryUrl
            ? Array.from(new Set([adv.advisoryUrl, `https://nvd.nist.gov/vuln/detail/${adv.cve}`]))
            : [`https://nvd.nist.gov/vuln/detail/${adv.cve}`],
        });
      }
    }

    // 最大CVSSスコア計算
    const maxCvss =
      matchedAdvisories.length > 0
        ? Math.max(...matchedAdvisories.map((a) => a.cvssScore || 5.0))
        : null;

    // 照合ステータス決定 (Matched / No Match)
    const offlineMatchStatus: OfflineMatchStatus =
      matchedAdvisories.length > 0 ? 'Matched' : 'No Match';
    const matchStatus: AdvisoryMatchStatus =
      matchedAdvisories.length > 0 ? 'Potentially Affected' : 'Not Affected';

    // 5. EOL・サポート状況突合
    const eolInfo = matchEolPolicy(targetKey || technology, version, targetEntry.eol);

    return {
      technology,
      version,
      matchStatus,
      offlineMatchStatus,
      isStale: freshnessInfo.isStale,
      dbFreshness: freshnessInfo.freshness,
      advisories: matchedAdvisories,
      maxCvss,
      eolInfo,
      updatedAt: now,
    };
  } catch (error) {
    // 照合処理エラー -> Lookup Error / Lookup Failed
    return {
      technology,
      version: version ?? null,
      matchStatus: 'Lookup Failed',
      offlineMatchStatus: 'Lookup Error',
      isStale: freshnessInfo.isStale,
      dbFreshness: freshnessInfo.freshness,
      advisories: [],
      maxCvss: null,
      eolInfo: {
        status: 'Unknown',
        eolDate: null,
        source: 'offline-db',
        recommendation: '照合処理中にエラーが発生しました。',
      },
      updatedAt: now,
      warning: error instanceof Error ? error.message : String(error),
    };
  }
}


/**
 * バージョン文字列とEOLエントリリストを突合する (SPEC-04)
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

  // 1. cycle === "major.minor" の完全一致
  if (majorMinor) {
    for (const entry of eolEntries) {
      if (entry.cycle.toLowerCase() === majorMinor) {
        return buildEolResult(techName, version, entry);
      }
    }
  }

  // 2. cycle === "major" の一致
  if (major !== null) {
    const majorStr = String(major);
    for (const entry of eolEntries) {
      if (entry.cycle.toLowerCase() === majorStr) {
        return buildEolResult(techName, version, entry);
      }
    }
  }

  // 3. "N.x" 形式は major の数値一致で判定する (1.x が 10 に一致する誤りを防止)
  if (major !== null) {
    for (const entry of eolEntries) {
      const cycle = entry.cycle.toLowerCase();
      const nxMatch = cycle.match(/^(\d+)\.x$/);
      if (nxMatch) {
        const cycleMajor = parseInt(nxMatch[1], 10);
        if (cycleMajor === major) {
          return buildEolResult(techName, version, entry);
        }
      }
    }
  }

  // 4. "N+" 形式は現行どおり
  if (major !== null) {
    for (const entry of eolEntries) {
      const cycle = entry.cycle.toLowerCase();
      if (cycle.endsWith('+')) {
        const baseCycle = cycle.replace('+', '');
        const baseParts = parseVersionParts(baseCycle);
        if (baseParts && major >= baseParts[0]) {
          return buildEolResult(techName, version, entry);
        }
      }
    }
  }

  // 5. どれにも一致しない場合:
  // 検出バージョンが、エントリ中で最も古いサイクルより古い（major.minor で比較）なら EOL
  let oldestMajor: number | null = null;
  let oldestMinor: number | null = null;

  for (const entry of eolEntries) {
    const parts = parseVersionParts(entry.cycle);
    if (!parts) continue;
    const cMajor = parts[0];
    const cMinor = parts[1];
    if (
      oldestMajor === null ||
      cMajor < oldestMajor ||
      (cMajor === oldestMajor && cMinor < (oldestMinor ?? 0))
    ) {
      oldestMajor = cMajor;
      oldestMinor = cMinor;
    }
  }

  if (major !== null && oldestMajor !== null) {
    const isOlderThanOldest =
      major < oldestMajor ||
      (major === oldestMajor && minor < (oldestMinor ?? 0));

    if (isOlderThanOldest) {
      return {
        status: 'EOL',
        eolDate: null,
        source: 'offline-db',
        recommendation:
          '公式のサポート表に掲載されていない古い系列です。サポート終了（EOL）とみなし、現行系列への移行を推奨します。',
      };
    }
  }

  // それ以外は Unknown (先頭エントリが Supported なら Supported とする既定動作は削除)
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
    if (techName.toLowerCase().includes('angularjs')) {
      recommendation = `AngularJS ${version}は2022年1月に公式サポート終了（EOL）となりました。後継の修正版は提供されないため、Angularや他のモダンフレームワークへの移行を強く推奨します。`;
    } else {
      recommendation = `${techName} ${version}（${entry.cycle}系列）はサポート終了 (EOL${entry.eolDate ? `: ${entry.eolDate}` : ''}) しています。最新版への移行を強く推奨します。`;
    }
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

/**
 * 検出バージョンおよび該当する全アドバイザリから、最適な推奨修正バージョンを解決する
 * 
 * 1. fixedVersion が "7.4.31 / 8.0.24 / 8.1.11" のような複数ブランチ表記の場合、
 *    検出バージョンと同一系統 (メジャー・マイナー) の修正版を優先抽出します。
 * 2. 複数のアドバイザリが存在する場合 (例: Apache 2.4.49 に対して 2.4.50, 2.4.51, 2.4.52)、
 *    全てを解消できる最も高い修正版を選択します。
 * 
 * @param detectedVersion 検出されたバージョン文字列 (例: "2.4.49", "8.0.10")
 * @param advisories 該当した脆弱性アドバイザリ配列
 * @returns 推奨修正バージョン文字列 (例: "8.0.24", "2.4.52")、または null
 */
export function resolveRecommendedVersion(
  detectedVersion: string | null | undefined,
  advisories: { fixedVersion?: string | null }[]
): string | null {
  if (!advisories || advisories.length === 0) return null;

  const detectedParts = parseVersionParts(detectedVersion);
  const candidateVersions: string[] = [];

  for (const adv of advisories) {
    if (!adv.fixedVersion) continue;

    // スラッシュ区切りの複数ブランチ修正版を分割
    const branches = adv.fixedVersion
      .split('/')
      .map((s) => s.trim())
      .filter(Boolean);

    if (branches.length === 1) {
      candidateVersions.push(branches[0]);
    } else if (branches.length > 1) {
      if (detectedParts) {
        // 1. 同一メジャー・マイナー系列の修正版を探す (例: 8.0.10 -> 8.0.24)
        const matchMinor = branches.find((b) => {
          const bp = parseVersionParts(b);
          return bp && bp[0] === detectedParts[0] && bp[1] === detectedParts[1];
        });
        if (matchMinor) {
          candidateVersions.push(matchMinor);
          continue;
        }

        // 2. 同一メジャー系列の修正版を探す (例: 8.0.10 -> 8.x)
        const matchMajor = branches.find((b) => {
          const bp = parseVersionParts(b);
          return bp && bp[0] === detectedParts[0];
        });
        if (matchMajor) {
          candidateVersions.push(matchMajor);
          continue;
        }
      }
      // 該当系列が見つからない場合は、最も新しいブランチの修正版を採用
      const sortedBranches = [...branches].sort((a, b) => compareVersions(b, a));
      candidateVersions.push(sortedBranches[0]);
    }
  }

  if (candidateVersions.length === 0) return null;

  // 複数のアドバイザリが存在する場合、すべてを解消できる「最も高い修正バージョン」を選択
  candidateVersions.sort((a, b) => compareVersions(b, a));
  return candidateVersions[0];
}

/**
 * 脆弱性検出に対する推奨文を生成する
 * 
 * @param detectedVersion 検出されたバージョン文字列
 * @param advisories 該当した脆弱性アドバイザリ配列
 * @param options オプション (isEol, technologyName)
 * @returns ユーザー向け推奨アクション文面
 */
export function formatAdvisoryRecommendation(
  detectedVersion: string | null | undefined,
  advisories: { fixedVersion?: string | null }[],
  options?: { isEol?: boolean; technologyName?: string }
): string {
  const isEol = options?.isEol ?? false;
  const techName = options?.technologyName ?? '';
  const hasUnpatched = advisories.some((a) => !a.fixedVersion);

  if (hasUnpatched || isEol) {
    const alt = techName.toLowerCase() === 'angularjs' ? 'Angularなど' : 'サポート対象の後継技術';
    return `公式の修正版はありません。${alt}への移行、またはサニタイズ/CSPなどの緩和策の適用を検討してください。`;
  }

  const recommendedVer = resolveRecommendedVersion(detectedVersion, advisories);
  if (recommendedVer) {
    return `修正済みバージョン（v${recommendedVer} 以上）への速やかなアップデートを推奨します。`;
  }

  return '最新のセキュリティ修正済みバージョンへの速やかなアップデートを推奨します。';
}

