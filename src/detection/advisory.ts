/**
 * Web Technology & Security Inspector
 * オフライン脆弱性・EOL照合エンジン (src/detection/advisory.ts)
 * 
 * 外部通信を一切行わず、ビルド時スナップショットDB (advisory-db.json) を用いて
 * 検出されたライブラリ・ソフトウェアの既知脆弱性 (CVE) およびEOL状況を完全ローカルで判定します。
 */

import {
  AdvisoryDbMetadata,
  AdvisoryFixStatus,
  AdvisoryMatchStatus,
  AdvisoryProductCoverage,
  DbFreshnessLevel,
  DetectedTechnology,
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

export interface LibraryVersionAdvisory {
  range: string;
  cve: string;
  ghsa?: string;
  aliases?: string[];
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cvssScore?: number;
  title: string;
  fixedVersion?: string | null;
  fixStatus?: AdvisoryFixStatus;
  kev?: boolean;
  kevDateAdded?: string | null;
  summary?: string;
  advisoryUrl?: string;
  verifiedAt?: string;
  scoreSource?: string;
  origin?: string;
  sources?: string[];
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
    byProduct?: Record<string, AdvisoryProductCoverage | number>;
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
  /** DB内のこの技術の脆弱性収録件数 (v1.7.0 T04 / SPEC-03) */
  productAdvisoryCount?: number;
  /** この技術の脆弱性の取得元リスト (curated / OSV / NVD) (v1.7.0 T04 / SPEC-03) */
  productSources?: string[];
  /** 照合に使用したDBのdataVersion (v1.7.0 T04 / SPEC-03) */
  advisoryDataVersion?: string;
  /** ディストリビューション版のときの上流版での参考該当件数 (v1.7.0 T04 / SPEC-03) */
  upstreamAdvisoriesCount?: number;
  /** ユーザー向け脆弱性照合ステータス表示ラベル (v1.7.0 T04 / SPEC-03) */
  advisoryStatusLabel?: string;
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

export interface MatchOfflineAdvisoriesOptions {
  /** Linuxディストリビューション版ヒント (SPEC-02 / T04) */
  distroHint?: string;
}

let testAdvisoryDbOverride: Partial<AdvisoryDatabase> | null = null;

/**
 * テスト用にデフォルトのオフライン脆弱性DBを一時的に差し替える
 */
export function setTestAdvisoryDatabase(db: Partial<AdvisoryDatabase> | null): void {
  testAdvisoryDbOverride = db;
}

/**
 * 脆弱性一覧を表示優先順位（KEV → 重大度 → CVSS降順）でソートする (v1.7.0 T04 / SPEC-03)
 */
export function sortAdvisoriesByPriority<
  T extends {
    severity?: string;
    cvssScore?: number | null;
    kev?: boolean;
    id?: string;
    cve?: string;
  },
>(advisories: T[]): T[] {
  const rankOf = (sev?: string): number => {
    const s = (sev || '').toLowerCase();
    if (s === 'critical') return 0;
    if (s === 'high') return 1;
    if (s === 'medium') return 2;
    if (s === 'low') return 3;
    return 4;
  };

  return [...advisories].sort((a, b) => {
    const aKev = Boolean(a.kev);
    const bKev = Boolean(b.kev);
    if (aKev !== bKev) return bKev ? 1 : -1;

    const rDiff = rankOf(a.severity) - rankOf(b.severity);
    if (rDiff !== 0) return rDiff;

    const scoreA = typeof a.cvssScore === 'number' ? a.cvssScore : 0;
    const scoreB = typeof b.cvssScore === 'number' ? b.cvssScore : 0;
    if (scoreB !== scoreA) return scoreB - scoreA;

    const idA = a.id || a.cve || '';
    const idB = b.id || b.cve || '';
    return idB.localeCompare(idA);
  });
}

/**
 * 技術名から収録DB内の該当製品エントリを検索する内部ヘルパー
 */
function findLibraryEntry(
  technology: string,
  activeDb: AdvisoryDatabase
): { targetKey: string | null; targetEntry: LibraryEntry | null } {
  const normalized = (technology || '').toLowerCase().trim();
  if (!normalized) return { targetKey: null, targetEntry: null };

  for (const [key, entry] of Object.entries(activeDb.libraries || {})) {
    if (
      key.toLowerCase() === normalized ||
      (Array.isArray(entry.aliases) && entry.aliases.some((a) => a.toLowerCase() === normalized))
    ) {
      return { targetKey: key, targetEntry: entry };
    }
  }
  return { targetKey: null, targetEntry: null };
}

/**
 * 技術名に対応する収録DBの収録件数・取得元・dataVersionを取得する (v1.7.0 T04 / SPEC-03)
 */
export function getProductCoverageInfo(
  technology: string,
  dbOverride?: Partial<AdvisoryDatabase>
): {
  count: number;
  sources: string[];
  dataVersion: string;
  covered: boolean;
} {
  const effectiveOverride = dbOverride ?? testAdvisoryDbOverride ?? undefined;
  const activeDb: AdvisoryDatabase = {
    ...advisoryDb,
    ...effectiveOverride,
    libraries: effectiveOverride?.libraries ?? advisoryDb.libraries,
  };
  const dataVersion =
    activeDb.dataVersion || activeDb.version || advisoryDb.dataVersion || ADVISORY_DB_VERSION;

  const { targetKey, targetEntry } = findLibraryEntry(technology, activeDb);
  if (!targetEntry) {
    return {
      count: 0,
      sources: [],
      dataVersion,
      covered: false,
    };
  }

  const vers = Array.isArray(targetEntry.versions) ? targetEntry.versions : [];
  const srcSet = new Set<string>();

  if (
    vers.some(
      (v) =>
        v.origin === 'curated' || (Array.isArray(v.sources) && v.sources.includes('curated'))
    )
  ) {
    srcSet.add('curated');
  }
  if (vers.some((v) => Array.isArray(v.sources) && v.sources.includes('osv'))) {
    srcSet.add('OSV');
  }
  if (vers.some((v) => Array.isArray(v.sources) && v.sources.includes('nvd'))) {
    srcSet.add('NVD');
  }

  const byProductItem = targetKey ? activeDb.coverage?.byProduct?.[targetKey] : undefined;
  if (
    byProductItem &&
    typeof byProductItem === 'object' &&
    Array.isArray(byProductItem.sources) &&
    (!effectiveOverride?.libraries || byProductItem.count === vers.length)
  ) {
    for (const s of byProductItem.sources) {
      srcSet.add(s);
    }
  }

  if (vers.length > 0 && srcSet.size === 0) {
    srcSet.add('curated');
    srcSet.add('OSV');
    srcSet.add('NVD');
  }

  const count = vers.length;
  return {
    count,
    sources: Array.from(srcSet),
    dataVersion,
    covered: count > 0,
  };
}

/**
 * ディストリビューション版のバージョン文字列から、上流版として照合した場合の該当件数を参考値として計算する (v1.7.0 T04 / SPEC-03)
 */
export function countUpstreamAdvisories(
  technology: string,
  version: string | null | undefined,
  dbOverride?: Partial<AdvisoryDatabase>
): number | undefined {
  if (!version || version.trim() === '') return undefined;

  const effectiveOverride = dbOverride ?? testAdvisoryDbOverride ?? undefined;
  const activeDb: AdvisoryDatabase = {
    ...advisoryDb,
    ...effectiveOverride,
    libraries: effectiveOverride?.libraries ?? advisoryDb.libraries,
  };

  const { targetEntry } = findLibraryEntry(technology, activeDb);
  if (!targetEntry || !Array.isArray(targetEntry.versions)) return undefined;

  const stripped = version
    .trim()
    .replace(/^[a-zA-Z0-9._-]+\//, '')
    .trim()
    .replace(/^v\.?/i, '');
  const upstreamVer = stripped.split(/[-+~\s(]/)[0];
  if (!upstreamVer || parseVersionParts(upstreamVer) === null) return undefined;

  let matchedCount = 0;
  for (const adv of targetEntry.versions) {
    if (satisfiesVersionRange(upstreamVer, adv.range)) {
      matchedCount++;
    }
  }
  return matchedCount;
}

/**
 * UI・エクスポート共通の脆弱性収録状況・表示ラベル解決ヘルパー (v1.7.0 T04 / SPEC-03)
 * 手動構築された DetectedTechnology オブジェクトに対しても、収録件数・取得元・dataVersion・上流版該当件数を補完する。
 */
export function resolveTechAdvisoryDisplayInfo(
  tech: Partial<DetectedTechnology>,
  dbOverride?: Partial<AdvisoryDatabase>
): {
  count: number;
  sources: string[];
  sourcesText: string;
  dataVersion: string;
  upstreamAdvisoriesCount?: number;
  isDistro: boolean;
  isZeroCoverage: boolean;
  statusLabel: string;
} {
  const cov = getProductCoverageInfo(tech.technology || '', dbOverride);
  const count =
    typeof tech.productAdvisoryCount === 'number' ? tech.productAdvisoryCount : cov.count;
  const sources =
    Array.isArray(tech.productSources) && tech.productSources.length > 0
      ? tech.productSources
      : cov.sources;
  const sourcesText = sources.length > 0 ? sources.join(' / ') : 'curated / OSV / NVD';
  const dataVersion = tech.advisoryDataVersion || cov.dataVersion;

  const isDistro = Boolean(
    tech.distroHint ||
      (tech.version && isLinuxPackageVersion(tech.version)) ||
      typeof tech.upstreamAdvisoriesCount === 'number'
  );

  const upstreamAdvisoriesCount =
    typeof tech.upstreamAdvisoriesCount === 'number'
      ? tech.upstreamAdvisoriesCount
      : isDistro
        ? countUpstreamAdvisories(tech.technology || '', tech.version, dbOverride)
        : undefined;

  const advList = Array.isArray(tech.advisories) ? tech.advisories : [];
  const isZeroCoverage =
    count === 0 ||
    tech.advisoryMatchStatus === 'No Data' ||
    tech.offlineMatchStatus === 'Not Covered';

  let statusLabel: string;
  if (advList.length > 0) {
    statusLabel = `既知脆弱性あり (${advList.length}件)`;
  } else if (isDistro) {
    const upNote =
      typeof upstreamAdvisoriesCount === 'number'
        ? `（参考: 上流版では ${upstreamAdvisoriesCount} 件該当）`
        : '';
    statusLabel = `Needs Review${upNote}`;
  } else if (isZeroCoverage) {
    statusLabel = 'この技術の脆弱性は収録していません';
  } else if (
    tech.advisoryMatchStatus === 'Needs Review' ||
    tech.offlineMatchStatus === 'Unknown Version' ||
    !tech.version
  ) {
    statusLabel = `要確認（バージョン未特定・収録 ${count} 件・取得元: ${sourcesText}・dataVersion: ${dataVersion}）`;
  } else if (
    tech.advisoryMatchStatus === 'Lookup Failed' ||
    tech.offlineMatchStatus === 'Lookup Error'
  ) {
    statusLabel = '照合エラー (Lookup Failed)';
  } else {
    statusLabel = `収録 DB 上は該当なし（収録 ${count} 件・取得元: ${sourcesText}・dataVersion: ${dataVersion}）`;
  }

  return {
    count,
    sources,
    sourcesText,
    dataVersion,
    upstreamAdvisoriesCount,
    isDistro,
    isZeroCoverage,
    statusLabel,
  };
}

/**
 * 技術名とバージョンから、オフラインデータベースを照合してCVEおよびEOL情報を取得する (Rev.2.1 IMP-06)
 *
 * @param technology 技術名 (例: "jQuery", "PHP", "Bootstrap", "Apache")
 * @param version 検出されたバージョン文字列 (例: "3.4.1", "7.4.33", "2.4.52-1ubuntu4")
 * @param dbOverride テスト・オーバーライド用カスタムDB (任意)
 * @param options 追加照合オプション (distroHintなど) (任意)
 * @returns OfflineAdvisoryResult
 */
export function matchOfflineAdvisories(
  technology: string,
  version: string | null | undefined,
  dbOverride?: Partial<AdvisoryDatabase>,
  options?: MatchOfflineAdvisoriesOptions
): OfflineAdvisoryResult {
  const effectiveOverride = dbOverride ?? testAdvisoryDbOverride ?? undefined;
  const activeDb: AdvisoryDatabase = {
    ...advisoryDb,
    ...effectiveOverride,
    libraries: effectiveOverride?.libraries ?? advisoryDb.libraries,
  };

  const now = new Date().toISOString().slice(0, 10);
  const freshnessInfo = calculateDbFreshness(activeDb.generatedAt);
  const coverageInfo = getProductCoverageInfo(technology, effectiveOverride);
  const { targetKey, targetEntry } = findLibraryEntry(technology, activeDb);

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
        productAdvisoryCount: coverageInfo.count,
        productSources: coverageInfo.sources,
        advisoryDataVersion: coverageInfo.dataVersion,
        advisoryStatusLabel:
          coverageInfo.count === 0
            ? 'この技術の脆弱性は収録していません'
            : `要確認（バージョン未特定・収録 ${coverageInfo.count} 件・取得元: ${coverageInfo.sources.join(' / ')}・dataVersion: ${coverageInfo.dataVersion}）`,
      };
    }

    // 2. Linuxパッケージ固有バージョンおよびディストリビューション版のバックポート考慮 (Rev.2.1 IMP-06 / 5.6 / D14 / SPEC-02 / SPEC-03)
    if (options?.distroHint) {
      const upstreamCount = countUpstreamAdvisories(technology, version, effectiveOverride);
      const upstreamNote =
        typeof upstreamCount === 'number'
          ? `（参考: 上流版では ${upstreamCount} 件該当）`
          : '';
      const distroNote = `${options.distroHint} のディストリビューション版です。セキュリティ修正がバックポートされている可能性があるため、バージョン番号だけでは脆弱性の有無を断定できません。ディストリビューションのセキュリティ情報で確認してください。${upstreamNote}`;
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
          recommendation: distroNote,
        },
        updatedAt: now,
        warning: distroNote,
        productAdvisoryCount: coverageInfo.count,
        productSources: coverageInfo.sources,
        advisoryDataVersion: coverageInfo.dataVersion,
        upstreamAdvisoriesCount: upstreamCount,
        advisoryStatusLabel: `Needs Review${upstreamNote}`,
      };
    }

    if (isLinuxPackageVersion(version)) {
      const upstreamCount = countUpstreamAdvisories(technology, version, effectiveOverride);
      const upstreamNote =
        typeof upstreamCount === 'number'
          ? `（参考: 上流版では ${upstreamCount} 件該当）`
          : '';
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
          recommendation: `Linuxディストリビューション固有パッケージ版 (${version}) です。ディストリビュータによるセキュリティ修正バックポートが適用されている可能性があるため、機械的断定を避けています。${upstreamNote}`,
        },
        updatedAt: now,
        warning: `Linuxディストリビューション固有パッケージのため、バックポート修正の可能性があります。${upstreamNote}`,
        productAdvisoryCount: coverageInfo.count,
        productSources: coverageInfo.sources,
        advisoryDataVersion: coverageInfo.dataVersion,
        upstreamAdvisoriesCount: upstreamCount,
        advisoryStatusLabel: `Needs Review${upstreamNote}`,
      };
    }

    // 3. カタログ未収録技術または収録0件 -> Not Covered / No Data (SPEC-03)
    if (!targetEntry || coverageInfo.count === 0) {
      return {
        technology,
        version,
        matchStatus: 'No Data',
        offlineMatchStatus: 'Not Covered',
        isStale: freshnessInfo.isStale,
        dbFreshness: freshnessInfo.freshness,
        advisories: [],
        maxCvss: null,
        eolInfo: targetEntry
          ? matchEolPolicy(targetKey || technology, version, targetEntry.eol)
          : {
              status: 'Unknown',
              eolDate: null,
              source: 'offline-db',
              recommendation: 'この技術のオフライン脆弱性・EOLカタログは未登録です。',
            },
        updatedAt: now,
        productAdvisoryCount: 0,
        productSources: [],
        advisoryDataVersion: coverageInfo.dataVersion,
        advisoryStatusLabel: 'この技術の脆弱性は収録していません',
      };
    }

    // 4. 脆弱性 (CVE / GHSA) 突合
    const matchedAdvisories: SecurityAdvisory[] = [];
    for (const adv of targetEntry.versions) {
      if (satisfiesVersionRange(version, adv.range)) {
        const rawSev = (adv.severity || '').toLowerCase();
        let normalizedSeverity: 'critical' | 'high' | 'medium' | 'low' = 'medium';
        if (
          rawSev === 'critical' ||
          rawSev === 'high' ||
          rawSev === 'medium' ||
          rawSev === 'low'
        ) {
          normalizedSeverity = rawSev;
        } else if (typeof adv.cvssScore === 'number') {
          if (adv.cvssScore >= 9.0) normalizedSeverity = 'critical';
          else if (adv.cvssScore >= 7.0) normalizedSeverity = 'high';
          else if (adv.cvssScore >= 4.0) normalizedSeverity = 'medium';
          else if (adv.cvssScore > 0) normalizedSeverity = 'low';
        }

        let defaultCvss = 5.0;
        if (normalizedSeverity === 'critical') defaultCvss = 9.8;
        else if (normalizedSeverity === 'high') defaultCvss = 7.5;
        else if (normalizedSeverity === 'medium') defaultCvss = 6.0;
        else if (normalizedSeverity === 'low') defaultCvss = 3.5;

        const actualCvss = typeof adv.cvssScore === 'number' ? adv.cvssScore : defaultCvss;
        const fixStatus = getEffectiveFixStatus(adv);
        const kev = Boolean(adv.kev);
        const kevDateAdded = adv.kevDateAdded ?? null;

        // 参照リンクの構築 (SPEC-13: CVEがあればNVD、GHSAのみならGitHub Advisoriesを使用し NVD に GHSA ID を付けたリンクは作らない)
        const candidateIds = [
          adv.cve,
          adv.ghsa,
          ...(Array.isArray(adv.aliases) ? adv.aliases : []),
        ].filter((id): id is string => typeof id === 'string' && id.trim() !== '');

        const cveId = candidateIds.find((id) => /^CVE-\d{4}-\d+$/i.test(id));
        const ghsaId = candidateIds.find((id) => /^GHSA-[a-z0-9-]+$/i.test(id));

        const urls: string[] = [];
        if (
          adv.advisoryUrl &&
          !(adv.advisoryUrl.includes('nvd.nist.gov') && /\/GHSA-/i.test(adv.advisoryUrl))
        ) {
          urls.push(adv.advisoryUrl);
        }
        if (cveId) {
          urls.push(`https://nvd.nist.gov/vuln/detail/${cveId}`);
        } else if (ghsaId) {
          urls.push(`https://github.com/advisories/${ghsaId}`);
        }

        matchedAdvisories.push({
          id: adv.cve,
          ...(adv.aliases
            ? { aliases: adv.aliases }
            : adv.ghsa && adv.ghsa !== adv.cve
              ? { aliases: [adv.ghsa] }
              : {}),
          title: adv.title,
          severity: normalizedSeverity,
          cvssScore: actualCvss,
          affectedRange: adv.range,
          fixedVersion: adv.fixedVersion || null,
          fixStatus,
          kev,
          kevDateAdded,
          summary: adv.summary || adv.title,
          referenceUrls: Array.from(new Set(urls)),
        });
      }
    }

    // KEV → 重大度 → CVSS の順にソート (SPEC-03)
    const sortedAdvisories = sortAdvisoriesByPriority(matchedAdvisories);

    // 最大CVSSスコア計算
    const maxCvss =
      sortedAdvisories.length > 0
        ? Math.max(...sortedAdvisories.map((a) => a.cvssScore || 5.0))
        : null;

    // 照合ステータス決定 (Matched / No Match)
    const offlineMatchStatus: OfflineMatchStatus =
      sortedAdvisories.length > 0 ? 'Matched' : 'No Match';
    const matchStatus: AdvisoryMatchStatus =
      sortedAdvisories.length > 0 ? 'Potentially Affected' : 'Not Affected';

    // 5. EOL・サポート状況突合
    const eolInfo = matchEolPolicy(targetKey || technology, version, targetEntry.eol);

    const statusLabel =
      sortedAdvisories.length > 0
        ? `既知脆弱性あり (${sortedAdvisories.length}件)`
        : `収録 DB 上は該当なし（収録 ${coverageInfo.count} 件・取得元: ${coverageInfo.sources.join(' / ')}・dataVersion: ${coverageInfo.dataVersion}）`;

    return {
      technology,
      version,
      matchStatus,
      offlineMatchStatus,
      isStale: freshnessInfo.isStale,
      dbFreshness: freshnessInfo.freshness,
      advisories: sortedAdvisories,
      maxCvss,
      eolInfo,
      updatedAt: now,
      productAdvisoryCount: coverageInfo.count,
      productSources: coverageInfo.sources,
      advisoryDataVersion: coverageInfo.dataVersion,
      advisoryStatusLabel: statusLabel,
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
      productAdvisoryCount: coverageInfo.count,
      productSources: coverageInfo.sources,
      advisoryDataVersion: coverageInfo.dataVersion,
      advisoryStatusLabel: '照合エラー (Lookup Failed)',
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
 * アドバイザリ項目から実効的な fixStatus を取得する (SPEC-13)
 * fixStatus が明示されていない場合は fixedVersion の有無から判定する
 */
export function getEffectiveFixStatus(adv: {
  fixedVersion?: string | null;
  fixStatus?: AdvisoryFixStatus;
}): AdvisoryFixStatus {
  if (
    adv.fixStatus === 'fixed' ||
    adv.fixStatus === 'partial' ||
    adv.fixStatus === 'none' ||
    adv.fixStatus === 'unknown'
  ) {
    return adv.fixStatus;
  }
  return adv.fixedVersion && adv.fixedVersion.trim() !== '' ? 'fixed' : 'none';
}

/**
 * 検出バージョンおよび該当する全アドバイザリから、最適な推奨修正バージョンを解決する
 * 
 * 1. fixedVersion が "7.4.31 / 8.0.24 / 8.1.11" のような複数ブランチ表記の場合、
 *    検出バージョンと同一系統 (メジャー・マイナー) の修正版を優先抽出します。
 * 2. 複数のアドバイザリが存在する場合 (例: Apache 2.4.49 に対して 2.4.50, 2.4.51, 2.4.52)、
 *    全てを解消できる最も高い修正版を選択します。
 * 3. fixStatus === 'none' のアドバイザリが含まれる場合はバージョン更新のみでは解消できないため null を返します。
 * 
 * @param detectedVersion 検出されたバージョン文字列 (例: "2.4.49", "8.0.10")
 * @param advisories 該当した脆弱性アドバイザリ配列
 * @returns 推奨修正バージョン文字列 (例: "8.0.24", "2.4.52")、または null
 */
export function resolveRecommendedVersion(
  detectedVersion: string | null | undefined,
  advisories: { fixedVersion?: string | null; fixStatus?: AdvisoryFixStatus }[]
): string | null {
  if (!advisories || advisories.length === 0) return null;

  // 公式修正版が存在しない脆弱性 (fixStatus === 'none') が含まれる場合は推奨版を導出しない
  if (advisories.some((adv) => getEffectiveFixStatus(adv) === 'none')) {
    return null;
  }

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
 * 脆弱性検出に対する推奨文を生成する (SPEC-13)
 * - fixStatus === 'none': 「公式の修正版はありません」と後継技術への移行・緩和策を案内
 * - fixStatus === 'unknown': 「修正版の情報が DB にありません。ベンダーの情報を確認してください」を案内（「公式の修正版はありません」は出さない）
 * - fixStatus === 'partial': 「一部の系列には修正版がありません」を含めて案内
 * - fixStatus === 'fixed': 推奨修正バージョンへのアップデートを案内
 * 
 * @param detectedVersion 検出されたバージョン文字列
 * @param advisories 該当した脆弱性アドバイザリ配列
 * @param options オプション (isEol, technologyName)
 * @returns ユーザー向け推奨アクション文面
 */
export function formatAdvisoryRecommendation(
  detectedVersion: string | null | undefined,
  advisories: { fixedVersion?: string | null; fixStatus?: AdvisoryFixStatus }[],
  options?: { isEol?: boolean; technologyName?: string }
): string {
  const isEol = options?.isEol ?? false;
  const techName = options?.technologyName ?? '';

  const hasNone = advisories.some((a) => getEffectiveFixStatus(a) === 'none');
  const hasPartial = advisories.some((a) => getEffectiveFixStatus(a) === 'partial');
  const hasUnknown = advisories.some((a) => getEffectiveFixStatus(a) === 'unknown');

  if (hasNone || (advisories.length === 0 && isEol)) {
    const alt = techName.toLowerCase() === 'angularjs' ? 'Angularなど' : 'サポート対象の後継技術';
    return `公式の修正版はありません。${alt}への移行、またはサニタイズ/CSPなどの緩和策の適用を検討してください。`;
  }

  const recommendedVer = resolveRecommendedVersion(detectedVersion, advisories);

  if (hasPartial) {
    const unknownNote = hasUnknown
      ? 'なお、一部の脆弱性は修正版の情報が DB にありません。ベンダーの情報を確認してください。'
      : '';
    if (recommendedVer) {
      return `一部の系列には修正版がありません。修正済みバージョン（v${recommendedVer} 以上）への速やかなアップデート、またはサポート対象系列への移行を推奨します。${unknownNote}`;
    }
    return `一部の系列には修正版がありません。修正版が提供されている系列への移行、または緩和策の適用を検討してください。${unknownNote}`;
  }

  if (hasUnknown) {
    if (recommendedVer) {
      return `修正済みバージョン（v${recommendedVer} 以上）への速やかなアップデートを推奨します。なお、一部の脆弱性は修正版の情報が DB にありません。ベンダーの情報を確認してください。`;
    }
    return '修正版の情報が DB にありません。ベンダーの情報を確認してください。';
  }

  if (recommendedVer) {
    return `修正済みバージョン（v${recommendedVer} 以上）への速やかなアップデートを推奨します。`;
  }

  return '最新のセキュリティ修正済みバージョンへの速やかなアップデートを推奨します。';
}

