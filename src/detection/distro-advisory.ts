/**
 * CVE ごとのディストリビューション修正状況の判定 (v1.8.1 T06 / §4)
 *
 * Debian / Ubuntu において、上流照合で出た CVE やディストリ固有の CVE に対し、
 * dpkg バージョン比較を用いて修正状況（distroStatus: 6区分）を判定します。
 * 推定に基づく結果のため、すべて Needs Review として扱います（H4）。
 */
import { compareDpkgVersions } from '../security/dpkg-version';
import { formatDistroReleaseName } from '../shared/distro-display';
import type {
  AdvisoryDistroSection,
  DistroAdvisoryAssessment,
  DistroAdvisoryEntry,
  DistroCveAssessment,
  DistroCveReleaseResult,
  DistroCveStatus,
  DistroInference,
  DistroProduct,
  DistroSourceRecord,
} from '../shared/types';

export interface AssessDistroAdvisoriesInput {
  product: DistroProduct;
  upstreamVersion: string;             // 上流版（tech.version。例 '7.4.3'）
  packageVersion: string | null;       // inference.packageVersion ?? null
  inference: DistroInference;
  upstreamCves: string[];              // 上流の照合で出た CVE ID（重複なし）
  distro: AdvisoryDistroSection | null | undefined;
}

/** 悪いほうの優先順位ランク (大きいほど悪い) */
const STATUS_SEVERITY_RANK: Record<DistroCveStatus, number> = {
  'not-fixed': 6,
  open: 5,
  'unknown-revision': 4,
  'no-data': 3,
  fixed: 2,
  'not-affected': 1,
};

/** 要確認件数に数えるか */
function isStatusCounted(status: DistroCveStatus): boolean {
  switch (status) {
    case 'not-fixed':
    case 'open':
    case 'unknown-revision':
    case 'no-data':
      return true;
    case 'fixed':
    case 'not-affected':
      return false;
  }
}

/** ソースパッケージの解決 */
function resolveSourcePackage(
  distro: AdvisoryDistroSection,
  family: string,
  release: string,
  product: DistroProduct,
  upstreamVersion: string
): string | null {
  const mapEntries = (distro.map || []).filter(
    (e) => e.family === family && e.release === release && e.product === product
  );
  if (mapEntries.length === 0) return null;

  const matched = mapEntries.find(
    (e) => Array.isArray(e.upstreamVersions) && e.upstreamVersions.includes(upstreamVersion)
  );
  if (matched && matched.sourcePackage) {
    return matched.sourcePackage;
  }

  const pkgs = Array.from(new Set(mapEntries.map((e) => e.sourcePackage).filter(Boolean)));
  if (pkgs.length === 1) {
    return pkgs[0];
  }

  return null;
}

/** 単一リリース・単一ソースパッケージにおける CVE の判定 */
function evaluateReleaseCve(
  cveId: string,
  release: string,
  sourcePackage: string | null,
  packageVersion: string | null,
  distroAdvisories: Record<string, Record<string, DistroAdvisoryEntry[]>>
): DistroCveReleaseResult {
  if (!sourcePackage) {
    return {
      release,
      sourcePackage: null,
      distroStatus: 'no-data',
      fixedVersions: [],
      osvIds: [],
    };
  }

  const relAdv = distroAdvisories[release];
  const entries = relAdv && Array.isArray(relAdv[sourcePackage]) ? relAdv[sourcePackage] : null;
  const entry = entries ? entries.find((e) => e.cve === cveId) : null;

  if (!entry) {
    return {
      release,
      sourcePackage,
      distroStatus: 'no-data',
      fixedVersions: [],
      osvIds: [],
    };
  }

  const fixedVersions = Array.isArray(entry.fixedVersions) ? [...entry.fixedVersions] : [];
  const osvIds = Array.isArray(entry.osvIds) ? [...entry.osvIds] : [];
  const esm = entry.esm === true ? true : undefined;

  if (entry.status === 'not-affected') {
    return {
      release,
      sourcePackage,
      distroStatus: 'not-affected',
      fixedVersions,
      esm,
      osvIds,
    };
  }

  if (entry.status === 'open') {
    return {
      release,
      sourcePackage,
      distroStatus: 'open',
      fixedVersions,
      esm,
      osvIds,
    };
  }

  // status === 'fixed'
  if (!packageVersion) {
    return {
      release,
      sourcePackage,
      distroStatus: 'unknown-revision',
      fixedVersions,
      esm,
      osvIds,
    };
  }

  if (fixedVersions.length === 0) {
    return {
      release,
      sourcePackage,
      distroStatus: 'fixed',
      fixedVersions,
      esm,
      osvIds,
    };
  }

  let hasSmaller = false;
  let hasIncomparable = false;

  for (const fv of fixedVersions) {
    const cmp = compareDpkgVersions(packageVersion, fv);
    if (cmp === -1) {
      hasSmaller = true;
      break;
    } else if (cmp === null) {
      hasIncomparable = true;
    }
  }

  let distroStatus: DistroCveStatus;
  if (hasSmaller) {
    distroStatus = 'not-fixed';
  } else if (hasIncomparable) {
    distroStatus = 'unknown-revision';
  } else {
    distroStatus = 'fixed';
  }

  return {
    release,
    sourcePackage,
    distroStatus,
    fixedVersions,
    esm,
    osvIds,
  };
}

/** 区分に応じた説明文の生成 */
function buildCveMessage(
  status: DistroCveStatus,
  packageVersion: string | null,
  fixedVersions: string[],
  esm?: boolean
): string {
  const fv = fixedVersions.join(' / ');
  const esmSuffix = esm ? '（ESM で修正）' : '';

  switch (status) {
    case 'not-fixed':
      return `パッケージの版（${packageVersion ?? ''}）はディストリの修正版より古い可能性があります。${fv}${esmSuffix} 以上への更新を検討してください。`;
    case 'open':
      return 'ディストリで未修正です（修正版はまだありません）。ディストリのセキュリティ情報を確認してください。';
    case 'unknown-revision':
      return `パッケージの版が取れないため判定できません。${fv}${esmSuffix} 以上であれば、ディストリで修正済みの可能性が高いです。サーバー側でパッケージの版を確かめてください。`;
    case 'no-data':
      return 'ディストリのデータにこの CVE がありません。セキュリティ修正がバックポートされている可能性があるため、バージョン番号だけでは断定できません。';
    case 'fixed':
      return `ディストリで修正済みの可能性が高いです（修正版 ${fv}${esmSuffix}）。`;
    case 'not-affected':
      return 'ディストリは影響なしと判断しています。';
  }
}

/**
 * CVE ごとにディストリの修正状況を判定する（§4）。判定しない入力では null を返す
 */
export function assessDistroAdvisories(input: AssessDistroAdvisoriesInput): DistroAdvisoryAssessment | null {
  const { product, upstreamVersion, packageVersion, inference, upstreamCves, distro } = input;

  // 1. 判定対象外の条件チェック
  if (!distro) return null;
  if (!distro.advisories || typeof distro.advisories !== 'object') return null;
  if (inference.thirdParty != null) return null;
  if (!inference.candidates || inference.candidates.length === 0) return null;
  if (inference.confidence === 'none') return null;
  if (inference.family !== 'ubuntu' && inference.family !== 'debian') return null;

  const candidates = inference.candidates;
  const distroAdvisories = distro.advisories;

  // 2. 候補リリースごとのソースパッケージ解決
  const releaseSources: Record<string, string | null> = {};
  for (const rel of candidates) {
    releaseSources[rel] = resolveSourcePackage(distro, inference.family, rel, product, upstreamVersion);
  }

  // 3. 上流 CVE およびディストリ限定 CVE のリスト収集
  const upstreamCveSet = new Set(upstreamCves);
  const distroOnlyCveSet = new Set<string>();

  for (const rel of candidates) {
    const srcPkg = releaseSources[rel];
    if (srcPkg && distroAdvisories[rel] && Array.isArray(distroAdvisories[rel][srcPkg])) {
      for (const entry of distroAdvisories[rel][srcPkg]) {
        if (!upstreamCveSet.has(entry.cve)) {
          distroOnlyCveSet.add(entry.cve);
        }
      }
    }
  }

  // 4. 各 CVE の判定ヘルパー
  function evaluateCveAcrossCandidates(cveId: string, origin: 'upstream' | 'distro'): DistroCveAssessment {
    const perRelease: DistroCveReleaseResult[] = [];
    for (const rel of candidates) {
      perRelease.push(evaluateReleaseCve(cveId, rel, releaseSources[rel], packageVersion, distroAdvisories));
    }

    // 悪いほうを採る（ランク最大。同ランクなら候補順で先頭）
    let bestResult = perRelease[0];
    let bestRank = STATUS_SEVERITY_RANK[bestResult.distroStatus];

    for (let i = 1; i < perRelease.length; i++) {
      const rank = STATUS_SEVERITY_RANK[perRelease[i].distroStatus];
      if (rank > bestRank) {
        bestRank = rank;
        bestResult = perRelease[i];
      }
    }

    const hasSplit = perRelease.length > 1 && perRelease.some((r) => r.distroStatus !== perRelease[0].distroStatus);
    const counted = isStatusCounted(bestResult.distroStatus);
    const message = buildCveMessage(bestResult.distroStatus, packageVersion, bestResult.fixedVersions, bestResult.esm);

    return {
      cve: cveId,
      origin,
      distroStatus: bestResult.distroStatus,
      counted,
      release: bestResult.release,
      sourcePackage: bestResult.sourcePackage,
      fixedVersions: bestResult.fixedVersions,
      esm: bestResult.esm,
      osvIds: bestResult.osvIds,
      message,
      ...(candidates.length > 1 ? { split: hasSplit, perRelease } : {}),
    };
  }

  // 5. 上流 CVE の評価（渡された順序を保持）
  const assessedCves: DistroCveAssessment[] = [];
  for (const cveId of upstreamCves) {
    assessedCves.push(evaluateCveAcrossCandidates(cveId, 'upstream'));
  }

  // 6. ディストリ限定 CVE の評価
  let otherFixedCount = 0;
  const distroOnlyList = Array.from(distroOnlyCveSet).sort();
  for (const cveId of distroOnlyList) {
    const assessed = evaluateCveAcrossCandidates(cveId, 'distro');
    if (assessed.distroStatus === 'not-fixed') {
      assessedCves.push(assessed);
    } else if (assessed.distroStatus === 'fixed') {
      otherFixedCount++;
    }
  }

  // 7. 出典情報の抽出
  const expectedEcosystem = inference.family === 'ubuntu' ? 'Ubuntu' : 'Debian';
  const sources: DistroSourceRecord[] = (distro._source || [])
    .filter((s) => s.ecosystem === expectedEcosystem)
    .map((s) => ({ ...s }));

  // 8. 分かれ注記の生成
  const splitCves = assessedCves.filter((c) => c.split);
  let splitNote: string | undefined;
  if (splitCves.length > 0) {
    const candNames = candidates.map((c) => formatDistroReleaseName(c)).join(' / ');
    const splitCveList = splitCves.map((c) => c.cve).join('、');
    splitNote = `候補のリリース（${candNames}）で結果が分かれたため、悪いほうの結果を採りました（${splitCveList}）。`;
  }

  const reviewCount = assessedCves.filter((c) => c.counted).length;

  return {
    family: inference.family as 'ubuntu' | 'debian',
    releases: [...candidates],
    packageVersion,
    cves: assessedCves,
    otherFixedCount,
    reviewCount,
    splitNote,
    sources,
  };
}
