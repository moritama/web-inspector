/**
 * Web Technology & Security Inspector
 * OS リリースの推定とライフサイクル判定 (src/detection/distro-inference.ts) - v1.8.1 T03
 *
 * 外部通信を一切行わず、Server・X-Powered-By ヘッダーのシグナルから
 * 製品ごとに OS リリースを推定し、ライフサイクルに基づく EOL 判定を行います。
 * 推定結果はすべて Needs Review として扱い、断定的な表現を避けます。
 */

import { formatDistroReleaseName, formatDistroConfidenceJp } from '../shared/distro-display';
import { parseDpkgVersion } from '../security/dpkg-version';
import type {
  AdvisoryDistroSection,
  DistroFamily,
  DistroInference,
  DistroInferenceConfidence,
  DistroInferenceEvidence,
  DistroProduct,
  DistroReleaseLifecycle,
  DistroThirdPartyInfo,
  EolInfo,
  SupportStatus,
} from '../shared/types';

export interface DistroEolJudgement {
  basisRelease: string;   // 判定に使ったリリース（候補が 2 件以上なら最も早く終わるもの）
  eolInfo: EolInfo;
}

interface ParsedProductToken {
  product: DistroProduct;
  productToken: string;
  upstreamVersion: string;
  suffix: string;
  headerName: string;
  headerValue: string;
  osFamily: DistroFamily | null;
  osToken: string | null;
}

/**
 * 括弧内の OS 名からディストリビューション系統を特定する
 */
function extractOsFamilyFromHeader(value: string): { family: DistroFamily | null; token: string | null } {
  const m = value.match(/\((Ubuntu|Debian|Red Hat Enterprise Linux|CentOS|AlmaLinux|Rocky Linux)\)/i);
  if (!m) {
    return { family: null, token: null };
  }
  const lower = m[1].toLowerCase();
  if (lower === 'ubuntu') return { family: 'ubuntu', token: m[0] };
  if (lower === 'debian') return { family: 'debian', token: m[0] };
  if (lower === 'red hat enterprise linux') return { family: 'rhel', token: m[0] };
  if (lower === 'centos') return { family: 'centos', token: m[0] };
  if (lower === 'almalinux') return { family: 'almalinux', token: m[0] };
  if (lower === 'rocky linux') return { family: 'rocky', token: m[0] };
  return { family: null, token: null };
}

/**
 * 第三者リポジトリまたはバックポートの印を検出する
 */
function checkThirdPartyMarker(suffix: string): DistroThirdPartyInfo | null {
  if (suffix.includes('deb.sury.org')) {
    return { kind: 'third-party', marker: 'deb.sury.org' };
  }
  const mUbuntu = suffix.match(/\+ubuntu\d+\.\d+(?:\.\d+)?/);
  if (mUbuntu) {
    return { kind: 'third-party', marker: mUbuntu[0] };
  }
  const mBpo = suffix.match(/~bpo\d+(?:\+\d+)?/);
  if (mBpo) {
    return { kind: 'backport', marker: mBpo[0] };
  }
  return null;
}

/**
 * Server・X-Powered-By の値から製品ごとに OS リリースを推定する（§3.1）
 */
export function inferDistroFromHeaders(
  responseHeaders: Record<string, string[] | undefined>,
  distro: AdvisoryDistroSection | null | undefined
): Partial<Record<DistroProduct, DistroInference>> {
  if (!distro || !Array.isArray(distro.map)) {
    return {};
  }

  // 小文字化したヘッダーマップを準備
  const headerKeys = Object.keys(responseHeaders);
  const targetHeaderNames = ['server', 'x-powered-by'];
  const parsedProducts: ParsedProductToken[] = [];
  const seenProducts = new Set<DistroProduct>();

  for (const targetName of targetHeaderNames) {
    const matchedKey = headerKeys.find((k) => k.toLowerCase() === targetName);
    if (!matchedKey) continue;
    const headerValues = responseHeaders[matchedKey];
    if (!Array.isArray(headerValues)) continue;

    for (const rawVal of headerValues) {
      if (typeof rawVal !== 'string') continue;
      const headerValue = rawVal.slice(0, 200);
      const { family: osFamily, token: osToken } = extractOsFamilyFromHeader(headerValue);

      const regex = /([A-Za-z]+)\/(\d+(?:\.\d+)+[a-z]?)(\S*)/g;
      let match: RegExpExecArray | null;
      while ((match = regex.exec(headerValue)) !== null) {
        const prodRaw = match[1].toLowerCase();
        if (prodRaw === 'apache' || prodRaw === 'nginx' || prodRaw === 'php' || prodRaw === 'openssl') {
          const product = prodRaw as DistroProduct;
          if (!seenProducts.has(product)) {
            seenProducts.add(product);
            parsedProducts.push({
              product,
              productToken: `${match[1]}/${match[2]}`,
              upstreamVersion: match[2],
              suffix: match[3],
              headerName: targetName,
              headerValue,
              osFamily,
              osToken,
            });
          }
        }
      }
    }
  }

  const results: Partial<Record<DistroProduct, DistroInference>> = {};

  for (const item of parsedProducts) {
    const evidence: DistroInferenceEvidence[] = [];

    // 手順 2: 第三者・バックポート判定
    const thirdParty = checkThirdPartyMarker(item.suffix);
    if (thirdParty) {
      let family: DistroFamily | null = null;
      if (thirdParty.kind === 'backport' || item.suffix.includes('~bpo')) {
        family = 'debian';
      } else if (item.suffix.includes('+ubuntu')) {
        family = 'ubuntu';
      } else if (item.osFamily) {
        family = item.osFamily;
      }

      evidence.push({
        header: item.headerName,
        value: item.headerValue,
        token: thirdParty.marker,
        detail: thirdParty.kind === 'backport' ? 'Debian バックポートの印を検出しました' : '第三者リポジトリの印を検出しました',
      });
      if (item.osToken) {
        evidence.push({
          header: item.headerName,
          value: item.headerValue,
          token: item.osToken,
          detail: '括弧内の OS 名から系統を判断しました',
        });
      }

      const note = thirdParty.kind === 'backport'
        ? `Debian のバックポート（第三者リポジトリと同じ扱い）の版です（${thirdParty.marker}）。ディストリのデータでは判定しません。`
        : `第三者リポジトリの版です（${thirdParty.marker}）。ディストリのデータでは判定しません。`;

      results[item.product] = {
        family,
        release: null,
        candidates: [],
        confidence: 'none',
        evidence,
        thirdParty,
        note,
      };
      continue;
    }

    // 手順 1: 系統判定
    let family: DistroFamily | null = null;
    let pkgToken: string | null = null;

    const mDeb = item.suffix.match(/[+~]deb(\d+)u\d+/);
    const mEl = item.suffix.match(/\.el(\d+)(?:_\d+)*/);
    const mUbuntu = item.suffix.match(/ubuntu\d+/);

    if (mDeb) {
      family = 'debian';
      pkgToken = mDeb[0];
    } else if (mEl) {
      // 解釈 9: 同じヘッダーに RHEL 系の OS 名があればその系統、無ければ rhel
      if (item.osFamily && (item.osFamily === 'centos' || item.osFamily === 'almalinux' || item.osFamily === 'rocky' || item.osFamily === 'rhel')) {
        family = item.osFamily;
      } else {
        family = 'rhel';
      }
      pkgToken = mEl[0];
    } else if (mUbuntu) {
      family = 'ubuntu';
      pkgToken = mUbuntu[0];
    } else if (item.osFamily) {
      family = item.osFamily;
    }

    if (!family) {
      // 対象の系統の印が無いため推定を付けない
      continue;
    }

    if (item.osToken) {
      evidence.push({
        header: item.headerName,
        value: item.headerValue,
        token: item.osToken,
        detail: '括弧内の OS 名から系統を判断しました',
      });
    }

    // 手順 3.1: パッケージ版の印からリリースを特定
    if (mDeb) {
      const release = `debian:${mDeb[1]}`;
      evidence.push({
        header: item.headerName,
        value: item.headerValue,
        token: mDeb[0],
        detail: 'パッケージ版の印からリリースを特定しました',
      });
      results[item.product] = {
        family,
        release,
        candidates: [release],
        confidence: 'high',
        evidence,
      };
      continue;
    }

    if (mEl) {
      const release = `${family}:${mEl[1]}`;
      evidence.push({
        header: item.headerName,
        value: item.headerValue,
        token: mEl[0],
        detail: 'パッケージ版の印からリリースを特定しました',
      });
      results[item.product] = {
        family,
        release,
        candidates: [release],
        confidence: 'high',
        evidence,
      };
      continue;
    }

    // パッケージ版の系統印（ubuntuNなど）を記録
    if (pkgToken) {
      evidence.push({
        header: item.headerName,
        value: item.headerValue,
        token: pkgToken,
        detail: 'パッケージ版の印から系統を判断しました',
      });
    }

    // 手順 3.2: 対応表から候補を検索
    const matchedReleases: string[] = [];
    for (const entry of distro.map) {
      if (entry.family === family && entry.product === item.product && entry.upstreamVersions.includes(item.upstreamVersion)) {
        if (!matchedReleases.includes(entry.release)) {
          matchedReleases.push(entry.release);
        }
      }
    }

    evidence.push({
      header: item.headerName,
      value: item.headerValue,
      token: item.productToken,
      detail: '対応表からリリース候補を検索しました',
    });

    if (matchedReleases.length === 1) {
      results[item.product] = {
        family,
        release: matchedReleases[0],
        candidates: matchedReleases,
        confidence: 'medium',
        evidence,
      };
    } else if (matchedReleases.length >= 2) {
      results[item.product] = {
        family,
        release: null,
        candidates: matchedReleases,
        confidence: 'low',
        evidence,
      };
    } else {
      results[item.product] = {
        family,
        release: null,
        candidates: [],
        confidence: 'none',
        evidence,
        note: 'リリースを推定できません（対応表に無い版です。自前ビルドや PPA の可能性があります）。',
      };
    }
  }

  // パッケージ版（packageVersion）の抽出と設定 (v1.8.1 T06)
  for (const item of parsedProducts) {
    if (results[item.product]) {
      const suffixMatch = item.suffix.match(/^-[0-9A-Za-z.+~]+/);
      if (suffixMatch) {
        const candidatePkgVer = `${item.upstreamVersion}${suffixMatch[0]}`;
        const parsed = parseDpkgVersion(candidatePkgVer);
        if (parsed && parsed.revision) {
          results[item.product]!.packageVersion = candidatePkgVer;
        }
      }
    }
  }

  // 手順 3.3: 積集合
  const candidateProducts = (Object.keys(results) as DistroProduct[]).filter((p) => {
    const inf = results[p];
    return inf && !inf.thirdParty && inf.candidates.length >= 1;
  });

  if (candidateProducts.length >= 2) {
    const firstProduct = candidateProducts[0];
    const initialCandidates = results[firstProduct]!.candidates;
    const intersection = initialCandidates.filter((rel) =>
      candidateProducts.every((p) => results[p]!.candidates.includes(rel))
    );

    if (intersection.length >= 1) {
      for (const p of candidateProducts) {
        const inf = results[p]!;
        inf.candidates = [...intersection];

        if (intersection.length === 1) {
          inf.release = intersection[0];
          inf.confidence = 'high';
        } else {
          inf.release = null;
          if (inf.confidence !== 'high') {
            inf.confidence = 'low';
          }
        }

        // 他の参加製品のトークンを根拠に追加
        for (const otherProd of candidateProducts) {
          if (otherProd !== p) {
            const otherToken = parsedProducts.find((x) => x.product === otherProd);
            if (otherToken) {
              inf.evidence.push({
                header: otherToken.headerName,
                value: otherToken.headerValue,
                token: otherToken.productToken,
                detail: '同じ応答の別の製品の候補と突き合わせました',
              });
            }
          }
        }
      }
    }
  }

  return results;
}

/**
 * リリース表示名をフォーマットする (v1.8.1 T06: shared/distro-display に委譲)
 */
function formatReleaseName(r: DistroReleaseLifecycle): string {
  return formatDistroReleaseName(r.release, { lts: r.lts });
}

/**
 * 確信度の日本語表記を取得する (v1.8.1 T06: shared/distro-display に委譲)
 */
function formatConfidenceJp(conf: DistroInferenceConfidence): string {
  return formatDistroConfidenceJp(conf);
}

/**
 * 延長サポート名称を取得する
 */
function getExtendedSupportName(family: DistroFamily): string {
  if (family === 'ubuntu') return 'ESM';
  if (family === 'debian') return 'ELTS';
  if (family === 'rhel') return 'ELS';
  return 'ESM / ELS';
}

/**
 * endoflife.date のスラッグ名を取得する
 */
function getDistroSlug(family: DistroFamily): string {
  if (family === 'rocky') return 'rocky-linux';
  return family;
}

/**
 * 推定したリリースのライフサイクルで EOL を判定する（§3.2）
 */
export function judgeDistroEol(
  inference: DistroInference,
  distro: AdvisoryDistroSection | null | undefined,
  now: Date
): DistroEolJudgement | null {
  if (inference.thirdParty || !inference.candidates || inference.candidates.length === 0) {
    return null;
  }
  if (!distro || !Array.isArray(distro.releases) || distro.releases.length === 0) {
    return null;
  }

  // 各候補のライフサイクルを取得（どれか 1 つでも欠けていれば判定しない）
  const candidateLifecycles: DistroReleaseLifecycle[] = [];
  for (const rel of inference.candidates) {
    const lc = distro.releases.find((r) => r.release === rel);
    if (!lc || !lc.standardSupportEnd) {
      return null;
    }
    candidateLifecycles.push(lc);
  }

  // standardSupportEnd が最も早い候補を basis に選択（同日の場合は先頭順）
  let basis = candidateLifecycles[0];
  for (let i = 1; i < candidateLifecycles.length; i++) {
    const cur = candidateLifecycles[i];
    if (cur.standardSupportEnd! < basis.standardSupportEnd!) {
      basis = cur;
    }
  }

  const today = now.toISOString().slice(0, 10);
  const isEol = today > basis.standardSupportEnd!;
  const status: SupportStatus = isEol ? 'EOL' : 'Unknown';

  const confJp = formatConfidenceJp(inference.confidence);
  const extName = getExtendedSupportName(basis.family);
  const slug = getDistroSlug(basis.family);

  const candidateNames = candidateLifecycles.map(formatReleaseName);
  const basisName = formatReleaseName(basis);

  const label = `${candidateNames.join(' / ')}（推定・確信度 ${confJp}）`;

  let note = isEol
    ? `${basisName}（推定・確信度 ${confJp}）：標準サポートは ${basis.standardSupportEnd} に終了。${extName} で延長されている可能性があります。`
    : `${basisName}（推定・確信度 ${confJp}）：標準サポートは ${basis.standardSupportEnd} まで（推定）。`;

  if (candidateLifecycles.length >= 2) {
    note += ` 候補: ${candidateNames.join('、')}。いちばん早く終わる ${basisName} で判定しています。`;
  }

  const recommendation = isEol
    ? `サポート中のリリースへの更新を検討してください。延長サポート（${extName}）を利用している場合は、その期限を確認してください。`
    : 'サーバー側で OS のリリースとサポート期限を確認してください。';

  const eolInfo: EolInfo = {
    status,
    eolDate: basis.standardSupportEnd,
    source: 'endoflife.date（OS のライフサイクル）',
    sourceUrl: `https://endoflife.date/${slug}`,
    recommendation,
    label,
    note,
  };

  return {
    basisRelease: basis.release,
    eolInfo,
  };
}
