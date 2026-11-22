/**
 * Web Technology & Security Inspector
 * 脆弱性DB 出典（sources）構造化・構築モジュール (scripts/advisories/lib/sources.mjs)
 *
 * - v1.8.2 T06 (H9・H10、指示書 §5.2・§5.3)
 * - 最上位 sources をオブジェクトの配列にし、各出典にライセンス情報 (license または licenseNote) を付与
 */

/** 最上位の sources の定義（§5.2） */
export const DB_SOURCE_DEFINITIONS = [
  {
    key: 'nvd',
    name: 'NIST National Vulnerability Database (NVD)',
    url: 'https://nvd.nist.gov/',
    ecosystem: null,
    license: null,
    licenseNote: '米国政府（NIST）の公開データ。NVD API の利用規約に従い、NVD の表示文を拡張機能内に載せます（NVD による承認・認定は受けていません）',
  },
  {
    key: 'ghsa',
    name: 'GitHub Advisory Database (OSV.dev 経由: npm / Packagist)',
    url: 'https://github.com/github/advisory-database',
    ecosystem: null,
    license: 'CC-BY-4.0',
    licenseNote: 'OSV.dev 経由で取得し、影響範囲・重大度・タイトルを加工して収録しています',
  },
  {
    key: 'ubuntu',
    name: 'OSV.dev (Ubuntu Security Notices)',
    url: 'https://github.com/canonical/ubuntu-security-notices',
    ecosystem: 'Ubuntu',
    license: 'CC-BY-SA-4.0',
    licenseNote: 'Ubuntu の部分は CC BY-SA 4.0 です。OSV.dev 経由で取得し、状態・修正版を加工して収録しています',
  },
  {
    key: 'debian',
    name: 'OSV.dev (Debian Security Tracker)',
    url: 'https://osv.dev/list?ecosystem=Debian',
    ecosystem: 'Debian',
    license: null,
    licenseNote: 'ライセンスの明記なし（出典のみ表示）',
  },
  {
    key: 'endoflife',
    name: 'endoflife.date',
    url: 'https://endoflife.date/',
    ecosystem: null,
    license: 'MIT',
    licenseNote: 'Copyright 2020 endoflife.date contributors。製品のサポート期間だけを収録しています（製品の説明文は使っていません）',
  },
  {
    key: 'kev',
    name: 'CISA Known Exploited Vulnerabilities Catalog',
    url: 'https://github.com/cisagov/kev-data',
    ecosystem: null,
    license: 'CC0-1.0',
  },
];

function pickLatestDate(dates) {
  const valid = dates.filter((d) => typeof d === 'string' && !Number.isNaN(Date.parse(d)));
  if (valid.length === 0) return null;
  valid.sort();
  return valid[valid.length - 1];
}

/**
 * @param {{
 *   upstream?: object,
 *   libraries?: object,
 *   eolSourceByProduct?: Record<string, string>,
 *   distroSection?: object | null
 * }} input
 * @returns {Array<{ name: string, url: string, ecosystem: string | null, license: string | null, licenseNote?: string, retrievedAt: string | null, recordCount: number }>}
 */
export function buildDbSources({ upstream = {}, libraries = {}, eolSourceByProduct = {}, distroSection = null } = {}) {
  const allVersions = Object.values(libraries || {}).flatMap((lib) =>
    Array.isArray(lib?.versions) ? lib.versions : []
  );

  const sources = [];

  for (const def of DB_SOURCE_DEFINITIONS) {
    if ((def.key === 'ubuntu' || def.key === 'debian') && !distroSection) {
      continue;
    }

    let retrievedAt = null;
    let recordCount = 0;

    switch (def.key) {
      case 'nvd': {
        const dates = [];
        if (upstream?.nvd) {
          for (const v of Object.values(upstream.nvd)) {
            if (typeof v?.fetchedAt === 'string') dates.push(v.fetchedAt);
          }
        }
        if (upstream?.nvdScores) {
          if (typeof upstream.nvdScores?.fetchedAt === 'string') dates.push(upstream.nvdScores.fetchedAt);
          for (const v of Object.values(upstream.nvdScores)) {
            if (typeof v?.fetchedAt === 'string') dates.push(v.fetchedAt);
          }
        }
        if (upstream?.manifest?.sources) {
          for (const [k, v] of Object.entries(upstream.manifest.sources)) {
            if ((k.startsWith('nvd:') || k === 'nvd-scores' || k === 'nvd') && typeof v?.fetchedAt === 'string') {
              dates.push(v.fetchedAt);
            }
          }
        }
        retrievedAt = pickLatestDate(dates);
        recordCount = allVersions.filter((v) => Array.isArray(v?.sources) && v.sources.includes('nvd')).length;
        break;
      }

      case 'ghsa': {
        const dates = [];
        if (upstream?.osv) {
          for (const v of Object.values(upstream.osv)) {
            if (typeof v?.fetchedAt === 'string') dates.push(v.fetchedAt);
          }
        }
        if (upstream?.manifest?.sources) {
          for (const [k, v] of Object.entries(upstream.manifest.sources)) {
            if ((k.startsWith('osv:') || k === 'osv') && typeof v?.fetchedAt === 'string') {
              dates.push(v.fetchedAt);
            }
          }
        }
        retrievedAt = pickLatestDate(dates);
        recordCount = allVersions.filter((v) => Array.isArray(v?.sources) && v.sources.includes('osv')).length;
        break;
      }

      case 'ubuntu':
      case 'debian': {
        const eco = def.ecosystem;
        const inner = Array.isArray(distroSection?._source)
          ? distroSection._source.find((s) => s?.ecosystem === eco)
          : null;
        if (inner) {
          retrievedAt = inner.retrievedAt ?? null;
          recordCount = inner.recordCount ?? 0;
        } else {
          retrievedAt = null;
          recordCount = 0;
        }
        break;
      }

      case 'endoflife': {
        const dates = [];
        if (upstream?.eol) {
          for (const v of Object.values(upstream.eol)) {
            if (typeof v?.fetchedAt === 'string') dates.push(v.fetchedAt);
          }
        }
        if (upstream?.distroEol) {
          for (const v of Object.values(upstream.distroEol)) {
            if (typeof v?.fetchedAt === 'string') dates.push(v.fetchedAt);
          }
        }
        if (upstream?.manifest?.sources) {
          for (const [k, v] of Object.entries(upstream.manifest.sources)) {
            if ((k.startsWith('eol:') || k.startsWith('distro-eol:') || k === 'eol' || k === 'distro-eol') && typeof v?.fetchedAt === 'string') {
              dates.push(v.fetchedAt);
            }
          }
        }
        retrievedAt = pickLatestDate(dates);

        let libCycles = 0;
        for (const [k, lib] of Object.entries(libraries || {})) {
          if (eolSourceByProduct?.[k] === 'endoflife.date' && Array.isArray(lib?.eol)) {
            libCycles += lib.eol.length;
          }
        }
        let distroEolCount = 0;
        if (distroSection && Array.isArray(distroSection._source)) {
          const eolSrc = distroSection._source.find((s) => s?.ecosystem === null);
          if (eolSrc && typeof eolSrc.recordCount === 'number') {
            distroEolCount = eolSrc.recordCount;
          }
        }
        recordCount = libCycles + distroEolCount;
        break;
      }

      case 'kev': {
        const dates = [];
        if (typeof upstream?.manifest?.sources?.kev?.fetchedAt === 'string') {
          dates.push(upstream.manifest.sources.kev.fetchedAt);
        }
        if (typeof upstream?.kev?.fetchedAt === 'string') {
          dates.push(upstream.kev.fetchedAt);
        }
        retrievedAt = pickLatestDate(dates);
        recordCount = allVersions.filter((v) => v?.kev === true).length;
        break;
      }

      default:
        break;
    }

    const item = {
      name: def.name,
      url: def.url,
      ecosystem: def.ecosystem,
      license: def.license,
      ...(def.licenseNote ? { licenseNote: def.licenseNote } : {}),
      retrievedAt,
      recordCount,
    };
    sources.push(item);
  }

  return sources;
}
