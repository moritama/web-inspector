/**
 * Web Technology & Security Inspector
 * ディストリビューション情報 (ライフサイクル・対応表) 処理 (scripts/advisories/lib/distro.mjs)
 *
 * - v1.8.1 T02 (NEW-04 第2・第3段階の土台)
 * - OS のライフサイクルと上流版→OS リリース対応表の検証・DB 組み立て
 */

import { cleanText } from './sanitize.mjs';

export const DISTRO_FAMILIES = ['ubuntu', 'debian', 'rhel', 'centos', 'almalinux', 'rocky'];
export const DISTRO_PRODUCTS = ['apache', 'nginx', 'php', 'openssl'];
export const DISTRO_SECTION_MAX_BYTES = 800 * 1024;

/** evidenceUrl に許可するホスト（完全一致） */
export const DISTRO_EVIDENCE_HOSTS = new Set([
  'launchpad.net',
  'api.launchpad.net',
  'sources.debian.org',
  'tracker.debian.org',
  'packages.debian.org',
  'security-tracker.debian.org',
  'access.redhat.com',
  'docs.redhat.com',
  'dl.rockylinux.org',
  'repo.almalinux.org',
  'vault.almalinux.org',
  'vault.centos.org',
]);

/**
 * evidenceUrl の検証 (https, 許可ホスト, 認証情報なし, 特殊文字なし)
 */
export function isDistroEvidenceUrl(value) {
  if (typeof value !== 'string') return false;
  if (/["'<>\s`]/.test(value)) return false;
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:') return false;
    if (url.username || url.password) return false;
    if (!DISTRO_EVIDENCE_HOSTS.has(url.hostname)) return false;
    return true;
  } catch {
    return false;
  }
}

/**
 * distro-map のエントリ 1 件の検証 (不正時は Error を投げる)
 */
export function validateDistroMapEntry(entry, releasesByFamily) {
  if (!entry || typeof entry !== 'object') {
    throw new Error('対応表の項目がオブジェクトではありません');
  }
  if (!DISTRO_FAMILIES.includes(entry.family)) {
    throw new Error(`不正な family: ${entry.family}`);
  }
  if (typeof entry.release !== 'string') {
    throw new Error(`不正な release: ${entry.release}`);
  }
  const relMatch = /^([a-z]+):([0-9][0-9.]*)$/.exec(entry.release);
  if (!relMatch || relMatch[1] !== entry.family) {
    throw new Error(`release が family と一致しません: ${entry.release} vs ${entry.family}`);
  }
  if (releasesByFamily) {
    const allowed = releasesByFamily[entry.family];
    if (!Array.isArray(allowed) || !allowed.includes(relMatch[2])) {
      throw new Error(`release が catalog の OS の節にありません: ${entry.release}`);
    }
  }
  if (entry.codename !== null && (typeof entry.codename !== 'string' || /[<>"'`\x00-\x1F\x7F]/.test(entry.codename))) {
    throw new Error(`不正な codename: ${entry.codename}`);
  }
  if (!DISTRO_PRODUCTS.includes(entry.product)) {
    throw new Error(`不正な product: ${entry.product}`);
  }
  if (
    !Array.isArray(entry.upstreamVersions) ||
    entry.upstreamVersions.length === 0 ||
    !entry.upstreamVersions.every((v) => typeof v === 'string' && /^\d+(?:\.\d+)+[a-z]?$/.test(v))
  ) {
    throw new Error(`不正な upstreamVersions: ${JSON.stringify(entry.upstreamVersions)}`);
  }
  if (typeof entry.sourcePackage !== 'string' || !/^[a-z0-9][a-z0-9.+-]+$/.test(entry.sourcePackage)) {
    throw new Error(`不正な sourcePackage: ${entry.sourcePackage}`);
  }
  if (typeof entry.verifiedAt !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(entry.verifiedAt)) {
    throw new Error(`不正な verifiedAt: ${entry.verifiedAt}`);
  }
  const d = new Date(`${entry.verifiedAt}T00:00:00Z`);
  if (Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== entry.verifiedAt) {
    throw new Error(`実在しない日付 verifiedAt: ${entry.verifiedAt}`);
  }
  if (!isDistroEvidenceUrl(entry.evidenceUrl)) {
    throw new Error(`不正な evidenceUrl: ${entry.evidenceUrl}`);
  }
}

/**
 * distro 節を組み立てる
 */
export function buildDistroSection({ distros, distroEol, distroMap }) {
  const warnings = [];
  let map = [];
  if (distroMap && Array.isArray(distroMap.entries)) {
    const releasesByFamily = distros
      ? Object.fromEntries(Object.entries(distros).map(([fam, d]) => [fam, d?.releases || []]))
      : null;
    const seenKeys = new Set();
    map = distroMap.entries.map((entry) => {
      validateDistroMapEntry(entry, releasesByFamily);
      const key = `${entry.release}|${entry.product}|${entry.sourcePackage}`;
      if (seenKeys.has(key)) {
        throw new Error(`重複する対応表項目: ${key}`);
      }
      seenKeys.add(key);
      return {
        family: entry.family,
        release: entry.release,
        codename: entry.codename ?? null,
        product: entry.product,
        upstreamVersions: [...entry.upstreamVersions],
        sourcePackage: entry.sourcePackage,
        verifiedAt: entry.verifiedAt,
        evidenceUrl: entry.evidenceUrl,
      };
    });
  } else if (!distroMap) {
    warnings.push('distroMap が指定されていません');
  }

  const releases = [];
  if (distros && typeof distros === 'object') {
    for (const [family, conf] of Object.entries(distros)) {
      const slug = conf?.eol?.slug || family;
      const eolData = distroEol ? distroEol[slug] : null;
      if (!eolData || !Array.isArray(eolData.cycles)) {
        warnings.push(`OS のライフサイクルの取得結果がありません: ${family} (${slug})`);
        continue;
      }
      const allowedReleases = Array.isArray(conf?.releases) ? conf.releases : [];
      for (const cycle of allowedReleases) {
        const c = eolData.cycles.find((item) => String(item.cycle) === String(cycle));
        if (!c) {
          warnings.push(`OS のサイクルが取得結果にありません: ${family}:${cycle}`);
          continue;
        }
        const cleanedCodename = c.codename ? cleanText(c.codename, 60) || null : null;
        const isLts = c.lts === true || typeof c.lts === 'string';
        const releaseDate = typeof c.releaseDate === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(c.releaseDate) ? c.releaseDate : null;
        const standardSupportEnd = typeof c.eol === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(c.eol) ? c.eol : null;
        const extendedSupportEnd = typeof c.extendedSupport === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(c.extendedSupport) ? c.extendedSupport : null;

        releases.push({
          release: `${family}:${cycle}`,
          family,
          cycle: String(cycle),
          codename: cleanedCodename,
          lts: isLts,
          releaseDate,
          standardSupportEnd,
          extendedSupportEnd,
        });
      }
    }
  }

  return {
    distro: { releases, map },
    warnings,
  };
}

/**
 * DB 内の distro 節を検証する
 */
export function validateDistroSection(distro) {
  if (!distro || typeof distro !== 'object') {
    throw new Error('distro 節がオブジェクトではありません');
  }
  if (!Array.isArray(distro.releases)) {
    throw new Error('distro.releases が配列ではありません');
  }
  if (!Array.isArray(distro.map)) {
    throw new Error('distro.map が配列ではありません');
  }
  for (const r of distro.releases) {
    if (!r || typeof r !== 'object') {
      throw new Error('distro.releases の要素がオブジェクトではありません');
    }
    if (!DISTRO_FAMILIES.includes(r.family)) {
      throw new Error(`distro.releases の family が不正です: ${r.family}`);
    }
    if (typeof r.cycle !== 'string' || r.cycle.length === 0) {
      throw new Error(`distro.releases の cycle が不正です: ${r.cycle}`);
    }
    if (r.release !== `${r.family}:${r.cycle}`) {
      throw new Error(`distro.releases の release が一致しません: ${r.release} vs ${r.family}:${r.cycle}`);
    }
    if (r.codename !== null && (typeof r.codename !== 'string' || /[<>"'`\x00-\x1F\x7F]/.test(r.codename))) {
      throw new Error(`distro.releases の codename が不正です: ${r.codename}`);
    }
    if (typeof r.lts !== 'boolean') {
      throw new Error(`distro.releases の lts が真偽値ではありません: ${r.lts}`);
    }
    if (r.releaseDate !== null && (typeof r.releaseDate !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(r.releaseDate))) {
      throw new Error(`distro.releases の releaseDate が不正です: ${r.releaseDate}`);
    }
    if (r.standardSupportEnd !== null && (typeof r.standardSupportEnd !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(r.standardSupportEnd))) {
      throw new Error(`distro.releases の standardSupportEnd が不正です: ${r.standardSupportEnd}`);
    }
    if (r.extendedSupportEnd !== null && (typeof r.extendedSupportEnd !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(r.extendedSupportEnd))) {
      throw new Error(`distro.releases の extendedSupportEnd が不正です: ${r.extendedSupportEnd}`);
    }
  }
  for (const m of distro.map) {
    validateDistroMapEntry(m, null);
  }

  // v1.8.1 T05: advisories と _source の検査
  // どちらか一方でもあれば両方が必須 (両方無ければ T02 までの形として通す)
  if (distro.advisories !== undefined || distro._source !== undefined) {
    if (distro._source === undefined) {
      throw new Error('distro._source がありません');
    }
    if (distro.advisories === undefined) {
      throw new Error('distro.advisories がありません');
    }

    // _source の検証
    if (!Array.isArray(distro._source) || distro._source.length === 0) {
      throw new Error('distro._source が空または配列ではありません');
    }
    const hasDebian = distro._source.some((s) => s.ecosystem === 'Debian');
    if (!hasDebian) {
      throw new Error('distro._source に Debian の情報がありません');
    }
    const hasUbuntu = distro._source.some((s) => s.ecosystem === 'Ubuntu');
    if (!hasUbuntu) {
      throw new Error('distro._source に Ubuntu の情報がありません');
    }
    const hasEol = distro._source.some((s) => s.ecosystem === null && typeof s.url === 'string' && s.url.startsWith('https://endoflife.date/'));
    if (!hasEol) {
      throw new Error('distro._source に endoflife.date の情報がありません');
    }

    for (const s of distro._source) {
      if (!s || typeof s !== 'object') {
        throw new Error('distro._source の要素がオブジェクトではありません');
      }
      if (typeof s.name !== 'string' || s.name.length === 0) {
        throw new Error(`distro._source の name が不正です: ${s.name}`);
      }
      if (typeof s.url !== 'string' || !s.url.startsWith('https://')) {
        throw new Error(`distro._source の url が不正です: ${s.url}`);
      }
      const hasLicense = typeof s.license === 'string' && s.license.length > 0;
      const hasLicenseNote = typeof s.licenseNote === 'string' && s.licenseNote.length > 0;
      if (!hasLicense && !hasLicenseNote) {
        throw new Error(`distro._source の license または licenseNote が必要です: ${s.name}`);
      }
      if (s.retrievedAt !== null && (typeof s.retrievedAt !== 'string' || Number.isNaN(new Date(s.retrievedAt).getTime()))) {
        throw new Error(`distro._source の retrievedAt が不正です: ${s.retrievedAt}`);
      }
      if (typeof s.recordCount !== 'number' || s.recordCount < 0 || !Number.isInteger(s.recordCount)) {
        throw new Error(`distro._source の recordCount が不正です: ${s.recordCount}`);
      }
    }

    // advisories の検証
    if (!distro.advisories || typeof distro.advisories !== 'object' || Array.isArray(distro.advisories)) {
      throw new Error('distro.advisories がオブジェクトではありません');
    }
    const ALLOWED_ENTRY_KEYS = new Set(['cve', 'status', 'fixedVersions', 'esm', 'osvIds']);
    for (const [release, byPkg] of Object.entries(distro.advisories)) {
      if (!/^(debian|ubuntu):[0-9][0-9.]*$/.test(release)) {
        throw new Error(`distro.advisories の release キーが不正です: ${release}`);
      }
      if (!byPkg || typeof byPkg !== 'object' || Array.isArray(byPkg)) {
        throw new Error(`distro.advisories[${release}] がオブジェクトではありません`);
      }
      for (const [pkg, entries] of Object.entries(byPkg)) {
        if (!/^[a-z0-9][a-z0-9.+-]+$/.test(pkg)) {
          throw new Error(`distro.advisories[${release}] の package キーが不正です: ${pkg}`);
        }
        if (!Array.isArray(entries)) {
          throw new Error(`distro.advisories[${release}][${pkg}] が配列ではありません`);
        }
        for (const e of entries) {
          if (!e || typeof e !== 'object' || Array.isArray(e)) {
            throw new Error(`distro.advisories のエントリがオブジェクトではありません`);
          }
          for (const k of Object.keys(e)) {
            if (!ALLOWED_ENTRY_KEYS.has(k)) {
              throw new Error(`distro.advisories エントリのキーが不正です: ${k}`);
            }
          }
          if (typeof e.cve !== 'string' || !/^CVE-\d{4}-\d{4,7}$/.test(e.cve)) {
            throw new Error(`distro.advisories の cve が不正です: ${e.cve}`);
          }
          if (e.status !== 'fixed' && e.status !== 'open' && e.status !== 'not-affected') {
            throw new Error(`distro.advisories の status が不正です: ${e.status}`);
          }
          if (!Array.isArray(e.fixedVersions)) {
            throw new Error(`distro.advisories の fixedVersions が配列ではありません`);
          }
          for (const v of e.fixedVersions) {
            if (typeof v !== 'string' || !/^[0-9][0-9A-Za-z.+~:-]{0,99}$/.test(v)) {
              throw new Error(`distro.advisories の fixedVersions の要素が不正です: ${v}`);
            }
          }
          if (e.status === 'fixed' && e.fixedVersions.length === 0) {
            throw new Error(`distro.advisories で fixed なのに fixedVersions が空です: ${e.cve}`);
          }
          if (e.status !== 'fixed' && e.fixedVersions.length > 0) {
            throw new Error(`distro.advisories で fixed でないのに fixedVersions があります: ${e.cve}`);
          }
          if (e.esm !== undefined) {
            if (e.esm !== true || e.status !== 'fixed') {
              throw new Error(`distro.advisories の esm は fixed のとき true のみ許容されます: ${e.cve}`);
            }
          }
          if (!Array.isArray(e.osvIds) || e.osvIds.length === 0) {
            throw new Error(`distro.advisories の osvIds が空または配列ではありません: ${e.cve}`);
          }
          for (const osvId of e.osvIds) {
            if (typeof osvId !== 'string' || !/^(?:USN|LSN|UBUNTU|DEBIAN|DSA|DLA|DTSA)-[0-9A-Za-z.-]{1,60}$/.test(osvId)) {
              throw new Error(`distro.advisories の osvIds の要素が不正です: ${osvId}`);
            }
          }
        }
      }
    }
  }

  // サイズ検査 (800 KB)
  const bytes = Buffer.byteLength(JSON.stringify(distro));
  if (bytes > DISTRO_SECTION_MAX_BYTES) {
    throw new Error(`distro 節のサイズが上限(800 KB)を超過しています: ${bytes} bytes > ${DISTRO_SECTION_MAX_BYTES} bytes`);
  }
}
