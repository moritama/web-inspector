/**
 * Web Technology & Security Inspector
 * OSV (Debian / Ubuntu) データの取り込みと圧縮 (scripts/advisories/lib/osv-distro.mjs)
 *
 * - v1.8.1 T05 (NEW-04 バックポート対応 第3段階)
 * - Debian / Ubuntu の「リリース×ソースパッケージ」の脆弱性レコードを OSV から取得・圧縮・構築
 */

import { fetchOsvPackage } from './osv.mjs';

export const OSV_DISTRO_FAMILIES = ['debian', 'ubuntu'];
export const OSV_DISTRO_PRODUCTS = ['apache', 'nginx', 'php'];

/**
 * Ubuntu のリリース番号が LTS かを判定する（偶数年の .04）
 * @param {string} version '20.04' -> true, '26.10' -> false
 * @returns {boolean}
 */
export function isUbuntuLts(version) {
  if (typeof version !== 'string') return false;
  const m = /^(\d+)\.04$/.exec(version);
  if (!m) return false;
  return parseInt(m[1], 10) % 2 === 0;
}

/**
 * リリース（'debian:12' / 'ubuntu:20.04'）を OSV のエコシステム名の配列にする。対象外なら []
 * @param {string} release
 * @returns {string[]}
 */
export function osvEcosystemsFor(release) {
  if (typeof release !== 'string') return [];
  const [family, version] = release.split(':');
  if (family === 'debian') {
    return [`Debian:${version}`];
  }
  if (family === 'ubuntu') {
    if (isUbuntuLts(version)) {
      return [`Ubuntu:${version}:LTS`, `Ubuntu:Pro:${version}:LTS`];
    }
    return [`Ubuntu:${version}`];
  }
  return [];
}

/**
 * 対応表から取得の対象を作る（family が OSV_DISTRO_FAMILIES、product が OSV_DISTRO_PRODUCTS の項目。release|sourcePackage で重複を除き、entries の順）
 * @param {{ entries?: Array<{ family: string, release: string, product: string, sourcePackage: string }> }} distroMap
 * @returns {Array<{ release: string, family: string, sourcePackage: string, ecosystems: string[] }>}
 */
export function osvDistroTargets(distroMap) {
  if (!distroMap || !Array.isArray(distroMap.entries)) return [];
  const targets = [];
  const seen = new Set();
  for (const entry of distroMap.entries) {
    if (!OSV_DISTRO_FAMILIES.includes(entry.family)) continue;
    if (!OSV_DISTRO_PRODUCTS.includes(entry.product)) continue;
    const key = `${entry.release}|${entry.sourcePackage}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const ecosystems = osvEcosystemsFor(entry.release);
    targets.push({
      release: entry.release,
      family: entry.family,
      sourcePackage: entry.sourcePackage,
      ecosystems,
    });
  }
  return targets;
}

/**
 * 取得: 1 つのエコシステム×パッケージを取る（既存の fetchOsvPackage を使う）
 * @param {{ ecosystem: string, name: string }} target
 * @param {(url: string, init?: object) => Promise<any>} fetchJson
 * @returns {Promise<any[]>}
 */
export async function fetchOsvDistroPackage({ ecosystem, name }, fetchJson) {
  return fetchOsvPackage({ ecosystem, name }, fetchJson);
}

/**
 * 圧縮（保存用）: 1 レコードから、そのパッケージ・エコシステムの行だけを残す
 * @param {object} vuln
 * @param {{ ecosystem: string, name: string }} target
 * @returns {{ id: string, withdrawn: string|null, modified: string|null, cves: string[], cveLevel: boolean, affected: Array<{ ecosystem: string, introduced: boolean, fixed: string[] }> }}
 */
export function compactOsvDistroVuln(vuln, { ecosystem, name }) {
  const cveLevel = /^(?:UBUNTU|DEBIAN)-(CVE-\d{4}-\d{4,7})$/.test(vuln.id);
  let cves = [];
  if (cveLevel) {
    const m = /^(?:UBUNTU|DEBIAN)-(CVE-\d{4}-\d{4,7})$/.exec(vuln.id);
    cves = [m[1]];
  } else {
    const set = new Set();
    for (const item of [...(vuln.upstream || []), ...(vuln.aliases || [])]) {
      if (/^CVE-\d{4}-\d{4,7}$/.test(item)) {
        set.add(item);
      }
    }
    cves = [...set].sort();
  }

  const affected = [];
  for (const a of vuln.affected || []) {
    if (a.package && a.package.ecosystem === ecosystem && a.package.name === name) {
      let introduced = false;
      const fixed = [];
      for (const r of a.ranges || []) {
        if (r.type === 'ECOSYSTEM') {
          for (const ev of r.events || []) {
            if (ev.introduced !== undefined) introduced = true;
            if (typeof ev.fixed === 'string') fixed.push(ev.fixed);
          }
        }
      }
      affected.push({ ecosystem, introduced, fixed });
    }
  }

  return {
    id: vuln.id,
    withdrawn: vuln.withdrawn || null,
    modified: vuln.modified || null,
    cves,
    cveLevel,
    affected,
  };
}

/**
 * 構築: 取得結果から distro.advisories と警告・数を作る
 * @param {{ targets: Array<{ release: string, family: string, sourcePackage: string, ecosystems: string[] }>, osvDistro: Record<string, any> }} options
 * @returns {{ advisories: Record<string, Record<string, any[]>>, warnings: string[], skipped: Record<string, number>, recordIds: { debian: Set<string>, ubuntu: Set<string> } }}
 */
export function buildDistroAdvisories({ targets = [], osvDistro = {} }) {
  const advisories = {};
  const warnings = [];
  const skipped = {};
  const recordIds = { debian: new Set(), ubuntu: new Set() };

  for (const target of targets) {
    const { release, family, sourcePackage, ecosystems } = target;

    // 1. 全エコシステムのスナップショットが存在するか検査
    let missingEco = null;
    for (const eco of ecosystems) {
      const key = `${eco}:${sourcePackage}`;
      if (!osvDistro[key]) {
        missingEco = eco;
        break;
      }
    }
    if (missingEco) {
      warnings.push(`OSV のディストリのデータがありません: ${release} ${sourcePackage}（${missingEco}）`);
      continue;
    }

    // 2. スナップショットからレコードを収集・統合
    const vulnsById = new Map();
    for (const eco of ecosystems) {
      const snap = osvDistro[`${eco}:${sourcePackage}`];
      for (const v of snap.vulns || []) {
        if (v.withdrawn) {
          skipped.withdrawn = (skipped.withdrawn || 0) + 1;
          continue;
        }
        if (!vulnsById.has(v.id)) {
          vulnsById.set(v.id, {
            id: v.id,
            cves: v.cves || [],
            cveLevel: Boolean(v.cveLevel),
            affected: [...(v.affected || [])],
          });
        } else {
          const existing = vulnsById.get(v.id);
          existing.affected.push(...(v.affected || []));
        }
      }
    }

    // 3. 観察 (observations) の収集
    const obsByCve = new Map();

    for (const v of vulnsById.values()) {
      if (!v.cves || v.cves.length === 0) {
        skipped['no-cve'] = (skipped['no-cve'] || 0) + 1;
        continue;
      }

      const targetObs = [];
      for (const a of v.affected) {
        if (!ecosystems.includes(a.ecosystem)) continue;

        if (a.fixed && a.fixed.length > 0) {
          const validFixed = a.fixed.filter((f) => /^[0-9][0-9A-Za-z.+~:-]{0,99}$/.test(f));
          if (validFixed.length === 0) {
            skipped['invalid-fixed'] = (skipped['invalid-fixed'] || 0) + 1;
            continue;
          }
          for (const f of validFixed) {
            const esm = a.ecosystem.includes(':Pro:') || /[+~]esm\d*/.test(f);
            targetObs.push({
              osvId: v.id,
              cveLevel: v.cveLevel,
              fixed: f,
              esm,
            });
          }
        } else if (a.introduced) {
          const esm = a.ecosystem.includes(':Pro:');
          targetObs.push({
            osvId: v.id,
            cveLevel: v.cveLevel,
            fixed: null,
            esm,
          });
        }
      }

      if (targetObs.length > 0) {
        if (recordIds[family]) {
          recordIds[family].add(v.id);
        }
        for (const cve of v.cves) {
          if (!obsByCve.has(cve)) obsByCve.set(cve, []);
          obsByCve.get(cve).push(...targetObs);
        }
      }
    }

    // 4. CVE ごとに判定
    const entries = [];
    const sortedCves = [...obsByCve.keys()].sort();

    for (const cve of sortedCves) {
      const obsList = obsByCve.get(cve);
      const osvIds = [...new Set(obsList.map((o) => o.osvId))].sort();

      const cveObs = obsList.filter((o) => o.cveLevel);
      const effectiveObs = cveObs.length > 0 ? cveObs : obsList;

      const stdFixed = [...new Set(effectiveObs.filter((o) => !o.esm && o.fixed !== null).map((o) => o.fixed))].sort();
      const esmFixed = [...new Set(effectiveObs.filter((o) => o.esm && o.fixed !== null).map((o) => o.fixed))].sort();

      let status;
      let fixedVersions = [];
      let esm = false;

      if (stdFixed.length > 0) {
        status = 'fixed';
        fixedVersions = stdFixed;
      } else if (esmFixed.length > 0) {
        status = 'fixed';
        fixedVersions = esmFixed;
        esm = true;
      } else {
        status = 'open';
        fixedVersions = [];
      }

      const entry = {
        cve,
        status,
        fixedVersions,
        ...(esm ? { esm: true } : {}),
        osvIds,
      };
      entries.push(entry);
    }

    if (!advisories[release]) {
      advisories[release] = {};
    }
    advisories[release][sourcePackage] = entries;
  }

  return { advisories, warnings, skipped, recordIds };
}

/**
 * 出典: catalog.distroSources と取得結果から distro._source を作る。定義が不正なら Error
 * @param {{ definitions: any[], osvDistro?: Record<string, any>, distroEol?: Record<string, any>, advisories?: Record<string, any>, releases?: any[] }} options
 * @returns {Array<{ name: string, url: string, ecosystem: string|null, license: string|null, licenseNote?: string, retrievedAt: string|null, recordCount: number }>}
 */
export function buildDistroSources({ definitions, osvDistro = {}, distroEol = {}, advisories = {}, releases = [] }) {
  if (!Array.isArray(definitions)) {
    throw new Error('catalog.json に distroSources (出典の定義) がありません');
  }
  const hasDebian = definitions.some((d) => d && d.ecosystem === 'Debian');
  if (!hasDebian) {
    throw new Error('catalog.distroSources に Debian の出典の定義がありません');
  }
  const hasUbuntu = definitions.some((d) => d && d.ecosystem === 'Ubuntu');
  if (!hasUbuntu) {
    throw new Error('catalog.distroSources に Ubuntu の出典の定義がありません');
  }
  const hasEol = definitions.some((d) => d && d.ecosystem === null && typeof d.url === 'string' && d.url.startsWith('https://endoflife.date/'));
  if (!hasEol) {
    throw new Error('catalog.distroSources に endoflife.date の出典の定義がありません');
  }

  for (const d of definitions) {
    if (!d || typeof d !== 'object') {
      throw new Error('distroSources の要素がオブジェクトではありません');
    }
    if (typeof d.name !== 'string' || d.name.length === 0) {
      throw new Error(`distroSources の name が不正です: ${d.name}`);
    }
    if (typeof d.url !== 'string' || !d.url.startsWith('https://')) {
      throw new Error(`distroSources の url が不正です: ${d.url}`);
    }
    const hasLicense = typeof d.license === 'string' && d.license.length > 0;
    const hasLicenseNote = typeof d.licenseNote === 'string' && d.licenseNote.length > 0;
    if (!hasLicense && !hasLicenseNote) {
      throw new Error(`distroSources の各定義には license または licenseNote が必要です: ${d.name}`);
    }
  }

  const getOsvStats = (family) => {
    const prefix = family === 'debian' ? 'Debian:' : 'Ubuntu:';
    let latestFetchedAt = null;
    for (const [key, snap] of Object.entries(osvDistro)) {
      if (key.startsWith(prefix) && snap && snap.fetchedAt) {
        if (!latestFetchedAt || snap.fetchedAt > latestFetchedAt) {
          latestFetchedAt = snap.fetchedAt;
        }
      }
    }

    const idSet = new Set();
    for (const [rel, byPkg] of Object.entries(advisories)) {
      if (rel.startsWith(`${family}:`)) {
        for (const list of Object.values(byPkg)) {
          for (const e of list) {
            for (const osvId of e.osvIds || []) {
              idSet.add(osvId);
            }
          }
        }
      }
    }

    return {
      retrievedAt: latestFetchedAt,
      recordCount: idSet.size,
    };
  };

  let latestEolFetchedAt = null;
  for (const snap of Object.values(distroEol)) {
    if (snap && snap.fetchedAt) {
      if (!latestEolFetchedAt || snap.fetchedAt > latestEolFetchedAt) {
        latestEolFetchedAt = snap.fetchedAt;
      }
    }
  }

  const sources = [];
  for (const def of definitions) {
    let retrievedAt = null;
    let recordCount = 0;

    if (def.ecosystem === 'Debian') {
      const stats = getOsvStats('debian');
      retrievedAt = stats.retrievedAt;
      recordCount = stats.recordCount;
    } else if (def.ecosystem === 'Ubuntu') {
      const stats = getOsvStats('ubuntu');
      retrievedAt = stats.retrievedAt;
      recordCount = stats.recordCount;
    } else if (def.ecosystem === null && typeof def.url === 'string' && def.url.startsWith('https://endoflife.date/')) {
      retrievedAt = latestEolFetchedAt;
      recordCount = Array.isArray(releases) ? releases.length : 0;
    }

    sources.push({
      name: def.name,
      url: def.url,
      ecosystem: def.ecosystem,
      license: def.license,
      ...(def.licenseNote ? { licenseNote: def.licenseNote } : {}),
      retrievedAt,
      recordCount,
    });
  }

  return sources;
}
