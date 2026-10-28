/**
 * Web Technology & Security Inspector
 * OSV (https://osv.dev) レコードの取得・正規化 (scripts/advisories/lib/osv.mjs)
 *
 * OSV は GitHub Advisory Database (GHSA) / npm / Packagist 等を統合したオープンなスキーマで、
 * npm・Packagist のライブラリ単位でバージョン範囲が機械可読な形で提供される。
 */

import { computeCvss3BaseScore } from './cvss.mjs';
import { intervalsToSpec, osvAffectedToIntervals } from './range.mjs';
import { cleanText, safeUrl } from './sanitize.mjs';
import { compareVersions, toIsoDate, uniq } from './util.mjs';

export const OSV_QUERY_URL = 'https://api.osv.dev/v1/query';

/**
 * 取得段階: パッケージ単位で全脆弱性を取得する (ページング対応)
 * @param {{ ecosystem: string, name: string }} pkg
 * @param {(url: string, init?: object) => Promise<any>} fetchJson
 */
export async function fetchOsvPackage(pkg, fetchJson) {
  const vulns = [];
  let pageToken;
  for (let page = 0; page < 50; page++) {
    const body = { package: { ecosystem: pkg.ecosystem, name: pkg.name } };
    if (pageToken) body.page_token = pageToken;
    const res = await fetchJson(OSV_QUERY_URL, { method: 'POST', body: JSON.stringify(body) });
    for (const v of res.vulns || []) vulns.push(v);
    if (!res.next_page_token) break;
    pageToken = res.next_page_token;
  }
  return vulns;
}

/**
 * 取得段階: レコードを DB 生成に必要な最小フィールドへ圧縮する (コミットするスナップショットを小さく保つ)
 */
export function compactOsvVuln(vuln, pkg) {
  const affected = (vuln.affected || [])
    .filter((a) => a.package && a.package.ecosystem === pkg.ecosystem && a.package.name === pkg.name)
    .map((a) => ({
      ranges: (a.ranges || [])
        .filter((r) => r.type === 'SEMVER' || r.type === 'ECOSYSTEM')
        .map((r) => ({ type: r.type, events: r.events })),
      versions: Array.isArray(a.versions) && (!a.ranges || a.ranges.length === 0) ? a.versions.slice(0, 200) : undefined,
    }));
  return {
    id: vuln.id,
    aliases: (vuln.aliases || []).slice().sort(),
    summary: vuln.summary || '',
    published: vuln.published || null,
    modified: vuln.modified || null,
    withdrawn: vuln.withdrawn || null,
    severity: (vuln.severity || []).map((s) => ({ type: s.type, score: s.score })),
    databaseSeverity: vuln.database_specific?.severity || null,
    references: (vuln.references || []).map((r) => r.url).filter(Boolean).slice(0, 10),
    affected,
  };
}

/** OSV の id / aliases から代表ID (CVE優先) と GHSA ID を決定する */
export function pickIds(compact) {
  const ids = [compact.id, ...(compact.aliases || [])];
  const cve = ids.find((x) => /^CVE-\d{4}-\d{4,7}$/.test(x)) || null;
  const ghsa = ids.find((x) => /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/.test(x)) || null;
  return { primaryId: cve || ghsa || compact.id, cve, ghsa };
}

/**
 * 構築段階: OSV 圧縮レコード群 (同一製品の複数パッケージ分) を候補アドバイザリへ変換する
 *
 * @param {object[]} compacts compactOsvVuln の結果 (複数パッケージ分を連結したもの)
 * @param {{ nvdScores: Map<string, object> }} ctx NVD から取得した CVE 単位スコア
 * @returns {{ advisories: object[], skipped: object[] }}
 */
export function osvToAdvisories(compacts, ctx = {}) {
  const byId = new Map();
  const skipped = [];

  for (const c of compacts) {
    if (c.withdrawn) {
      skipped.push({ id: c.id, reason: 'withdrawn' });
      continue;
    }
    const { primaryId, cve, ghsa } = pickIds(c);
    const merged = byId.get(primaryId) || { compacts: [], cve, ghsa };
    merged.compacts.push(c);
    byId.set(primaryId, merged);
  }

  const advisories = [];
  for (const [primaryId, { compacts: group, cve, ghsa }] of byId) {
    const intervals = [];
    const fixed = [];
    const lastAffected = [];
    let openEnded = false;
    const unparsable = [];
    for (const c of group) {
      for (const a of c.affected) {
        const r = osvAffectedToIntervals(a);
        intervals.push(...r.intervals);
        fixed.push(...r.fixed);
        lastAffected.push(...r.lastAffected);
        openEnded = openEnded || r.openEnded;
        unparsable.push(...r.unparsable);
      }
    }
    if (intervals.length === 0) {
      skipped.push({ id: primaryId, reason: unparsable.length ? `unparsable-versions:${unparsable.slice(0, 3).join(',')}` : 'no-affected-range' });
      continue;
    }

    // スコア: NVD Primary > (NVD Secondary) > OSV/GHSA の CVSS v3 ベクター計算
    const nvd = cve ? ctx.nvdScores?.get(cve) : null;
    let cvss = nvd && nvd.score !== null ? nvd : null;
    if (!cvss) {
      for (const c of group) {
        const v3 = (c.severity || []).find((s) => s.type === 'CVSS_V3');
        const computed = v3 ? computeCvss3BaseScore(v3.score) : null;
        if (computed) {
          cvss = { score: computed.score, vector: v3.score, source: `${ghsa ? 'GHSA' : 'OSV'} (CVSS v${computed.version} vector)` };
          break;
        }
      }
    }
    if (!cvss) {
      skipped.push({ id: primaryId, reason: 'unscored', detail: 'CVSS v3 not available' });
      continue;
    }

    const head = group[0];
    const fixedSorted = uniq(fixed).sort(compareVersions);
    const published = group.map((c) => toIsoDate(c.published)).filter(Boolean).sort()[0] || null;
    const modified = group.map((c) => toIsoDate(c.modified)).filter(Boolean).sort().reverse()[0] || null;
    const references = uniq(group.flatMap((c) => c.references || []).map((u) => safeUrl(u)).filter(Boolean)).slice(0, 5);

    let fixStatus = 'fixed';
    if (fixedSorted.length === 0) fixStatus = 'none';
    else if (openEnded || lastAffected.length > 0) fixStatus = 'partial';

    advisories.push({
      id: primaryId,
      cve,
      ghsa,
      title: cleanText(head.summary || primaryId, 160),
      range: intervalsToSpec(intervals),
      fixedVersion: fixedSorted.length > 0 ? fixedSorted.join(' / ') : null,
      fixStatus,
      cvssScore: cvss.score,
      cvssVector: cvss.vector || null,
      scoreSource: cvss.source,
      published,
      modified,
      advisoryUrl: cve
        ? `https://nvd.nist.gov/vuln/detail/${cve}`
        : ghsa
          ? `https://github.com/advisories/${ghsa}`
          : `https://osv.dev/vulnerability/${encodeURIComponent(primaryId)}`,
      references,
      sources: ['osv'],
    });
  }

  return { advisories, skipped };
}
