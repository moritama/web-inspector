/**
 * Web Technology & Security Inspector
 * NIST NVD (API 2.0) レコードの取得・正規化 (scripts/advisories/lib/nvd.mjs)
 *
 * - Webサーバー・言語ランタイム・CMS 本体 (Apache httpd / nginx / PHP / WordPress / Node.js) は
 *   OSV にエコシステムが無いため、NVD の CPE 構成 (configurations) を一次情報とする。
 * - スコアは MAINTENANCE_GUIDE 2.2 ① の優先順位 (NVD Primary > Secondary) で採用する。
 */

import { collapseExactIntervals, intervalsToSpec, nvdMatchToInterval } from './range.mjs';
import { cleanText, safeUrl } from './sanitize.mjs';
import { compareVersions, toIsoDate, uniq } from './util.mjs';

export const NVD_CVES_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const PAGE_SIZE = 2000;

/** "vendor:product" 形式のターゲットに CPE criteria が一致するか */
export function cpeMatchesTarget(criteria, targets) {
  const parts = String(criteria || '').split(':');
  if (parts.length < 6 || parts[0] !== 'cpe' || parts[1] !== '2.3') return false;
  const key = `${parts[3]}:${parts[4]}`.toLowerCase();
  return targets.some((t) => t.toLowerCase() === key);
}

/**
 * 取得段階: CPE (vendor:product) に紐づく全 CVE を取得する (ページング対応)
 */
export async function fetchNvdByCpe(target, fetchJson, headers = {}) {
  const items = [];
  let startIndex = 0;
  for (let page = 0; page < 100; page++) {
    const url = `${NVD_CVES_URL}?virtualMatchString=${encodeURIComponent(`cpe:2.3:a:${target}`)}&resultsPerPage=${PAGE_SIZE}&startIndex=${startIndex}`;
    const res = await fetchJson(url, { headers });
    const vulns = res.vulnerabilities || [];
    items.push(...vulns.map((v) => v.cve).filter(Boolean));
    startIndex += vulns.length;
    if (vulns.length === 0 || startIndex >= (res.totalResults ?? 0)) break;
  }
  return items;
}

/** 取得段階: CVE ID 単体の取得 (OSV 由来エントリのスコア補完用) */
export async function fetchNvdCve(cveId, fetchJson, headers = {}) {
  const res = await fetchJson(`${NVD_CVES_URL}?cveId=${encodeURIComponent(cveId)}`, { headers });
  return res.vulnerabilities?.[0]?.cve || null;
}

/**
 * CVSS v3.x メトリクスを優先順位に従って 1 つ選択する
 * 1. NVD (nvd@nist.gov) の Primary  2. その他 Primary  3. Secondary (CNA / CISA-ADP)
 * v3.1 を v3.0 より優先。v4.0 のみの場合は null (手書き換算はしない)
 */
export function pickNvdCvss(metrics) {
  if (!metrics) return null;
  const pools = [metrics.cvssMetricV31 || [], metrics.cvssMetricV30 || []];
  for (const pool of pools) {
    const ordered = [
      ...pool.filter((m) => m.type === 'Primary' && m.source === 'nvd@nist.gov'),
      ...pool.filter((m) => m.type === 'Primary' && m.source !== 'nvd@nist.gov'),
      ...pool.filter((m) => m.type !== 'Primary'),
    ];
    const chosen = ordered.find((m) => typeof m.cvssData?.baseScore === 'number');
    if (chosen) {
      const secondary = pool.find((m) => m !== chosen && typeof m.cvssData?.baseScore === 'number');
      return {
        score: chosen.cvssData.baseScore,
        vector: chosen.cvssData.vectorString || null,
        source: `${chosen.source} (${chosen.type || 'Secondary'})`,
        secondaryScore: secondary ? secondary.cvssData.baseScore : null,
        secondarySource: secondary ? secondary.source : null,
      };
    }
  }
  return null;
}

/**
 * 取得段階: NVD CVE レコードをターゲット製品に関係する最小情報へ圧縮する
 * @param {object} cve NVD API 2.0 の cve オブジェクト
 * @param {string[]} targets ["vendor:product", ...]
 */
export function compactNvdCve(cve, targets = []) {
  const matches = [];
  const conditions = [];
  for (const config of cve.configurations || []) {
    const nodes = config.nodes || [];
    const nodeMatches = nodes.map((n) => (n.cpeMatch || []).filter((m) => m.vulnerable && cpeMatchesTarget(m.criteria, targets)));
    const hasTarget = nodeMatches.some((ms) => ms.length > 0);
    if (!hasTarget) continue;
    for (const ms of nodeMatches) {
      for (const m of ms) {
        matches.push({
          criteria: m.criteria,
          vsi: m.versionStartIncluding || undefined,
          vse: m.versionStartExcluding || undefined,
          vei: m.versionEndIncluding || undefined,
          vee: m.versionEndExcluding || undefined,
        });
      }
    }
    // AND 構成 (例: PHP-CGI on Windows) の場合、非脆弱側の CPE を適用条件として記録する
    if (config.operator === 'AND' || nodes.some((n) => n.operator === 'AND')) {
      for (const n of nodes) {
        for (const m of n.cpeMatch || []) {
          if (!m.vulnerable) {
            const p = String(m.criteria).split(':');
            conditions.push(`${p[2] === 'o' ? 'OS' : p[2] === 'h' ? 'HW' : '構成'}: ${p[3]} ${p[4]}`);
          }
        }
      }
    }
  }
  const desc = (cve.descriptions || []).find((d) => d.lang === 'en')?.value || '';
  return {
    id: cve.id,
    published: toIsoDate(cve.published),
    lastModified: toIsoDate(cve.lastModified),
    vulnStatus: cve.vulnStatus || null,
    description: desc.slice(0, 600),
    cvss: pickNvdCvss(cve.metrics),
    matches,
    conditions: uniq(conditions).slice(0, 4),
    references: (cve.references || []).map((r) => r.url).filter(Boolean).slice(0, 8),
  };
}

/** 説明文の先頭1文をタイトルとして抽出 */
function firstSentence(text) {
  const m = String(text).match(/^(.{20,}?[.!?])(\s|$)/);
  return m ? m[1] : String(text);
}

/**
 * 構築段階: NVD 圧縮レコードを候補アドバイザリへ変換する
 * @param {object[]} compacts
 * @param {{ publishedSince?: string, minCvss?: number, includeKevAlways?: boolean, kev?: Map<string,string> }} filters
 */
export function nvdToAdvisories(compacts, filters = {}) {
  const advisories = [];
  const skipped = [];
  const seen = new Set();

  for (const c of compacts) {
    if (seen.has(c.id)) continue;
    seen.add(c.id);
    if (c.vulnStatus === 'Rejected') {
      skipped.push({ id: c.id, reason: 'rejected' });
      continue;
    }
    const isKev = Boolean(filters.kev?.has(c.id));
    if (!c.cvss) {
      skipped.push({ id: c.id, reason: 'unscored', detail: 'CVSS v3 not available' });
      continue;
    }
    if (!(isKev && filters.includeKevAlways)) {
      if (filters.publishedSince && c.published && c.published < filters.publishedSince) {
        skipped.push({ id: c.id, reason: 'filtered:publishedSince' });
        continue;
      }
      if (typeof filters.minCvss === 'number' && c.cvss.score < filters.minCvss) {
        skipped.push({ id: c.id, reason: 'filtered:minCvss' });
        continue;
      }
    }

    const intervals = c.matches.map(nvdMatchToInterval).filter(Boolean);
    if (intervals.length === 0) {
      skipped.push({ id: c.id, reason: 'no-cpe-range' });
      continue;
    }
    const { intervals: collapsed, approximated } = collapseExactIntervals(intervals);
    const fixedVersions = uniq(c.matches.map((m) => m.vee).filter(Boolean));
    let fixedSorted = [];
    try {
      fixedSorted = fixedVersions.sort(compareVersions);
    } catch {
      fixedSorted = fixedVersions.sort();
    }
    const allFixed = c.matches.every((m) => m.vee);

    const notes = [];
    if (c.conditions.length > 0) notes.push(`該当の可能性あり (条件: ${c.conditions.join(' / ')})`);
    if (approximated) notes.push('NVD の個別バージョン列挙を最小〜最大の範囲に近似');
    if (c.cvss.secondaryScore !== null && c.cvss.secondaryScore !== undefined && c.cvss.secondaryScore !== c.cvss.score) {
      notes.push(`${c.cvss.secondarySource} 評価: ${c.cvss.secondaryScore}`);
    }

    advisories.push({
      id: c.id,
      cve: c.id,
      ghsa: null,
      title: cleanText(firstSentence(c.description) || c.id, 160),
      summary: cleanText(`${notes.length && c.conditions.length ? `${notes[0]}。` : ''}${c.description}`, 400),
      range: intervalsToSpec(collapsed),
      fixedVersion: fixedSorted.length > 0 ? fixedSorted.join(' / ') : null,
      fixStatus: allFixed ? 'fixed' : 'unknown',
      cvssScore: c.cvss.score,
      cvssVector: c.cvss.vector,
      scoreSource: c.cvss.source,
      published: c.published,
      modified: c.lastModified,
      advisoryUrl: `https://nvd.nist.gov/vuln/detail/${c.id}`,
      references: uniq((c.references || []).map((u) => safeUrl(u)).filter(Boolean)).slice(0, 5),
      notes: notes.length ? cleanText(notes.join(' / '), 300) : undefined,
      rangeApproximated: approximated || undefined,
      sources: ['nvd'],
    });
  }
  return { advisories, skipped };
}
