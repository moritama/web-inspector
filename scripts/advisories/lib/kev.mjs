/**
 * Web Technology & Security Inspector
 * CISA Known Exploited Vulnerabilities (KEV) カタログ (scripts/advisories/lib/kev.mjs)
 */

import { toIsoDate } from './util.mjs';

export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/** 取得段階: CVE ID -> 追加日 のみに圧縮 */
export function compactKev(raw) {
  const items = {};
  for (const v of raw?.vulnerabilities || []) {
    if (/^CVE-\d{4}-\d{4,7}$/.test(v.cveID || '')) {
      items[v.cveID] = toIsoDate(v.dateAdded) || null;
    }
  }
  const sorted = Object.fromEntries(Object.entries(items).sort(([a], [b]) => a.localeCompare(b)));
  return {
    catalogVersion: raw?.catalogVersion || null,
    dateReleased: toIsoDate(raw?.dateReleased) || null,
    count: Object.keys(sorted).length,
    items: sorted,
  };
}

export function kevMap(compact) {
  return new Map(Object.entries(compact?.items || {}));
}
