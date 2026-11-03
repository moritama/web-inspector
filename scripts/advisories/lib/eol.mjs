/**
 * Web Technology & Security Inspector
 * endoflife.date のサイクル情報の取得・正規化 (scripts/advisories/lib/eol.mjs)
 *
 * endoflife.date の各サイクル: { cycle, releaseDate, eol: boolean|date, support?: boolean|date, lts?, latest? }
 *   - eol      : セキュリティサポート終了日 (true = 終了済み / false = 未定)
 *   - support  : アクティブサポート終了日 (以降はセキュリティ修正のみ)
 *
 * 注意 (v1.6.5 レビュー指摘 DB-EOL-1):
 *   React のように「最新メジャーのみサポート」の製品では upstream の eol が false のまま
 *   残っている旧サイクルがあり、そのまま取り込むと 15〜17 系が "Supported" と誤表示される。
 *   catalog.json の eol.supportedLatestCycles で製品ポリシーを明示する。
 */

import path from 'node:path';
import { cleanText } from './sanitize.mjs';
import { compareVersions, isComparableVersion, PATHS, readJson, toIsoDate } from './util.mjs';

let cachedCatalogOverrides = null;

/**
 * build-db.mjs から cycleOverrides が省略して呼ばれた場合に、
 * 本番 catalog.json と upstream/eol スナップショットが一致すれば cycleOverrides を補完する
 */
function resolveCatalogCycleOverrides(cycles) {
  if (!Array.isArray(cycles) || cycles.length === 0) return null;
  if (!cachedCatalogOverrides) {
    cachedCatalogOverrides = [];
    try {
      const catalog = readJson(PATHS.catalog, null);
      if (catalog && catalog.products) {
        for (const product of Object.values(catalog.products)) {
          if (product?.eol?.slug && product?.eol?.cycleOverrides) {
            const snapPath = path.join(PATHS.upstreamDir, 'eol', `${product.eol.slug}.json`);
            const snap = readJson(snapPath, null);
            if (Array.isArray(snap?.cycles)) {
              cachedCatalogOverrides.push({
                cyclesJson: JSON.stringify(snap.cycles),
                cycleOverrides: product.eol.cycleOverrides,
              });
            }
          }
        }
      }
    } catch {
      // カタログやスナップショットが読めない環境では補完しない
    }
  }
  const targetJson = JSON.stringify(cycles);
  const matched = cachedCatalogOverrides.find((item) => item.cyclesJson === targetJson);
  return matched ? matched.cycleOverrides : null;
}

export function eolApiUrl(slug) {
  return `https://endoflife.date/api/${encodeURIComponent(slug)}.json`;
}

/** 取得段階: 必要フィールドのみに圧縮 */
export function compactEolCycles(cycles) {
  return (Array.isArray(cycles) ? cycles : []).map((c) => ({
    cycle: String(c.cycle),
    releaseDate: toIsoDate(c.releaseDate),
    eol: typeof c.eol === 'boolean' ? c.eol : toIsoDate(c.eol),
    support: typeof c.support === 'boolean' ? c.support : toIsoDate(c.support) ?? undefined,
    latest: c.latest ? String(c.latest) : undefined,
  }));
}

function isPast(dateStr, asOf) {
  return Boolean(dateStr) && dateStr <= asOf;
}

/**
 * 構築段階: 拡張機能の LibraryEolEntry { cycle, eolDate, status, label?, note? } へ変換
 *
 * @param {object[]} cycles compactEolCycles の結果
 * @param {{ asOf: string, supportedLatestCycles?: number, cycleOverrides?: Record<string, { status?: string, label?: string, note?: string }> }} options asOf は YYYY-MM-DD (取得日)
 */
export function normalizeEol(cycles, options) {
  const asOf = options.asOf;
  const valid = cycles.filter((c) => isComparableVersion(c.cycle));
  valid.sort((a, b) => compareVersions(b.cycle, a.cycle));

  const resolvedOverrides =
    options.cycleOverrides !== undefined ? options.cycleOverrides : resolveCatalogCycleOverrides(cycles);

  return valid.map((c, index) => {
    let status = 'Supported';
    let eolDate = typeof c.eol === 'string' ? c.eol : null;

    if (c.eol === true || isPast(eolDate, asOf)) {
      status = 'EOL';
    } else {
      // support: true = アクティブサポート中 / false = 終了 / 日付 = 終了日 / 未定義 = 情報なし
      const activeSupportEnded = c.support === false || (typeof c.support === 'string' && isPast(c.support, asOf));
      if (activeSupportEnded) {
        // アクティブサポートは終了し、セキュリティ修正のみ提供中
        status = 'Maintenance';
      }
    }

    // 製品ポリシー: 最新 N サイクル以外は upstream の値によらず EOL 扱い
    const n = options.supportedLatestCycles;
    if (typeof n === 'number' && index >= n && status !== 'EOL') {
      status = 'EOL';
      eolDate = eolDate && !isPast(eolDate, asOf) ? null : eolDate;
    }

    // サイクル個別の上書き設定 (D1: supportedLatestCycles 適用後に上書き)
    const entry = { cycle: c.cycle, eolDate, status };
    const ov = resolvedOverrides && typeof resolvedOverrides === 'object' ? resolvedOverrides[String(c.cycle)] : null;
    if (ov && typeof ov === 'object') {
      if (ov.status === 'Supported' || ov.status === 'Maintenance' || ov.status === 'EOL') {
        entry.status = ov.status;
      }
      if (typeof ov.label === 'string') {
        const cleanedLabel = cleanText(ov.label, 120);
        if (cleanedLabel) entry.label = cleanedLabel;
      }
      if (typeof ov.note === 'string') {
        const cleanedNote = cleanText(ov.note, 300);
        if (cleanedNote) entry.note = cleanedNote;
      }
    }

    return entry;
  });
}
