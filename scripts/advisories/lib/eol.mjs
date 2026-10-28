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

import { compareVersions, isComparableVersion, toIsoDate } from './util.mjs';

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
 * 構築段階: 拡張機能の LibraryEolEntry { cycle, eolDate, status } へ変換
 *
 * @param {object[]} cycles compactEolCycles の結果
 * @param {{ asOf: string, supportedLatestCycles?: number }} options asOf は YYYY-MM-DD (取得日)
 */
export function normalizeEol(cycles, options) {
  const asOf = options.asOf;
  const valid = cycles.filter((c) => isComparableVersion(c.cycle));
  valid.sort((a, b) => compareVersions(b.cycle, a.cycle));

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

    return { cycle: c.cycle, eolDate, status };
  });
}
