/**
 * Web Technology & Security Inspector
 * 影響範囲 (range) 正規化 (scripts/advisories/lib/range.mjs)
 *
 * 拡張機能の version-matcher.ts が解釈できる範囲書式に変換する:
 *   - 句: "<op> <version>"  (op: <, <=, >, >=, =)
 *   - AND: ", "  /  OR: " || "
 *   例: ">= 1.2.0, < 3.5.0 || >= 4.0.0, < 4.3.1"
 */

import { compareVersions, isComparableVersion, uniq } from './util.mjs';

const CLAUSE_RE = /^(<=|>=|<|>|=)\s*v?(\d+(?:\.\d+){0,3}(?:[-.][0-9A-Za-z.-]+)?)$/;

/** 範囲書式が version-matcher で解釈可能か検証する */
export function isValidRangeSpec(spec) {
  if (typeof spec !== 'string' || !spec.trim()) return false;
  if (spec.trim() === '*') return true;
  return spec.split('||').every((branch) => {
    const clauses = branch.split(',').map((c) => c.trim()).filter(Boolean);
    return clauses.length > 0 && clauses.every((c) => CLAUSE_RE.test(c));
  });
}

/**
 * 区間 {lower, lowerInclusive, upper, upperInclusive, exact} を範囲文字列へ変換
 */
export function intervalToClause(iv) {
  if (iv.exact) return `= ${iv.exact}`;
  const parts = [];
  if (iv.lower) parts.push(`${iv.lowerInclusive === false ? '>' : '>='} ${iv.lower}`);
  if (iv.upper) parts.push(`${iv.upperInclusive ? '<=' : '<'} ${iv.upper}`);
  if (parts.length === 0) return '>= 0.0.0';
  return parts.join(', ');
}

/** 区間リストを整列・重複排除して OR 結合の範囲文字列にする */
export function intervalsToSpec(intervals) {
  const clauses = uniq(intervals.map(intervalToClause));
  const keyOf = (c) => {
    const m = c.match(/(\d+(?:\.\d+){0,3})/);
    return m ? m[1] : '0';
  };
  clauses.sort((a, b) => {
    try {
      return compareVersions(keyOf(a), keyOf(b));
    } catch {
      return a.localeCompare(b);
    }
  });
  return clauses.join(' || ');
}

/**
 * OSV の affected[].ranges (SEMVER / ECOSYSTEM) と versions[] から区間を生成する
 * https://ossf.github.io/osv-schema/#affectedranges-field
 *
 * @returns {{ intervals: object[], fixed: string[], lastAffected: string[], openEnded: boolean, unparsable: string[] }}
 */
export function osvAffectedToIntervals(affected) {
  const intervals = [];
  const fixed = [];
  const lastAffected = [];
  const unparsable = [];
  let openEnded = false;

  for (const range of affected.ranges || []) {
    if (range.type !== 'SEMVER' && range.type !== 'ECOSYSTEM') continue;
    let current = null;
    for (const ev of range.events || []) {
      if (ev.introduced !== undefined) {
        const intro = String(ev.introduced);
        if (intro !== '0' && !isComparableVersion(intro)) {
          unparsable.push(intro);
          current = null;
          continue;
        }
        current = { lower: intro === '0' ? null : intro, lowerInclusive: true, upper: null, upperInclusive: false };
      } else if (ev.fixed !== undefined && current) {
        if (!isComparableVersion(ev.fixed)) {
          unparsable.push(String(ev.fixed));
          current = null;
          continue;
        }
        current.upper = String(ev.fixed);
        current.upperInclusive = false;
        fixed.push(String(ev.fixed));
        intervals.push(current);
        current = null;
      } else if (ev.last_affected !== undefined && current) {
        if (!isComparableVersion(ev.last_affected)) {
          unparsable.push(String(ev.last_affected));
          current = null;
          continue;
        }
        current.upper = String(ev.last_affected);
        current.upperInclusive = true;
        lastAffected.push(String(ev.last_affected));
        intervals.push(current);
        current = null;
      } else if (ev.limit !== undefined && current) {
        current.upper = String(ev.limit);
        current.upperInclusive = false;
        intervals.push(current);
        current = null;
      }
    }
    if (current) {
      // introduced のみで修正版が無い (= 以降の全バージョンが影響)
      intervals.push(current);
      openEnded = true;
    }
  }

  // ranges が無く versions[] のみ列挙されている場合
  if (intervals.length === 0 && Array.isArray(affected.versions) && affected.versions.length > 0) {
    for (const v of affected.versions) {
      if (isComparableVersion(v)) intervals.push({ exact: String(v) });
      else unparsable.push(String(v));
    }
  }

  return { intervals, fixed, lastAffected, openEnded, unparsable };
}

/**
 * NVD cpeMatch を区間へ変換する
 * - versionStart/End(Including|Excluding) がある場合は区間
 * - criteria にバージョンが明記されている場合は完全一致 (= x.y.z)
 */
export function nvdMatchToInterval(match) {
  const versionInCriteria = (match.criteria || '').split(':')[5];
  const hasRange = match.vsi || match.vse || match.vei || match.vee;
  if (!hasRange) {
    if (versionInCriteria && versionInCriteria !== '*' && versionInCriteria !== '-') {
      return isComparableVersion(versionInCriteria) ? { exact: versionInCriteria } : null;
    }
    // バージョン指定なし ("*") かつ範囲指定なし = 全バージョン
    return { lower: null, upper: null };
  }
  const iv = { lower: null, lowerInclusive: true, upper: null, upperInclusive: false };
  if (match.vsi) {
    iv.lower = match.vsi;
    iv.lowerInclusive = true;
  } else if (match.vse) {
    iv.lower = match.vse;
    iv.lowerInclusive = false;
  }
  if (match.vee) {
    iv.upper = match.vee;
    iv.upperInclusive = false;
  } else if (match.vei) {
    iv.upper = match.vei;
    iv.upperInclusive = true;
  }
  for (const v of [iv.lower, iv.upper]) {
    if (v && !isComparableVersion(v)) return null;
  }
  return iv;
}

/**
 * 完全一致の列挙が多すぎる場合 (NVD の古いCVEで頻出) に、最小〜最大の閉区間へ畳み込む。
 * 拡大方向 (誤検知寄り) の近似となるため、呼び出し側で approximated フラグを記録すること。
 */
export function collapseExactIntervals(intervals, maxExact = 25) {
  const exact = intervals.filter((iv) => iv.exact);
  if (exact.length <= maxExact) return { intervals, approximated: false };
  const versions = exact.map((iv) => iv.exact).sort(compareVersions);
  const others = intervals.filter((iv) => !iv.exact);
  others.push({ lower: versions[0], lowerInclusive: true, upper: versions[versions.length - 1], upperInclusive: true });
  return { intervals: others, approximated: true };
}
