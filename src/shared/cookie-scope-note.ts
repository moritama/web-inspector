/**
 * 親ドメイン（host-only でない）の Cookie 名だけで検出した技術の注記生成 (v1.8.2 T04 / §4.2)
 */

import type { DetectedTechnology, InspectedCookieInfo } from './types';

/**
 * 親ドメイン（host-only でない）の Cookie 名だけで検出した技術の注記を返す (v1.8.2 T04 / §4.2)
 *
 * 条件:
 * 1. tech.cookieScopeDowngraded === true
 * 2. tech.evidence が存在し、そのすべてが type === 'cookie-name' かつ cookieScope !== 'host'
 * 3. 上記を満たさない場合は null
 *
 * @param tech 検出技術オブジェクト
 * @param cookies 調査結果の Cookie リスト（省略可）
 * @returns 注記文字列、または注記対象外の場合は null
 */
export function formatCookieScopeNote(
  tech: DetectedTechnology,
  cookies?: readonly InspectedCookieInfo[]
): string | null {
  if (!tech || tech.cookieScopeDowngraded !== true) {
    return null;
  }

  const evidences = Array.isArray(tech.evidence) ? tech.evidence : [];
  if (evidences.length === 0) {
    return null;
  }

  // 根拠がすべて cookie-name で、かつ cookieScope が 'host' でないこと
  const allDomainOrUnknownCookies = evidences.every(
    (e) => e.type === 'cookie-name' && e.cookieScope !== 'host'
  );
  if (!allDomainOrUnknownCookies) {
    return null;
  }

  // 根拠の Cookie 名（出現順、重複除外）
  const cookieNames: string[] = [];
  for (const e of evidences) {
    if (e.name && !cookieNames.includes(e.name)) {
      cookieNames.push(e.name);
    }
  }

  if (cookieNames.length === 0) {
    return null;
  }

  // Cookie 名ごとの表示文字列（ドメイン情報付き）を生成
  const nameParts = cookieNames.map((name) => {
    // 該当する Cookie のドメインを取得
    const domains: string[] = [];
    if (cookies && Array.isArray(cookies)) {
      for (const c of cookies) {
        if (c.name === name && c.hostOnly === false && c.domain && !domains.includes(c.domain)) {
          domains.push(c.domain);
        }
      }
    }

    if (domains.length > 0) {
      return `${name}（${domains.join('・')}）`;
    }

    // cookies から特定できない場合、evidence の cookieScope に応じて付記
    const matchedEvidence = evidences.find((e) => e.name === name);
    if (matchedEvidence?.cookieScope === 'unknown') {
      return `${name}（スコープ不明）`;
    }
    if (matchedEvidence?.cookieScope === 'domain') {
      return `${name}（親ドメイン）`;
    }
    return name;
  });

  return `根拠の Cookie ${nameParts.join('、')} は、このホスト専用（host-only）の Cookie ではありません。同一ドメインの別サイトで発行された可能性があり、このホスト単体での利用は確認できていません。`;
}
