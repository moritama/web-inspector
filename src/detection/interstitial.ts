/**
 * Web Technology & Security Inspector
 * WAF・ボット確認画面（interstitial）検出エンジン (src/detection/interstitial.ts) - v1.8.0 T04 / G6
 *
 * 閲覧したページが WAF やボット対策の確認画面（Fastly Client Challenge, Cloudflare Challenge, AWS WAF Captcha 等）
 * であるかどうかを受動的に判定する。
 */

import { DomSignals, InterstitialInfo } from '../shared/types';

/**
 * 確認画面検出で使用するレスポンスヘッダー名（小文字） (v1.8.0 T04 / G5)
 */
export const INTERSTITIAL_HEADER_NAMES: readonly string[] = [
  'cf-mitigated',
  'x-amzn-waf-action',
] as const;

/**
 * ヘッダーマップから指定した名前のヘッダー値一覧を大文字小文字を区別せず取得する
 */
function getHeaderValues(headers: Record<string, string[]>, name: string): string[] {
  const target = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === target) {
      return Array.isArray(v) ? v : [String(v)];
    }
  }
  return [];
}

/**
 * WAF・ボット対策確認画面の検出を行う (v1.8.0 T04 / G6)
 *
 * 【判定規則】
 * 1. レスポンスヘッダーによる判定（1つのヘッダーで判定）:
 *    - Cloudflare: `cf-mitigated: challenge`（challenge が唯一の値）
 *    - AWS WAF: `x-amzn-waf-action: captcha` または `challenge`
 * 2. ページ内の印による判定（同一ベンダーの印が 2 つ以上必要）:
 *    - Fastly:
 *      - タイトル完全一致: `Client Challenge`
 *      - DOM 要素 ID: `id="fastlyLogo"`
 *      - DOM 要素 ID: `id="captchaTitle"`
 * 3. 異なるベンダーの印を合算して判定しない（安全側）。
 *
 * @param dom DOMシグナル
 * @param responseHeaders HTTPレスポンスヘッダー（キャッシュ照合済みの観測済みヘッダー）
 * @returns 検出された場合は InterstitialInfo、非該当の場合は undefined
 */
export function detectInterstitial(
  dom?: DomSignals,
  responseHeaders?: Record<string, string[]>
): InterstitialInfo | undefined {
  const headers = responseHeaders || {};

  // 1. レスポンスヘッダーによる判定（ヘッダー判定を優先）
  // 1a. Cloudflare: cf-mitigated: challenge
  const cfMitigated = getHeaderValues(headers, 'cf-mitigated');
  for (const val of cfMitigated) {
    if (val.toLowerCase().trim() === 'challenge') {
      return {
        vendor: 'Cloudflare',
        evidence: ['cf-mitigated: challenge'],
      };
    }
  }

  // 1b. AWS WAF: x-amzn-waf-action: captcha または challenge
  const amznWafAction = getHeaderValues(headers, 'x-amzn-waf-action');
  for (const val of amznWafAction) {
    const action = val.toLowerCase().trim();
    if (action === 'captcha' || action === 'challenge') {
      return {
        vendor: 'AWS WAF',
        evidence: [`x-amzn-waf-action: ${action}`],
      };
    }
  }

  // 2. ページ内の印による判定（同一ベンダーで2つ以上の印が必要）
  if (!dom) {
    return undefined;
  }

  // 2a. Fastly: タイトル Client Challenge, id="fastlyLogo", id="captchaTitle"
  const fastlyEvidence: string[] = [];
  if (dom.title && dom.title.trim() === 'Client Challenge') {
    fastlyEvidence.push('title: Client Challenge');
  }
  const markers = dom.interstitialMarkers || [];
  if (markers.includes('id="fastlyLogo"')) {
    fastlyEvidence.push('id="fastlyLogo"');
  }
  if (markers.includes('id="captchaTitle"')) {
    fastlyEvidence.push('id="captchaTitle"');
  }

  if (fastlyEvidence.length >= 2) {
    return {
      vendor: 'Fastly',
      evidence: fastlyEvidence,
    };
  }

  // 2b. Cloudflare: /cdn-cgi/challenge-platform/ (印1つ。通常ページにも出るため単独判定しない)
  // ページ内印のみでは2つ以上にならないため判定なし

  return undefined;
}
