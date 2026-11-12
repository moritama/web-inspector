/**
 * Web Technology & Security Inspector
 * サブリソース完全性 (Subresource Integrity: SRI) 診断 (src/security/sri.ts) (v1.8.0 T08 / NEW-03c)
 */

import { stripUrlQueryAndFragment } from '../shared/identity';
import { SecurityCheckResult, SriResourceItem } from '../shared/types';
import { determinePartyType } from './domain-analyzer';

/**
 * 内容が常に自動更新されるため SRI の適用が推奨されない配信元の一覧
 * 根拠: 設計メモ T08 および WORKLOG（一次資料確認済み）
 * 1. Google タグマネージャー (www.googletagmanager.com)
 * 2. Stripe.js (js.stripe.com)
 * 3. PayPal JavaScript SDK (www.paypal.com/sdk/js)
 * 4. Google Identity Services (accounts.google.com/gsi/)
 */
export const SRI_UNSUPPORTED_PROVIDERS: ReadonlyArray<{ hostname: string; pathPrefix?: string }> = [
  { hostname: 'www.googletagmanager.com' },
  { hostname: 'js.stripe.com' },
  { hostname: 'www.paypal.com', pathPrefix: '/sdk/js' },
  { hostname: 'accounts.google.com', pathPrefix: '/gsi/' },
];

/**
 * 対象 URL が SRI 非対応配信元に該当するか判定する（ホスト名は完全一致で判定）
 *
 * @param url 検証対象リソースの URL
 * @returns 非対応配信元に一致する場合は true
 */
export function isSriUnsupportedProvider(url: string): boolean {
  try {
    const parsed = new URL(url);
    const host = parsed.hostname.toLowerCase();
    for (const p of SRI_UNSUPPORTED_PROVIDERS) {
      if (host === p.hostname) {
        if (!p.pathPrefix || parsed.pathname.startsWith(p.pathPrefix)) {
          return true;
        }
      }
    }
  } catch {
    // 不正な URL は対象外
  }
  return false;
}

/**
 * サードパーティ script / stylesheet の Subresource Integrity (SRI) 設定状況を診断する
 *
 * - SEC-SRI-01 (warning / low): 一般サードパーティ資源で SRI (integrity 属性) が未設定
 * - SEC-SRI-02 (info / info): 自動更新等により SRI を付けられない配信元の資源
 *
 * ※ integrity の値自体は一切検査・保持・出力しません（属性の有無のみ評価）。
 * ※ URL のクエリ文字列およびフラグメントは機密情報保護のため除去・マスクします。
 *
 * @param pageUrl 調査対象ページの URL
 * @param resources DOM から抽出されたリソース情報配列
 * @returns セキュリティ診断結果配列（該当なしの場合は空配列）
 */
export function checkSubresourceIntegrity(
  pageUrl: string,
  resources: SriResourceItem[] | undefined | null
): SecurityCheckResult[] {
  if (!Array.isArray(resources) || resources.length === 0) {
    return [];
  }

  const genericUrls = new Set<string>();
  const unsupportedUrls = new Set<string>();

  for (const item of resources) {
    if (!item || typeof item !== 'object') continue;
    if (typeof item.url !== 'string' || item.url.length > 2048) continue;
    if (typeof item.hasIntegrity !== 'boolean') continue;
    if (item.kind !== 'script' && item.kind !== 'stylesheet') continue;

    // integrity が設定されている場合は診断対象外（合格）
    if (item.hasIntegrity) continue;

    // http / https スキームのみ対象（data:, blob: 等は除外）
    if (!/^https?:\/\//i.test(item.url)) continue;

    // PSL に基づくサードパーティ判定（ファーストパーティおよびローカルは除外）
    const party = determinePartyType(item.url, pageUrl);
    if (party !== 'third-party') continue;

    // クエリとフラグメントを除去してマスク
    const cleanUrl = stripUrlQueryAndFragment(item.url);
    if (!cleanUrl) continue;

    if (isSriUnsupportedProvider(item.url)) {
      unsupportedUrls.add(cleanUrl);
    } else {
      genericUrls.add(cleanUrl);
    }
  }

  const checks: SecurityCheckResult[] = [];

  // SEC-SRI-01: サードパーティ資源の SRI 未設定
  if (genericUrls.size > 0) {
    const urls = Array.from(genericUrls);
    const displayed = urls.slice(0, 10);
    const rest = urls.length - 10;
    const observedSummary = `${urls.length} 件のサードパーティ資源で SRI 未設定 (${displayed.join(', ')}${
      rest > 0 ? ` 他 ${rest} 件` : ''
    })`;

    checks.push({
      checkId: 'SEC-SRI-01',
      category: 'https-communication',
      name: 'サードパーティ資源の SRI (integrity) 未設定',
      status: 'warning',
      severity: 'low',
      observed: observedSummary,
      description:
        'サードパーティから読み込まれるスクリプトまたはスタイルシートに Subresource Integrity (SRI) が設定されていません。CDN 等の配信元が改ざんされた場合、悪意あるコードが実行されるリスクがあります。',
      recommendation:
        'バージョンを固定した URL を指定し、integrity 属性（および crossorigin 属性）を設定してリソースの改ざんを防止してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/Security/Subresource_Integrity'],
      scope: pageUrl,
    });
  }

  // SEC-SRI-02: SRI を付けられない配信元の資源
  if (unsupportedUrls.size > 0) {
    const urls = Array.from(unsupportedUrls);
    const displayed = urls.slice(0, 10);
    const rest = urls.length - 10;
    const observedSummary = `${urls.length} 件の自動更新配信元資源 (${displayed.join(', ')}${
      rest > 0 ? ` 他 ${rest} 件` : ''
    })`;

    checks.push({
      checkId: 'SEC-SRI-02',
      category: 'https-communication',
      name: 'SRI を付けられない配信元の資源',
      status: 'info',
      severity: 'info',
      observed: observedSummary,
      description:
        'タグマネージャーや決済・認証 SDK など、配信元により内容が頻繁に自動更新されるため SRI の適用が推奨されないサードパーティ資源が検出されました。',
      recommendation:
        'SRI の代わりに、Content Security Policy (CSP) の script-src 等で読み込み元ホストを限定し、信頼できる配信元のみを許可してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/Security/Subresource_Integrity'],
      scope: pageUrl,
    });
  }

  return checks;
}
