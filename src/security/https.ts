/**
 * Web Technology & Security Inspector
 * HTTPSおよび混在コンテンツ (Mixed Content) 診断 (src/security/https.ts)
 */

import { MixedContentItem, SecurityCheckResult } from '../shared/types';

/**
 * HTTPSおよび混在コンテンツ（Mixed Content）の診断を行う
 *
 * @param url 調査対象URL
 * @param isHttps HTTPS接続かどうか
 * @param mixedItems DOM上で検出されたHTTPリソース一覧
 * @returns セキュリティチェック結果一覧
 */
export function checkHttpsAndMixedContent(
  url: string,
  isHttps: boolean,
  mixedItems: MixedContentItem[]
): SecurityCheckResult[] {
  const results: SecurityCheckResult[] = [];

  // 1. ページ自体のHTTPS利用チェック
  if (!isHttps) {
    results.push({
      checkId: 'SEC-HTTPS-01',
      category: 'https-communication',
      name: '暗号化通信未適用 (平文HTTP接続)',
      status: 'fail',
      severity: 'high',
      observed: 'HTTP (非暗号化接続)',
      description:
        'ページが暗号化されていないHTTP接続で提供されています。通信経路上で盗聴、改ざん、セッションハイジャックが行われる危険性があります。',
      recommendation:
        'TLS/SSL証明書を導入し、すべてのHTTPリクエストをHTTPSへ常時リダイレクトするようにWebサーバーを設定してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/Security/Transport_Layer_Security'],
      scope: url,
    });
    return results;
  }

  // 2. HTTPS通信の確認 (Pass)
  results.push({
    checkId: 'SEC-HTTPS-00',
    category: 'https-communication',
    name: 'HTTPS暗号化通信',
    status: 'pass',
    severity: 'info',
    observed: 'HTTPS (暗号化通信)',
    description: '基本通信はHTTPSによって暗号化されています。',
    recommendation: '現状の設定を維持してください。',
    referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/Security/Transport_Layer_Security'],
    scope: url,
  });

  // 3. 混在コンテンツ (Mixed Content) の診断
  if (mixedItems && mixedItems.length > 0) {
    // アクティブ混在コンテンツ (スクリプト, スタイル, iframe等: 危険度大)
    const activeMixed = mixedItems.filter((i) =>
      ['script', 'stylesheet', 'iframe', 'fetch'].includes(i.resourceType)
    );
    // パッシブ混在コンテンツ (画像, 音声, 動画等)
    const passiveMixed = mixedItems.filter((i) => ['image', 'other'].includes(i.resourceType));

    if (activeMixed.length > 0) {
      results.push({
        checkId: 'SEC-MIXED-ACTIVE',
        category: 'https-communication',
        name: 'アクティブ混在コンテンツ (Active Mixed Content)',
        status: 'fail',
        severity: 'high',
        observed: `${activeMixed.length} 件の非暗号化スクリプト/iframe等のリソースを検出`,
        description:
          'HTTPSページ内で平文HTTP経由のスクリプトやスタイル、iframeが読み込まれています。攻撃者がこの通信を改ざんすることで、ページ全体の制御を奪われる危険があります（最新ブラウザでは自動ブロックされる傾向にあります）。',
        recommendation:
          'すべてのスクリプト・スタイルシート・iframeの読み込みURLを「https://」に修正するか、相対パスに変更してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/Security/Mixed_content'],
        scope: url,
      });
    }

    if (passiveMixed.length > 0) {
      results.push({
        checkId: 'SEC-MIXED-PASSIVE',
        category: 'https-communication',
        name: 'パッシブ混在コンテンツ (Passive Mixed Content)',
        status: 'warning',
        severity: 'medium',
        observed: `${passiveMixed.length} 件の非暗号化画像/メディア等のリソースを検出`,
        description:
          'HTTPSページ内で平文HTTP経由の画像などのメディアリソースが読み込まれています。中間者によって画像を差し替えられたり、閲覧情報が盗聴されるリスクがあります。',
        recommendation:
          'すべての画像・メディアURLを「https://」に更新してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/Security/Mixed_content'],
        scope: url,
      });
    }
  } else {
    results.push({
      checkId: 'SEC-MIXED-00',
      category: 'https-communication',
      name: '混在コンテンツ (Mixed Content) なし',
      status: 'pass',
      severity: 'info',
      observed: '混在コンテンツは検出されませんでした',
      description: 'ページ内のすべての主要リソースがHTTPS経由で安全に読み込まれています。',
      recommendation: '現状の設定を維持してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/Security/Mixed_content'],
      scope: url,
    });
  }

  return results;
}
