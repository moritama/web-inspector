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

  // 3. 混在コンテンツ (Mixed Content) の診断 (v1.7.0 T07 / SPEC-15)
  if (mixedItems && mixedItems.length > 0) {
    // アクティブ混在コンテンツおよび平文HTTPのフォーム送信先 (スクリプト, スタイル, iframe, object/embed, form action等: 危険度大)
    const activeMixed = mixedItems.filter((i) =>
      ['script', 'stylesheet', 'iframe', 'object', 'embed', 'form', 'fetch'].includes(
        i.resourceType
      )
    );
    // パッシブ混在コンテンツ (画像, 音声, 動画等: モダンブラウザではHTTPSへ自動昇格)
    const passiveMixed = mixedItems.filter((i) =>
      ['image', 'video', 'audio', 'other'].includes(i.resourceType)
    );

    if (activeMixed.length > 0) {
      results.push({
        checkId: 'SEC-MIXED-ACTIVE',
        category: 'https-communication',
        name: 'アクティブ混在コンテンツ / 非暗号化フォーム送信 (Active Mixed Content)',
        status: 'fail',
        severity: 'high',
        observed: `${activeMixed.length} 件の非暗号化スクリプト/iframe/object/form等のリソースを検出`,
        description:
          'HTTPSページ内で平文HTTP経由のスクリプトやスタイル、iframe、プラグイン要素（object/embed）、または非暗号化（http://）のフォーム送信先（form action）が検出されました。攻撃者がこの通信を傍受・改ざんすることで、送信データの漏洩やページ全体の制御を奪われる重大な危険があります。',
        recommendation:
          'すべてのスクリプト・スタイルシート・iframe・プラグイン要素およびフォーム送信先（form action）のURLを「https://」に修正するか、相対パスに変更してください。',
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
        severity: 'low',
        observed: `${passiveMixed.length} 件の非暗号化画像/メディア等のリソースを検出`,
        description:
          'HTTPSページ内で平文HTTP経由の画像・動画・音声などのメディアリソース（src / srcset 等）が指定されています。モダンブラウザではパッシブ混在コンテンツは自動的にHTTPSへ昇格（アップグレード）されますが、HTTPS未対応の配信元では読み込み失敗や中間者による干渉のリスクがあります。',
        recommendation:
          'すべての画像・メディアURL（srcset や video/audio/source を含む）を明示的に「https://」に更新してください。',
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
