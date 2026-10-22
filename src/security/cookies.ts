/**
 * Web Technology & Security Inspector
 * Cookie属性セキュリティ診断 (src/security/cookies.ts)
 */

import { InspectedCookieInfo, SecurityCheckResult } from '../shared/types';

/**
 * 収集されたCookie属性リストを評価し、セキュリティチェック結果を生成する
 * (※Cookieの値そのものは一切診断・保持・ログ出力しません)
 *
 * @param cookies 検査対象のCookie属性リスト
 * @param url 調査対象URL
 * @param isHttps HTTPS接続かどうか
 * @returns セキュリティチェック結果一覧
 */
export function checkCookies(
  cookies: InspectedCookieInfo[],
  url: string,
  isHttps: boolean
): {
  checks: SecurityCheckResult[];
  inspectedCookies: InspectedCookieInfo[];
} {
  const checks: SecurityCheckResult[] = [];
  const processedCookies: InspectedCookieInfo[] = [];

  if (!cookies || cookies.length === 0) {
    return { checks, inspectedCookies: [] };
  }

  // セッションまたは認証関連の可能性が高いCookie名のパターン
  const sensitiveCookiePattern = /(?:session|sess|auth|token|jwt|login|id|user|csrf|xsrf|phpsessid|jsessionid|\.aspxauth)/i;

  let missingSecureCount = 0;
  let missingHttpOnlyCount = 0;
  let laxOrNoneSameSiteCount = 0;
  let prefixViolationCount = 0;

  for (const cookie of cookies) {
    const issues: string[] = [];
    const isSensitive = sensitiveCookiePattern.test(cookie.name);

    // 1. Secure属性の確認
    if (isHttps && !cookie.secure) {
      missingSecureCount++;
      issues.push('Secure属性が未設定 (平文HTTP通信でも送信されるリスク)');
    }

    // 2. HttpOnly属性の確認 (機密性の高いCookieの場合に特に重要)
    if (!cookie.httpOnly) {
      if (isSensitive) {
        missingHttpOnlyCount++;
        issues.push('HttpOnly属性が未設定 (XSS時にJavaScriptから読み取り可能)');
      } else {
        issues.push('HttpOnly未設定 (非機密用途の可能性あり)');
      }
    }

    // 3. SameSite属性の確認
    if (cookie.sameSite === 'unspecified' || cookie.sameSite === 'no_restriction') {
      laxOrNoneSameSiteCount++;
      issues.push(`SameSite属性が ${cookie.sameSite} (CSRF攻撃の標的となるリスク)`);
    }

    // 4. __Host- プレフィックス整合性チェック
    // 仕様: Secure必須、Pathは'/'、Domain属性は指定不可(ホスト限定)
    if (cookie.name.startsWith('__Host-')) {
      const hasValidHostPrefix = cookie.secure && cookie.path === '/' && !cookie.domain.startsWith('.');
      cookie.hostPrefixValid = hasValidHostPrefix;
      if (!hasValidHostPrefix) {
        prefixViolationCount++;
        issues.push('__Host-プレフィックスの要件（Secure必須、Path=/、Domain指定不可）を満たしていません');
      }
    }

    // 5. __Secure- プレフィックス整合性チェック
    // 仕様: Secure必須
    if (cookie.name.startsWith('__Secure-')) {
      cookie.securePrefixValid = cookie.secure;
      if (!cookie.secure) {
        prefixViolationCount++;
        issues.push('__Secure-プレフィックスの要件（Secure属性必須）を満たしていません');
      }
    }

    cookie.issues = issues;
    processedCookies.push(cookie);
  }

  // 統合診断結果の生成
  if (missingSecureCount > 0) {
    checks.push({
      checkId: 'SEC-COOKIE-SECURE',
      category: 'cookies',
      name: 'Cookie Secure属性欠落',
      status: 'warning',
      severity: 'medium',
      observed: `${missingSecureCount} 件のCookieでSecure属性が未設定`,
      description:
        'HTTPS通信下にもかかわらず、Secure属性が付与されていないCookieが検出されました。ネットワーク傍受によって平文で漏洩するリスクがあります。',
      recommendation:
        'すべてのCookieに「Secure」属性を付与し、暗号化通信（HTTPS）経由でのみ送信されるようにしてください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Cookies#restrict_access_to_cookies'],
      scope: url,
    });
  }

  if (missingHttpOnlyCount > 0) {
    checks.push({
      checkId: 'SEC-COOKIE-HTTPONLY',
      category: 'cookies',
      name: '重要Cookie HttpOnly属性欠落',
      status: 'warning',
      severity: 'medium',
      observed: `${missingHttpOnlyCount} 件のセッション・認証系CookieでHttpOnly属性が未設定`,
      description:
        'セッションや認証に関連すると推測されるCookieにHttpOnly属性が設定されていません。万一XSS脆弱性が存在した場合、document.cookie経由でセッションが乗っ取られる危険があります。',
      recommendation:
        'サーバーサイドで発行するセッションIDや認証トークンには必ず「HttpOnly」属性を付与してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Cookies#restrict_access_to_cookies'],
      scope: url,
    });
  }

  if (prefixViolationCount > 0) {
    checks.push({
      checkId: 'SEC-COOKIE-PREFIX',
      category: 'cookies',
      name: 'Cookie プレフィックス整合性不備',
      status: 'fail',
      severity: 'medium',
      observed: `${prefixViolationCount} 件のCookieで__Host- / __Secure-プレフィックス仕様違反`,
      description:
        '__Host- または __Secure- プレフィックスが付与されているCookieが、仕様で定められた要件（Secure属性やスコープ制限）を満たしていません。ブラウザによって拒否されるか、意図しないスコープで扱われる恐れがあります。',
      recommendation:
        '__Host-を使用する場合はSecure属性、Path=/、Domain属性なしを設定してください。__Secure-を使用する場合はSecure属性を設定してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Cookies#cookie_prefixes'],
      scope: url,
    });
  }

  if (checks.length === 0 && cookies.length > 0) {
    checks.push({
      checkId: 'SEC-COOKIE-PASS',
      category: 'cookies',
      name: 'Cookie属性セキュリティ',
      status: 'pass',
      severity: 'info',
      observed: `検査した ${cookies.length} 件のCookie属性に重大な不備は検出されませんでした`,
      description: '主要なCookieにおいて適切な属性設定が確認できました。',
      recommendation: '現状の設定を維持してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Cookies'],
      scope: url,
    });
  }

  return { checks, inspectedCookies: processedCookies };
}
