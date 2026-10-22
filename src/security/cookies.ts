/**
 * Web Technology & Security Inspector
 * Cookie属性セキュリティ診断 (src/security/cookies.ts) - IMP-01 用途別リスク判定対応
 */

import {
  CookieCategory,
  CookieIssue,
  InspectedCookieInfo,
  SecurityCheckResult,
  SecuritySeverity,
} from '../shared/types';

/**
 * Cookieの名称パターンから用途カテゴリを自動判別する (IMP-01)
 *
 * @param name Cookie名
 * @returns CookieCategory
 */
export function classifyCookie(name: string): CookieCategory {
  const lower = name.toLowerCase();

  // 1. トラッキング・アクセス解析系 (接頭辞判定: _hjSession等の解析用セッションを含むため最優先)
  if (/^(_ga|_gid|_gat|_fbp|_hj|mp_)/i.test(lower)) {
    return 'analytics';
  }

  // 2. CSRF保護トークン系 (XSRF-TOKENなどtokenという文字列を含むため優先判定)
  if (/(csrf|xsrf)/i.test(lower)) {
    return 'csrf';
  }

  // 3. UI・表示設定系 (sidebar, theme, lang等。sidebarのsid誤爆を防止)
  if (/(theme|mode|lang|locale|sidebar|view|layout)/i.test(lower)) {
    return 'preferences';
  }

  // 4. 認証・セッション系 (sidは単語境界や区切り文字を考慮)
  if (/(session|sess|auth|token|jwt|(^|[_\-.])sid([_\-.]|$)|ticket|connect\.sid|phpsessid|jsessionid)/i.test(lower)) {
    return 'authentication';
  }

  // 5. 一般・未分類
  return 'general';
}

/**
 * 単一のCookie属性を評価し、課題があればCookieIssueを生成する (IMP-01)
 *
 * @param cookie 検査対象Cookie
 * @param isHttps HTTPS接続かどうか (デフォルト: true)
 * @returns CookieIssue | null
 */
export function evaluateCookie(
  cookie: InspectedCookieInfo | chrome.cookies.Cookie,
  isHttps: boolean = true
): CookieIssue | null {
  const category = classifyCookie(cookie.name);
  if ('category' in cookie) {
    (cookie as InspectedCookieInfo).category = category;
  }
  const missing: ('Secure' | 'HttpOnly' | 'SameSite' | 'Prefix')[] = [];

  // 1. Secure属性の検査 (HTTPS環境下)
  if (isHttps && !cookie.secure) {
    missing.push('Secure');
  }

  // 2. HttpOnly属性の検査 (用途に応じた判定)
  // - 認証・セッション系は必須
  // - 一般・未分類系も推奨
  // - CSRFトークン、アクセス解析タグ、UI設定系はJavaScript連携が前提のため欠落を許容
  if (!cookie.httpOnly) {
    if (category === 'authentication') {
      missing.push('HttpOnly');
    } else if (category === 'general') {
      missing.push('HttpOnly');
    }
  }

  // 3. SameSite属性の検査
  if (cookie.sameSite === 'no_restriction' && !cookie.secure) {
    missing.push('SameSite');
  }

  // 4. __Host- プレフィックス整合性チェック (Secure必須, Path=/ , ドメイン属性なし)
  if (cookie.name.startsWith('__Host-')) {
    const isDomainPrefix = cookie.domain ? cookie.domain.startsWith('.') : false;
    const isHostOnly = 'hostOnly' in cookie ? cookie.hostOnly : !isDomainPrefix;
    const valid = cookie.secure && cookie.path === '/' && isHostOnly;
    if ('hostPrefixValid' in cookie) {
      (cookie as InspectedCookieInfo).hostPrefixValid = valid;
    }
    if (!valid) {
      missing.push('Prefix');
    }
  }

  // 5. __Secure- プレフィックス整合性チェック (Secure必須)
  if (cookie.name.startsWith('__Secure-')) {
    if ('securePrefixValid' in cookie) {
      (cookie as InspectedCookieInfo).securePrefixValid = cookie.secure;
    }
    if (!cookie.secure && !missing.includes('Prefix')) {
      missing.push('Prefix');
    }
  }

  if (missing.length === 0) {
    return null;
  }

  // 用途に応じた重大度の動的決定
  let severity: SecuritySeverity = 'low';
  if (category === 'authentication') {
    severity = missing.includes('HttpOnly') || missing.includes('Secure') ? 'high' : 'medium';
  } else if (category === 'csrf') {
    severity = missing.includes('Secure') ? 'medium' : 'low';
  } else if (category === 'analytics' || category === 'preferences') {
    severity = 'low';
  } else {
    severity = missing.includes('Secure') ? 'medium' : 'low';
  }

  const desc = `Cookie '${cookie.name}' (${formatCookieCategory(category)}) に属性の不備が検出されました: ${missing.join(', ')}`;
  const recommendation = getCookieRecommendation(category, missing);

  return {
    id: `cookie-${cookie.name}-${Date.now()}`,
    name: cookie.name,
    category,
    severity,
    missingAttributes: missing,
    description: desc,
    recommendation,
  };
}

/**
 * 収集されたCookie属性リスト全体を評価する
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

  const issues: CookieIssue[] = [];

  for (const cookie of cookies) {
    const issue = evaluateCookie(cookie, isHttps);
    const issueTexts: string[] = [];

    if (issue) {
      issues.push(issue);
      if (issue.missingAttributes.includes('Secure')) {
        issueTexts.push('Secure属性未設定');
      }
      if (issue.missingAttributes.includes('HttpOnly')) {
        issueTexts.push('HttpOnly属性未設定');
      }
      if (issue.missingAttributes.includes('SameSite')) {
        issueTexts.push(`SameSite属性不備 (${cookie.sameSite})`);
      }
      if (issue.missingAttributes.includes('Prefix')) {
        issueTexts.push('プレフィックス要件不備');
      }
    } else {
      // 意図的・安全な設定
      if (!cookie.httpOnly && (cookie.category === 'csrf' || cookie.category === 'preferences' || cookie.category === 'analytics')) {
        issueTexts.push('HttpOnly未設定 (フロントエンド連携のため意図的)');
      }
    }

    cookie.issues = issueTexts;
    processedCookies.push(cookie);
  }

  // 1. 認証・セッションCookieの深刻な問題
  const authIssues = issues.filter((i) => i.category === 'authentication');
  if (authIssues.length > 0) {
    const missingHttpOnly = authIssues.filter((i) => i.missingAttributes.includes('HttpOnly'));
    const missingSecure = authIssues.filter((i) => i.missingAttributes.includes('Secure'));

    if (missingHttpOnly.length > 0) {
      checks.push({
        checkId: 'SEC-COOKIE-HTTPONLY',
        category: 'cookies',
        name: '認証・セッションCookie HttpOnly未設定',
        status: 'fail',
        severity: 'high',
        observed: `${missingHttpOnly.length} 件の認証系CookieでHttpOnlyが未設定 (${missingHttpOnly.map((i) => i.name).join(', ')})`,
        description:
          'セッション管理や認証トークンと思われるCookieにHttpOnly属性が設定されていません。万一XSS脆弱性が存在した場合、悪意あるスクリプトによってセッションが即座に奪取される重大な危険があります。',
        recommendation:
          'サーバーサイドでセッションを発行する際、必ず「HttpOnly」属性を付与してJavaScriptからのアクセスを遮断してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Cookies#restrict_access_to_cookies'],
        scope: url,
      });
    }

    if (missingSecure.length > 0) {
      checks.push({
        checkId: 'SEC-COOKIE-SECURE',
        category: 'cookies',
        name: '認証・セッションCookie Secure未設定',
        status: 'fail',
        severity: 'high',
        observed: `${missingSecure.length} 件の認証系CookieでSecureが未設定 (${missingSecure.map((i) => i.name).join(', ')})`,
        description:
          'セッションCookieにSecure属性がないため、平文HTTP通信でも送信される危険があります。中間者による通信傍受で認証情報が漏洩する恐れがあります。',
        recommendation: 'すべての認証Cookieに「Secure」属性を付与してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Cookies#restrict_access_to_cookies'],
        scope: url,
      });
    }
  }

  // 2. CSRFトークン等のCookie
  const csrfIssues = issues.filter((i) => i.category === 'csrf');
  if (csrfIssues.length > 0) {
    const missingSecure = csrfIssues.filter((i) => i.missingAttributes.includes('Secure'));
    if (missingSecure.length > 0) {
      checks.push({
        checkId: 'SEC-COOKIE-SECURE-CSRF',
        category: 'cookies',
        name: 'CSRFトークン Secure属性未設定',
        status: 'warning',
        severity: 'medium',
        observed: `${missingSecure.length} 件のCSRF保護CookieでSecure属性が未設定`,
        description: 'CSRFトークンが暗号化されていない平文通信で送出されるリスクがあります。',
        recommendation: 'CSRFトークンを保持するCookieに「Secure」属性を付与してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Cookies'],
        scope: url,
      });
    }
  }

  // 3. プレフィックス整合性不備
  const prefixIssues = issues.filter((i) => i.missingAttributes.includes('Prefix'));
  if (prefixIssues.length > 0) {
    checks.push({
      checkId: 'SEC-COOKIE-PREFIX',
      category: 'cookies',
      name: 'Cookie プレフィックス仕様不備 (__Host- / __Secure-)',
      status: 'fail',
      severity: 'medium',
      observed: `${prefixIssues.length} 件のCookieでプレフィックス要件を満たしていません (${prefixIssues.map((i) => i.name).join(', ')})`,
      description:
        '__Host- または __Secure- プレフィックスが付与されているCookieが、仕様要件（Secure属性、Path=/、Domain非指定等）を満たしていません。ブラウザによってはCookieが破棄されるか無効化されます。',
      recommendation:
        '__Host- を使用する場合は Secure属性、Path=/、Domain未指定としてください。__Secure- を使用する場合は Secure属性を必須としてください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Cookies#cookie_prefixes'],
      scope: url,
    });
  }

  // 4. 一般・トラッキング等のCookie
  const generalIssues = issues.filter((i) => i.category === 'general' || i.category === 'analytics' || i.category === 'preferences');
  if (generalIssues.length > 0 && authIssues.length === 0) {
    const missingSecure = generalIssues.filter((i) => i.missingAttributes.includes('Secure'));
    if (missingSecure.length > 0) {
      checks.push({
        checkId: 'SEC-COOKIE-SECURE-GENERAL',
        category: 'cookies',
        name: 'Cookie Secure属性未設定 (一般・解析用)',
        status: 'warning',
        severity: 'low',
        observed: `${missingSecure.length} 件の非認証系CookieでSecure属性が未設定`,
        description: '機密性の低いCookieですが、HTTPS通信環境下では全CookieにSecure属性を設定することが推奨されます。',
        recommendation: 'Webサーバーまたは発行スクリプトで「Secure」フラグを付与してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Cookies'],
        scope: url,
      });
    }
  }

  // 重大な問題がない場合
  if (checks.length === 0 && cookies.length > 0) {
    checks.push({
      checkId: 'SEC-COOKIE-PASS',
      category: 'cookies',
      name: 'Cookie属性セキュリティ (用途別適合)',
      status: 'pass',
      severity: 'info',
      observed: `検査した ${cookies.length} 件のCookie属性は用途別に適切な保護が確認されました`,
      description: '認証・セッションCookieにはHttpOnlyとSecureが付与され、フロントエンド用Cookieも適正に管理されています。',
      recommendation: '現状の安全な設定を維持してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Cookies'],
      scope: url,
    });
  }

  return { checks, inspectedCookies: processedCookies };
}

function formatCookieCategory(category: CookieCategory): string {
  const map: Record<CookieCategory, string> = {
    authentication: '認証・セッション',
    csrf: 'CSRFトークン',
    analytics: 'アクセス解析',
    preferences: 'UI・表示設定',
    general: '一般・未分類',
  };
  return map[category] || category;
}

function getCookieRecommendation(category: CookieCategory, missing: string[]): string {
  if (category === 'authentication') {
    return 'セッションハイジャック防止のため、直ちに「HttpOnly」および「Secure」属性を付与してください。';
  }
  if (category === 'csrf') {
    return '暗号化通信でのみトークンを送信するため、「Secure」属性の付与を推奨します。';
  }
  return `不足している属性（${missing.join(', ')}）の設定を検討してください。`;
}
