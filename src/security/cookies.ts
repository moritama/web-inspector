/**
 * Web Technology & Security Inspector
 * Cookie属性セキュリティ診断 (src/security/cookies.ts) - IMP-04 (Rev.2.1)
 * 
 * - Chrome API SameSiteStatus の内部正規化 (normalizeSameSite)
 * - 用途別分類の高度化・あいまい性 (ambiguous) 管理
 * - Cookieプレフィックス (__Secure-, __Host-, __Http-, __Host-Http-) 検査
 * - Partitioned Cookie (CHIPS) 識別と属性整合性評価
 * - Cookie値（Value）の完全非保持（プライバシー保護徹底）
 * - 安定ID (FindingIdentity) の付与
 */

import { buildCookieResourceKey, generateFindingId } from '../shared/identity';
import {
  CookieCategory,
  CookieClassification,
  CookieIssue,
  InspectedCookieInfo,
  NormalizedSameSite,
  SecurityCheckResult,
  SecuritySeverity,
} from '../shared/types';

/**
 * 既知Cookie辞書 (完全一致による高信頼度分類)
 */
const KNOWN_COOKIES: Record<string, CookieCategory> = {
  // 認証・セッション
  phpsessid: 'authentication',
  jsessionid: 'authentication',
  aspsessionid: 'authentication',
  'connect.sid': 'authentication',
  auth_token: 'authentication',
  session_id: 'authentication',
  token: 'authentication',
  jwt: 'authentication',
  // CSRF対策
  'xsrf-token': 'csrf',
  csrf_token: 'csrf',
  _csrf: 'csrf',
  csrftoken: 'csrf',
  // 解析・トラッキング
  _ga: 'analytics',
  _gid: 'analytics',
  _gat: 'analytics',
  _fbp: 'analytics',
  // UI設定
  theme: 'preferences',
  theme_mode: 'preferences',
  user_lang: 'preferences',
  lang: 'preferences',
  locale: 'preferences',
  sidebar_view: 'preferences',
};

/**
 * Chrome API の SameSiteStatus を内部正規化表現に変換する (IMP-04 / 3.2)
 *
 * @param value Chrome API または生SameSite文字列
 * @returns NormalizedSameSite ('none' | 'lax' | 'strict' | 'unspecified' | 'unknown')
 */
export function normalizeSameSite(
  value: chrome.cookies.SameSiteStatus | string | undefined | null
): NormalizedSameSite {
  if (!value) return 'unknown';

  const lower = String(value).toLowerCase().trim();
  switch (lower) {
    case 'no_restriction':
    case 'none':
      return 'none';
    case 'lax':
      return 'lax';
    case 'strict':
      return 'strict';
    case 'unspecified':
      return 'unspecified';
    default:
      return 'unknown';
  }
}

/**
 * Cookieの名称から詳細な分類・あいまい性を判定する (IMP-04 / 3.3)
 *
 * @param name Cookie名
 * @returns CookieClassification
 */
export function classifyCookieAdvanced(name: string): CookieClassification {
  const lower = name.toLowerCase().trim();
  const matchedRules: string[] = [];

  // 1. 既知Cookie辞書への完全一致
  if (KNOWN_COOKIES[lower]) {
    matchedRules.push(`known-dict:${KNOWN_COOKIES[lower]}`);
    return {
      category: KNOWN_COOKIES[lower],
      confidence: 'high',
      matchedRules,
      ambiguous: false,
      overridden: false,
    };
  }

  let isAnalytics = false;
  let isCsrf = false;
  let isPreferences = false;
  let isAuth = false;

  // 2. 解析・トラッキングパターン
  if (/^(_ga|_gid|_gat|_fbp|_hj|mp_)/i.test(lower)) {
    isAnalytics = true;
    matchedRules.push('pattern:analytics');
  }

  // 3. CSRF専用パターン
  if (/(csrf|xsrf)/i.test(lower)) {
    isCsrf = true;
    matchedRules.push('pattern:csrf');
  }

  // 4. UI・表示設定パターン
  if (/(theme|mode|lang|locale|sidebar|view|layout)/i.test(lower)) {
    isPreferences = true;
    matchedRules.push('pattern:preferences');
  }

  // 5. 認証・セッションパターン
  if (/(session|sess|auth|token|jwt|(^|[_\-.])sid([_\-.]|$)|ticket|connect\.sid|phpsessid|jsessionid)/i.test(lower)) {
    isAuth = true;
    matchedRules.push('pattern:authentication');
  }

  const matchCount = [isAnalytics, isCsrf, isPreferences, isAuth].filter(Boolean).length;
  const ambiguous = matchCount > 1;

  // 優先順位決定 (解析 -> CSRF -> UI設定 -> 認証 -> 一般)
  let category: CookieCategory = 'general';
  if (isAnalytics) category = 'analytics';
  else if (isCsrf) category = 'csrf';
  else if (isPreferences) category = 'preferences';
  else if (isAuth) category = 'authentication';

  return {
    category,
    confidence: ambiguous ? 'low' : matchCount === 1 ? 'medium' : 'unknown',
    matchedRules: matchedRules.length > 0 ? matchedRules : ['default:general'],
    ambiguous,
    overridden: false,
  };
}

/**
 * Cookieカテゴリ簡易取得関数 (後方互換用)
 */
export function classifyCookie(name: string): CookieCategory {
  return classifyCookieAdvanced(name).category;
}

/**
 * 単一のCookie属性を評価し、課題があればCookieIssueを生成する (IMP-04 / 3.4 & 3.5)
 * ※Cookie値 (Value) は一切引数に取らず、内部・結果にも含めません。
 *
 * @param cookie 検査対象Cookie情報
 * @param isHttps HTTPS接続かどうか (デフォルト: true)
 * @param origin サイトオリジン
 * @returns CookieIssue | null
 */
export function evaluateCookie(
  cookie: InspectedCookieInfo | chrome.cookies.Cookie | any,
  isHttps: boolean = true,
  origin: string = 'https://unknown'
): CookieIssue | null {
  const classification = classifyCookieAdvanced(cookie.name);
  const category = classification.category;
  const missing: ('Secure' | 'HttpOnly' | 'SameSite' | 'Prefix')[] = [];
  const descriptions: string[] = [];

  // SameSite正規化
  const normSameSite = normalizeSameSite(cookie.sameSite);
  if ('normalizedSameSite' in cookie) {
    cookie.normalizedSameSite = normSameSite;
  }

  // 1. Secure属性の検査 (HTTPS環境下)
  if (isHttps && !cookie.secure) {
    missing.push('Secure');
    descriptions.push('HTTPS通信において暗号化を義務付けるSecure属性が欠落しています。');
  }

  // 2. Partitioned Cookie (CHIPS) 検査 (3.5)
  const isPartitioned = Boolean(cookie.partitioned || cookie.partitionKey);
  if (isPartitioned) {
    if (!cookie.secure) {
      if (!missing.includes('Secure')) missing.push('Secure');
      descriptions.push('Partitioned Cookie (CHIPS) には仕様上Secure属性が必須です。');
    }
  }

  // 3. HttpOnly属性の検査 (用途に応じた判定)
  if (!cookie.httpOnly) {
    if (category === 'authentication') {
      missing.push('HttpOnly');
      descriptions.push('認証・セッションCookieですが、JavaScriptアクセスを遮断するHttpOnly属性が欠落しています。');
    } else if (category === 'general' && !classification.ambiguous) {
      missing.push('HttpOnly');
      descriptions.push('HttpOnly属性が設定されていません。');
    }
  }

  // 4. SameSite属性の検査 (3.2)
  if (normSameSite === 'none' && !cookie.secure) {
    missing.push('SameSite');
    descriptions.push('SameSite=None のCookieにはSecure属性の付与が必須です。');
  }

  // 5. Cookieプレフィックス要件の検査 (3.4)
  const isDomainPrefix = cookie.domain ? cookie.domain.startsWith('.') : false;
  const isHostOnly = 'hostOnly' in cookie ? Boolean(cookie.hostOnly) : !isDomainPrefix;
  let prefixType: '__Secure-' | '__Host-' | '__Http-' | '__Host-Http-' | null = null;

  if (cookie.name.startsWith('__Host-Http-')) {
    prefixType = '__Host-Http-';
    const valid = cookie.secure && cookie.path === '/' && isHostOnly && cookie.httpOnly;
    if (!valid) {
      missing.push('Prefix');
      descriptions.push('__Host-Http- プレフィックスの要件（Secure、Path=/、Domain属性なし、HttpOnly）を満たしていません。');
    }
  } else if (cookie.name.startsWith('__Host-')) {
    prefixType = '__Host-';
    const valid = cookie.secure && cookie.path === '/' && isHostOnly;
    if (!valid) {
      missing.push('Prefix');
      descriptions.push('__Host- プレフィックスの要件（Secure、Path=/、Domain属性なし）を満たしていません。');
    }
  } else if (cookie.name.startsWith('__Http-')) {
    prefixType = '__Http-';
    const valid = cookie.secure && cookie.httpOnly;
    if (!valid) {
      missing.push('Prefix');
      descriptions.push('__Http- プレフィックスの要件（Secure、HttpOnly）を満たしていません。');
    }
  } else if (cookie.name.startsWith('__Secure-')) {
    prefixType = '__Secure-';
    if (!cookie.secure) {
      missing.push('Prefix');
      descriptions.push('__Secure- プレフィックスの要件（Secure属性必須）を満たしていません。');
    }
  }

  if (missing.length === 0) {
    return null;
  }

  // 用途に応じた重大度の決定
  let severity: SecuritySeverity = 'low';
  if (category === 'authentication') {
    // 分類があいまいな場合は重大度を過剰に引き上げない (3.3)
    if (classification.ambiguous) {
      severity = 'medium';
    } else {
      severity = missing.includes('HttpOnly') || missing.includes('Secure') ? 'high' : 'medium';
    }
  } else if (category === 'csrf') {
    severity = missing.includes('Secure') ? 'medium' : 'low';
  } else if (isPartitioned && !cookie.secure) {
    severity = 'medium';
  } else {
    severity = missing.includes('Secure') ? 'medium' : 'low';
  }

  // 安定IDの発行 (IMP-07)
  const resourceKey = buildCookieResourceKey(
    cookie.name,
    cookie.domain || '',
    cookie.path || '/',
    isHostOnly,
    cookie.partitionKey
  );
  const stableId = generateFindingId({
    ruleId: 'COOKIE-ATTRIBUTE-ISSUE',
    origin,
    resourceKey,
    targetKey: missing.join(','),
  });

  return {
    id: stableId,
    name: cookie.name,
    category,
    severity,
    missingAttributes: Array.from(new Set(missing)),
    description: `Cookie '${cookie.name}' (${formatCookieCategory(category)}): ${descriptions.join(' ')}`,
    recommendation: getCookieRecommendation(category, missing, prefixType),
  };
}

/**
 * 収集されたCookie属性リスト全体を診断する
 * ※入力オブジェクトにvalueが含まれていても、出力リストからは完全に除外・安全化します。
 */
export function checkCookies(
  cookies: InspectedCookieInfo[] | chrome.cookies.Cookie[] | any[],
  url: string,
  isHttps: boolean = true
): {
  checks: SecurityCheckResult[];
  inspectedCookies: InspectedCookieInfo[];
} {
  const checks: SecurityCheckResult[] = [];
  const processedCookies: InspectedCookieInfo[] = [];

  if (!cookies || cookies.length === 0) {
    return { checks, inspectedCookies: [] };
  }

  let origin = 'https://unknown';
  try {
    origin = new URL(url).origin;
  } catch {
    origin = url;
  }

  const issues: CookieIssue[] = [];

  for (const rawCookie of cookies) {
    const classification = classifyCookieAdvanced(rawCookie.name);
    const issue = evaluateCookie(rawCookie, isHttps, origin);
    const issueTexts: string[] = [];

    if (issue) {
      issues.push(issue);
      if (issue.missingAttributes.includes('Secure')) issueTexts.push('Secure属性未設定');
      if (issue.missingAttributes.includes('HttpOnly')) issueTexts.push('HttpOnly属性未設定');
      if (issue.missingAttributes.includes('SameSite')) issueTexts.push(`SameSite属性不備`);
      if (issue.missingAttributes.includes('Prefix')) issueTexts.push('プレフィックス仕様不備');
    } else {
      if (!rawCookie.httpOnly && (classification.category === 'csrf' || classification.category === 'preferences' || classification.category === 'analytics')) {
        issueTexts.push('HttpOnly未設定 (フロントエンド連携のため意図的)');
      }
    }

    const isDomainPrefix = rawCookie.domain ? rawCookie.domain.startsWith('.') : false;
    const isHostOnly = 'hostOnly' in rawCookie ? Boolean(rawCookie.hostOnly) : !isDomainPrefix;

    // クリーンな Cookie オブジェクト（値は一切含めない）
    const cleanCookie: InspectedCookieInfo = {
      name: rawCookie.name,
      domain: rawCookie.domain || '',
      path: rawCookie.path || '/',
      secure: Boolean(rawCookie.secure),
      httpOnly: Boolean(rawCookie.httpOnly),
      sameSite: rawCookie.sameSite || 'unspecified',
      normalizedSameSite: normalizeSameSite(rawCookie.sameSite),
      session: Boolean(rawCookie.session),
      hostOnly: isHostOnly,
      partitioned: Boolean(rawCookie.partitioned || rawCookie.partitionKey),
      partitionKey: rawCookie.partitionKey || null,
      expirationDate: rawCookie.expirationDate,
      category: classification.category,
      classification,
      issues: issueTexts,
    };

    processedCookies.push(cleanCookie);
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
      name: 'Cookie プレフィックス仕様不備 (__Host- / __Secure- / __Http-)',
      status: 'fail',
      severity: 'medium',
      observed: `${prefixIssues.length} 件のCookieでプレフィックス要件を満たしていません (${prefixIssues.map((i) => i.name).join(', ')})`,
      description:
        '__Host- または __Secure- / __Http- プレフィックスが付与されているCookieが仕様要件を満たしていません。ブラウザによって破棄されるか無効化されます。',
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

  // 5. 課題が一切検出されなかった場合
  if (issues.length === 0) {
    checks.push({
      checkId: 'SEC-COOKIE-00',
      category: 'cookies',
      name: 'Cookie属性セキュリティ',
      status: 'pass',
      severity: 'info',
      observed: `${processedCookies.length} 件のCookieを検査（全属性が適切）`,
      description: '検出されたCookieに適切なセキュリティ属性が設定されています。',
      recommendation: '現在の設定を維持してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Cookies'],
      scope: url,
    });
  }

  return { checks, inspectedCookies: processedCookies };
}

function formatCookieCategory(category: CookieCategory): string {
  const map: Record<CookieCategory, string> = {
    authentication: '認証・セッション',
    csrf: 'CSRF対策',
    analytics: 'トラッキング・解析',
    preferences: 'UI・機能設定',
    general: '一般・未分類',
  };
  return map[category] || category;
}

function getCookieRecommendation(
  category: CookieCategory,
  missing: string[],
  prefixType?: string | null
): string {
  const recs: string[] = [];

  if (prefixType) {
    recs.push(`プレフィックス '${prefixType}' の仕様要件（Secure, Path=/ 等）を正しく満たしてください。`);
  }

  if (missing.includes('Secure')) {
    recs.push("暗号化通信を強制するために 'Secure' 属性を付与してください。");
  }

  if (missing.includes('HttpOnly')) {
    if (category === 'authentication') {
      recs.push("XSSによるセッション奪取を防止するため、直ちに 'HttpOnly' 属性を付与してください。");
    } else if (category === 'general') {
      recs.push("JavaScriptからのアクセスが不要であれば 'HttpOnly' 属性の付与を推奨します。");
    }
  }

  if (missing.includes('SameSite')) {
    recs.push("クロスサイトリクエスト時の送信を制御するため、適切な 'SameSite' (LaxまたはStrict) を指定してください。");
  }

  return recs.join(' ');
}
