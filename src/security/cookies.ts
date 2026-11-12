/**
 * Web Technology & Security Inspector
 * Cookie属性セキュリティ診断 (src/security/cookies.ts) - IMP-04 (Rev.2.1) / v1.7.0 T07 (D7)
 * 
 * - Chrome API SameSiteStatus の内部正規化 (normalizeSameSite)
 * - 用途別分類の高度化・あいまい性 (ambiguous) 管理
 * - Partitioned Cookie (CHIPS) 識別
 * - Cookie値（Value）の完全非保持（プライバシー保護徹底）
 * - 安定ID (FindingIdentity) の付与
 * - v1.7.0 D7: ブラウザが保存しないCookie（プレフィックス違反・SameSite=NoneでSecureなし・PartitionedでSecureなし）のチェックを削除
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
 * 有効なCookie用途カテゴリの集合 (v1.7.1 T07)
 */
const VALID_COOKIE_CATEGORIES: ReadonlySet<CookieCategory> = new Set<CookieCategory>([
  'authentication',
  'csrf',
  'analytics',
  'advertising',
  'consent',
  'preferences',
  'general',
]);

/**
 * 未知または未設定のCookie用途値を既定値 ('general') へ正規化する（過去履歴・将来互換用）(v1.7.1 T07)
 *
 * @param category 検査対象または履歴から読み込んだカテゴリ値
 * @returns 正規化された CookieCategory
 */
export function normalizeCookieCategory(category: unknown): CookieCategory {
  if (typeof category === 'string' && VALID_COOKIE_CATEGORIES.has(category as CookieCategory)) {
    return category as CookieCategory;
  }
  return 'general';
}

/**
 * 既知Cookie辞書（完全一致による高信頼度分類・小文字キー）(v1.7.1 T07)
 */
const KNOWN_COOKIES: Record<string, CookieCategory> = {
  // 認証・セッション
  phpsessid: 'authentication',
  jsessionid: 'authentication',
  'asp.net_sessionid': 'authentication',
  aspsessionid: 'authentication',
  _gh_sess: 'authentication',
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
  __requestverificationtoken: 'csrf',
  anti_forgery: 'csrf',
  antiforgery: 'csrf',
  'mw-wp-form-token': 'csrf',
  // 解析・トラッキング
  _ga: 'analytics',
  _gid: 'analytics',
  _gat: 'analytics',
  ai_session: 'analytics',
  ai_user: 'analytics',
  __utma: 'analytics',
  __utmb: 'analytics',
  __utmc: 'analytics',
  __utmt: 'analytics',
  __utmz: 'analytics',
  _mkto_trk: 'analytics',
  // 広告・マーケティング
  _fbp: 'advertising',
  _twpid: 'advertising',
  _twsid: 'advertising',
  // 同意管理
  optanonconsent: 'consent',
  optanonalertboxclosed: 'consent',
  'zaraz-consent': 'consent',
  cookieconsent: 'consent',
  // UI設定
  theme: 'preferences',
  theme_mode: 'preferences',
  user_lang: 'preferences',
  lang: 'preferences',
  locale: 'preferences',
  sidebar_view: 'preferences',
};

/**
 * 既知Cookieプレフィックス対応表（先頭一致による高信頼度分類・小文字）(v1.7.1 T07)
 * 名前の対応表にあるプレフィックス（kndctr_*, _gcl_*, anti_forgery*, antiforgery*, ASPSESSIONID* 等）を
 * パターン判定より優先して分類する。
 */
const KNOWN_COOKIE_PREFIXES: ReadonlyArray<{ prefix: string; category: CookieCategory }> = [
  // 解析・トラッキング
  { prefix: 'kndctr_', category: 'analytics' },
  // 広告・マーケティング
  { prefix: '_gcl_', category: 'advertising' },
  // CSRF対策
  { prefix: '__requestverificationtoken', category: 'csrf' },
  { prefix: 'anti_forgery', category: 'csrf' },
  { prefix: 'antiforgery', category: 'csrf' },
  { prefix: '.aspnetcore.antiforgery', category: 'csrf' },
  // 認証・セッション
  { prefix: 'aspsessionid', category: 'authentication' },
];

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
 * Cookieの名称から詳細な分類・あいまい性を判定する (IMP-04 / 3.3 / v1.7.1 T07)
 *
 * - 名前の対応表（完全一致・プレフィックス一致）にあるものをパターン判定より優先する
 * - token を含んでも verification や forgery を含む名前は CSRF にする
 * - ai_session のように session を含む計測用 Cookie が認証用にならないようにする
 *
 * @param name Cookie名
 * @returns CookieClassification
 */
export function classifyCookieAdvanced(name: string): CookieClassification {
  const lower = String(name || '').toLowerCase().trim();
  const matchedRules: string[] = [];

  // 1. 既知Cookie辞書への完全一致（パターンより優先）
  if (KNOWN_COOKIES[lower]) {
    const knownCategory = KNOWN_COOKIES[lower];
    matchedRules.push(`known-dict:${knownCategory}`);
    return {
      category: knownCategory,
      confidence: 'high',
      matchedRules,
      ambiguous: false,
      overridden: false,
    };
  }

  // 2. 既知Cookieプレフィックス対応表への先頭一致（パターンより優先）
  for (const entry of KNOWN_COOKIE_PREFIXES) {
    if (lower.startsWith(entry.prefix)) {
      matchedRules.push(`known-prefix:${entry.category}`);
      return {
        category: entry.category,
        confidence: 'high',
        matchedRules,
        ambiguous: false,
        overridden: false,
      };
    }
  }

  let isConsent = false;
  let isAdvertising = false;
  let isAnalytics = false;
  let isCsrf = false;
  let isPreferences = false;
  let isAuth = false;

  // 3. 同意管理パターン
  if (/(optanon|cookie[-_]?consent|zaraz[-_]?consent)/i.test(lower)) {
    isConsent = true;
    matchedRules.push('pattern:consent');
  }

  // 4. 広告・マーケティングパターン
  if (/^(_gcl_|_fbp|_fbc|_twpid|_twsid)/i.test(lower)) {
    isAdvertising = true;
    matchedRules.push('pattern:advertising');
  }

  // 5. 解析・トラッキングパターン
  if (/^(_ga|_gid|_gat|__utm|_hj|mp_|ai_session|ai_user|_mkto_trk|kndctr_)/i.test(lower)) {
    isAnalytics = true;
    matchedRules.push('pattern:analytics');
  }

  // 6. CSRF専用パターン（token を含んでも verification や forgery を含む名前は CSRF にする）
  if (/(csrf|xsrf|verification|forgery)/i.test(lower)) {
    isCsrf = true;
    matchedRules.push('pattern:csrf');
  }

  // 7. UI・表示設定パターン
  if (/(theme|mode|lang|locale|sidebar|view|layout)/i.test(lower)) {
    isPreferences = true;
    matchedRules.push('pattern:preferences');
  }

  // 8. 認証・セッションパターン
  // ※ verification / forgery / csrf / xsrf を含むトークンは CSRF 用であり token 単体では認証とみなさない。
  //    また計測用 Cookie（ai_session, _hjSession 等）に含まれる session も認証用としない。
  const hasExplicitAuthKeyword =
    /(auth|jwt|(^|[_\-.])sid([_\-.]|$)|ticket|connect\.sid|phpsessid|jsessionid|aspsessionid|_gh_sess)/i.test(lower) ||
    (!isAnalytics && /(session|sess)/i.test(lower)) ||
    (!isCsrf && /token/i.test(lower));
  if (hasExplicitAuthKeyword) {
    isAuth = true;
    matchedRules.push('pattern:authentication');
  }

  const matchCount = [isConsent, isAdvertising, isAnalytics, isCsrf, isPreferences, isAuth].filter(Boolean).length;
  const ambiguous = matchCount > 1;

  // 優先順位決定 (同意管理 -> 広告 -> 解析 -> CSRF -> UI設定 -> 認証 -> 一般)
  let category: CookieCategory = 'general';
  if (isConsent) category = 'consent';
  else if (isAdvertising) category = 'advertising';
  else if (isAnalytics) category = 'analytics';
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
  const missing: ('Secure' | 'HttpOnly')[] = [];
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

  // 2. HttpOnly属性の検査 (用途に応じた判定)
  if (!cookie.httpOnly) {
    if (category === 'authentication') {
      missing.push('HttpOnly');
      descriptions.push('認証・セッションCookieですが、JavaScriptアクセスを遮断するHttpOnly属性が欠落しています。');
    } else if (category === 'general' && !classification.ambiguous) {
      missing.push('HttpOnly');
      descriptions.push('HttpOnly属性が設定されていません。');
    }
  }

  const isDomainPrefix = cookie.domain ? cookie.domain.startsWith('.') : false;
  const isHostOnly = 'hostOnly' in cookie ? Boolean(cookie.hostOnly) : !isDomainPrefix;

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
  } else {
    severity = missing.includes('Secure') ? 'medium' : 'low';
  }

  // 安定IDの発行 (IMP-07)
  const normalizedPartitionKey =
    typeof cookie.partitionKey === 'object' && cookie.partitionKey !== null
      ? cookie.partitionKey.topLevelSite || null
      : typeof cookie.partitionKey === 'string'
        ? cookie.partitionKey
        : null;
  const resourceKey = buildCookieResourceKey(
    cookie.name,
    cookie.domain || '',
    cookie.path || '/',
    isHostOnly,
    normalizedPartitionKey
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
    recommendation: getCookieRecommendation(category, missing),
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
    } else {
      if (
        !rawCookie.httpOnly &&
        (classification.category === 'csrf' ||
          classification.category === 'preferences' ||
          classification.category === 'analytics' ||
          classification.category === 'advertising' ||
          classification.category === 'consent')
      ) {
        issueTexts.push('HttpOnly未設定 (フロントエンド連携のため意図的)');
      }
    }

    const isDomainPrefix = rawCookie.domain ? rawCookie.domain.startsWith('.') : false;
    const isHostOnly = 'hostOnly' in rawCookie ? Boolean(rawCookie.hostOnly) : !isDomainPrefix;

    const normalizedPartitionKey =
      typeof rawCookie.partitionKey === 'object' && rawCookie.partitionKey !== null
        ? rawCookie.partitionKey.topLevelSite || null
        : typeof rawCookie.partitionKey === 'string'
          ? rawCookie.partitionKey
          : null;

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
      partitionKey: normalizedPartitionKey,
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
      const namesSummary = formatCookieNamesForObserved(
        missingSecure.map((i) => i.name),
        3
      );
      checks.push({
        checkId: 'SEC-COOKIE-SECURE-CSRF',
        category: 'cookies',
        name: 'CSRFトークン Secure属性未設定',
        status: 'warning',
        severity: 'medium',
        observed: `${missingSecure.length} 件のCSRF保護CookieでSecure属性が未設定 (${namesSummary})`,
        description: 'CSRFトークンが暗号化されていない平文通信で送出されるリスクがあります。',
        recommendation: 'CSRFトークンを保持するCookieに「Secure」属性を付与してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Cookies'],
        scope: url,
      });
    }
  }

  // 3. 一般・解析・広告・同意管理・UI設定等のCookie（v1.7.1 T07: 認証系の指摘とは独立に出す）
  const generalIssues = issues.filter(
    (i) =>
      i.category === 'general' ||
      i.category === 'analytics' ||
      i.category === 'advertising' ||
      i.category === 'consent' ||
      i.category === 'preferences'
  );
  if (generalIssues.length > 0) {
    const missingSecure = generalIssues.filter((i) => i.missingAttributes.includes('Secure'));
    if (missingSecure.length > 0) {
      const namesSummary = formatCookieNamesForObserved(
        missingSecure.map((i) => i.name),
        3
      );
      checks.push({
        checkId: 'SEC-COOKIE-SECURE-GENERAL',
        category: 'cookies',
        name: 'Cookie Secure属性未設定 (一般・解析用)',
        status: 'warning',
        severity: 'low',
        observed: `${missingSecure.length} 件の非認証系CookieでSecure属性が未設定 (${namesSummary})`,
        description: '機密性の低いCookieですが、HTTPS通信環境下では全CookieにSecure属性を設定することが推奨されます。',
        recommendation: 'Webサーバーまたは発行スクリプトで「Secure」フラグを付与してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Cookies'],
        scope: url,
      });
    }
  }

  // 3b. 認証系 Cookie の有効期限・SameSite チェック (v1.8.0 T08 / NEW-03c)
  const authCookies = processedCookies.filter((c) => c.category === 'authentication');
  if (authCookies.length > 0) {
    const nowSec = Date.now() / 1000;
    const ONE_YEAR_SEC = 365 * 24 * 60 * 60;

    // SEC-COOKIE-EXPIRY: 有効期限が 1 年（365日）を超える認証系 Cookie
    const expiryCookies = authCookies.filter(
      (c) => !c.session && typeof c.expirationDate === 'number' && c.expirationDate > nowSec + ONE_YEAR_SEC
    );
    if (expiryCookies.length > 0) {
      const namesSummary = formatCookieNamesForObserved(
        expiryCookies.map((c) => c.name),
        3
      );
      checks.push({
        checkId: 'SEC-COOKIE-EXPIRY',
        category: 'cookies',
        name: '認証系 Cookie の有効期限が長い',
        status: 'warning',
        severity: 'low',
        observed: `${expiryCookies.length} 件の認証系Cookieで有効期限が1年（365日）を超過 (${namesSummary})`,
        description:
          '認証・セッションCookieの有効期限が1年（365日）を超えて設定されています。長期間有効な認証Cookieは、端末の紛失やセッションハイジャック時のリスクを高めます。',
        recommendation:
          'セッションCookieとするか、認証Cookieの有効期限を必要最小限（例: 数時間〜数日、長くても数週間以内）に設定してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Cookies'],
        scope: url,
      });
    }

    // SEC-COOKIE-SAMESITE-NONE: SameSite=None かつ Secure ありの認証系 Cookie
    const samesiteNoneCookies = authCookies.filter(
      (c) => normalizeSameSite(c.sameSite) === 'none' && c.secure === true
    );
    if (samesiteNoneCookies.length > 0) {
      const namesSummary = formatCookieNamesForObserved(
        samesiteNoneCookies.map((c) => c.name),
        3
      );
      checks.push({
        checkId: 'SEC-COOKIE-SAMESITE-NONE',
        category: 'cookies',
        name: '認証系 Cookie の SameSite=None',
        status: 'warning',
        severity: 'low',
        observed: `${samesiteNoneCookies.length} 件の認証系CookieでSameSite=Noneが設定されています (${namesSummary})`,
        description:
          '認証・セッションCookieにSameSite=Noneが設定されているため、外部サイトからのクロスサイトリクエスト（CSRFなど）でもCookieが送信されます。',
        recommendation:
          'クロスサイトでの送信が必須でない場合は、SameSite属性をLaxまたはStrictに設定し、クロスサイトリクエスト時の送信を制限してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Set-Cookie/SameSite'],
        scope: url,
      });
    }
  }

  // 4. 課題が一切検出されなかった場合（v1.7.1 T07: HTTPページでは「HTTP のため Secure は評価対象外」と書き分ける）
  if (checks.length === 0) {
    checks.push({
      checkId: 'SEC-COOKIE-00',
      category: 'cookies',
      name: 'Cookie属性セキュリティ',
      status: 'pass',
      severity: 'info',
      observed: isHttps
        ? `${processedCookies.length} 件のCookieを検査（全属性が適切）`
        : `${processedCookies.length} 件のCookieを検査（HTTP のため Secure は評価対象外）`,
      description: isHttps
        ? '検出されたCookieに適切なセキュリティ属性が設定されています。'
        : '検出されたCookieにHttpOnly等の不備はありません（HTTP通信のためSecure属性は評価対象外です）。',
      recommendation: '現在の設定を維持してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Cookies'],
      scope: url,
    });
  }

  return { checks, inspectedCookies: processedCookies };
}

/**
 * 観測値に表示する対象Cookie名リストを最大 maxCount 件までに整形する (v1.7.1 T07)
 */
function formatCookieNamesForObserved(names: string[], maxCount = 3): string {
  const displayed = names.slice(0, maxCount).join(', ');
  const rest = names.length - maxCount;
  return rest > 0 ? `${displayed} 他 ${rest} 件` : displayed;
}

/**
 * Cookie用途カテゴリの日本語表示名を返す（未知の用途は general として扱う）(v1.7.1 T07)
 */
export function formatCookieCategory(category: CookieCategory | string | undefined | null): string {
  const normalized = normalizeCookieCategory(category);
  const map: Record<CookieCategory, string> = {
    authentication: '認証・セッション',
    csrf: 'CSRF対策',
    analytics: 'トラッキング・解析',
    advertising: '広告・マーケティング',
    consent: '同意管理',
    preferences: 'UI・機能設定',
    general: '一般・未分類',
  };
  return map[normalized];
}

function getCookieRecommendation(
  category: CookieCategory,
  missing: string[]
): string {
  const recs: string[] = [];

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

  return recs.join(' ');
}
