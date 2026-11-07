/**
 * Web Technology & Security Inspector
 * HTTPセキュリティヘッダー診断 (src/security/headers.ts)
 */

import { SecurityCheckResult } from '../shared/types';
import { analyzeCSPPolicies, parseCSPHeaderValues } from './csp-parser';

/**
 * セキュリティ診断 (checkHttpHeaders) で評価・参照されるHTTPヘッダー名一覧（小文字）
 * 手書きでの二重管理を防ぐため、診断ロジックで参照されるヘッダーを一元定義する
 */
export const SECURITY_HEADER_NAMES: readonly string[] = [
  'strict-transport-security',
  'content-security-policy',
  'content-security-policy-report-only',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'access-control-allow-origin',
  'access-control-allow-credentials',
  'cross-origin-opener-policy',
  'cross-origin-embedder-policy',
  'cross-origin-resource-policy',
  'server',
  'x-powered-by',
  'x-aspnet-version',
];

/**
 * X-Frame-Options の値がブラウザで有効な指定（DENY または SAMEORIGIN）であるか判定する (v1.7.0 T07 / SPEC-12)
 */
export function isValidXFrameOptions(xfo: string | null | undefined): boolean {
  if (!xfo) return false;
  const tokens = xfo
    .split(',')
    .map((t) => t.trim().toUpperCase())
    .filter(Boolean);
  if (tokens.length === 0) return false;
  // 単一または同一値の繰り返しで DENY または SAMEORIGIN のみ有効とする
  const first = tokens[0];
  if (first !== 'DENY' && first !== 'SAMEORIGIN') {
    return false;
  }
  return tokens.every((t) => t === first);
}

const SAFE_REFERRER_POLICIES = new Set([
  'no-referrer',
  'same-origin',
  'origin',
  'strict-origin',
  'origin-when-cross-origin',
  'strict-origin-when-cross-origin',
]);

const ALL_RECOGNIZED_REFERRER_POLICIES = new Set([
  ...SAFE_REFERRER_POLICIES,
  'no-referrer-when-downgrade',
  'unsafe-url',
]);

/**
 * HTTPレスポンスヘッダーを診断する
 *
 * @param headers レスポンスヘッダーのマップ (キーは小文字)
 * @param url 調査対象URL
 * @param isHttps HTTPS接続かどうか
 * @returns セキュリティチェック結果一覧
 */
export function checkHttpHeaders(
  headers: Record<string, string[]>,
  url: string,
  isHttps: boolean
): SecurityCheckResult[] {
  const results: SecurityCheckResult[] = [];

  // ヘッダー取得ヘルパー (小文字化キーで先頭値または結合値を取得)
  const getHeader = (name: string): string | null => {
    const vals = headers[name.toLowerCase()];
    if (!vals || vals.length === 0) return null;
    return vals.join(', ');
  };

  // --- 1. HSTS (Strict-Transport-Security) (v1.7.0 T07 / SPEC-12) ---
  const hsts = getHeader('strict-transport-security');
  if (isHttps) {
    if (!hsts) {
      results.push({
        checkId: 'SEC-HSTS-01',
        category: 'http-headers',
        name: 'HSTS (Strict-Transport-Security)',
        status: 'warning',
        severity: 'medium',
        observed: 'ヘッダー未設定',
        description:
          'HTTPS接続においてHSTSヘッダーが検出されませんでした。中間者攻撃やダウングレード攻撃（SSL Stripping）のリスクがあります。',
        recommendation:
          '適切なmax-ageディレクティブ（推奨: 1年以上: 31536000）を設定し、必要に応じてincludeSubDomainsやpreloadを付与してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Strict-Transport-Security'],
        scope: url,
      });
    } else {
      const maxAgeMatch = hsts.match(/max-age\s*=\s*(\d+)/i);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : null;
      const hasSubDomains = /includeSubDomains/i.test(hsts);

      if (maxAge === null || maxAge === 0) {
        // max-age=0（HSTSの明示的な無効化）または max-age 未指定
        results.push({
          checkId: 'SEC-HSTS-02',
          category: 'http-headers',
          name: 'HSTS (Strict-Transport-Security)',
          status: 'warning',
          severity: 'medium',
          observed: hsts,
          description:
            maxAge === 0
              ? 'HSTSのmax-ageが 0 に設定されており、HSTSが明示的に無効化されています。中間者攻撃やダウングレード攻撃（SSL Stripping）のリスクがあります。'
              : 'HSTSヘッダーに有効なmax-ageディレクティブが含まれていません。',
          recommendation:
            'HSTSを有効にするため、max-age=31536000（1年）以上の値を設定してください。',
          referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Strict-Transport-Security'],
          scope: url,
        });
      } else if (maxAge < 31536000) {
        // 1年（31536000秒）未満
        results.push({
          checkId: 'SEC-HSTS-02',
          category: 'http-headers',
          name: 'HSTS (Strict-Transport-Security)',
          status: 'warning',
          severity: 'low',
          observed: hsts,
          description: `HSTSのmax-ageが ${maxAge} 秒（約 ${Math.round(maxAge / 86400)} 日）と1年（31536000秒）未満に設定されています。`,
          recommendation: 'HSTSの有効期間は1年以上（推奨: 31536000秒 = 1年）を設定することを検討してください。',
          referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Strict-Transport-Security'],
          scope: url,
        });
      } else {
        results.push({
          checkId: 'SEC-HSTS-00',
          category: 'http-headers',
          name: 'HSTS (Strict-Transport-Security)',
          status: 'pass',
          severity: 'info',
          observed: hsts,
          description: `適切にHSTSが設定されています (max-age=${maxAge}${hasSubDomains ? ', サブドメイン含む' : ''})。`,
          recommendation: '現在の設定を維持してください。',
          referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Strict-Transport-Security'],
          scope: url,
        });
      }
    }
  }

  // --- 2. CSP (Content-Security-Policy) (v1.7.0 T06 / SPEC-07: 配列要素・カンマ区切りごとに別ポリシーとして解析) ---
  const cspPolicies = [
    ...parseCSPHeaderValues(headers['content-security-policy'], 'response-header', 'enforce'),
    ...parseCSPHeaderValues(
      headers['content-security-policy-report-only'],
      'response-header',
      'report-only'
    ),
  ];

  const xfo = getHeader('x-frame-options');
  const validXfo = isValidXFrameOptions(xfo);

  if (cspPolicies.length === 0) {
    results.push({
      checkId: 'SEC-CSP-01',
      category: 'http-headers',
      name: 'CSP (Content-Security-Policy)',
      status: 'warning',
      severity: 'medium',
      observed: 'ヘッダー未設定',
      description:
        'CSPヘッダーが設定されていません。クロスサイトスクリプティング（XSS）やデータインジェクション攻撃への多層防御が不足しています。',
      recommendation:
        '信頼できるリソースのみを読み込むCSPポリシー（script-src, default-src 等）を定義してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/CSP'],
      scope: url,
    });
  } else {
    results.push(...analyzeCSPPolicies(cspPolicies, url, validXfo).results);
  }

  // --- 3. X-Frame-Options (クリックジャッキング対策) (v1.7.0 T07 / SPEC-12) ---
  const hasCspFrameAncestors = cspPolicies.some(
    (p) =>
      p.mode === 'enforce' &&
      p.source === 'response-header' &&
      Boolean(p.directives['frame-ancestors']?.length)
  );

  if (hasCspFrameAncestors) {
    // CSP frame-ancestors がある場合はブラウザ仕様どおり frame-ancestors を優先して判定 (v1.7.1 T01: 項目名を統一し観測値で区別)
    results.push({
      checkId: 'SEC-XFO-00',
      category: 'http-headers',
      name: 'X-Frame-Options',
      status: 'pass',
      severity: 'info',
      observed: validXfo ? `${xfo} (CSP frame-ancestors により保護)` : 'CSP frame-ancestors により保護',
      description: validXfo
        ? `X-Frame-Options (${xfo}) および CSP frame-ancestors が設定されています。`
        : 'モダンなCSP frame-ancestorsディレクティブによりiframe埋め込みが制御されています（CSP frame-ancestorsがある環境ではX-Frame-Optionsより優先されます）。',
      recommendation: '現状の設定を維持してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors'],
      scope: url,
    });
  } else if (!xfo) {
    results.push({
      checkId: 'SEC-XFO-01',
      category: 'http-headers',
      name: 'X-Frame-Options',
      status: 'warning',
      severity: 'medium',
      observed: 'ヘッダー未設定',
      description:
        'X-Frame-Options および CSP frame-ancestors が設定されていません。第三者サイトのiframe内に埋め込まれ、クリックジャッキング攻撃を受ける恐れがあります。',
      recommendation:
        'X-Frame-Optionsに DENY または SAMEORIGIN を設定するか、CSPの frame-ancestors ディレクティブを設定してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/X-Frame-Options'],
      scope: url,
    });
  } else if (!validXfo) {
    results.push({
      checkId: 'SEC-XFO-02',
      category: 'http-headers',
      name: 'X-Frame-Options',
      status: 'warning',
      severity: 'medium',
      observed: xfo,
      description: `X-Frame-Options に有効ではない値または廃止された値 (${xfo}) が指定されています。DENY または SAMEORIGIN 以外の値（ALLOWALL、ALLOW-FROM 等）ではクリックジャッキング攻撃を防止できません。`,
      recommendation:
        'X-Frame-Options には DENY または SAMEORIGIN を設定するか、特定オリジンの埋め込み許可には CSP の frame-ancestors ディレクティブを使用してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/X-Frame-Options'],
      scope: url,
    });
  } else {
    results.push({
      checkId: 'SEC-XFO-00',
      category: 'http-headers',
      name: 'X-Frame-Options',
      status: 'pass',
      severity: 'info',
      observed: xfo,
      description: `X-Frame-Optionsが適切に設定されています (${xfo})。`,
      recommendation: '現状の設定を維持してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/X-Frame-Options'],
      scope: url,
    });
  }

  // --- 4. X-Content-Type-Options (MIMEスニッフィング対策) ---
  const xcto = getHeader('x-content-type-options');
  if (!xcto || !xcto.toLowerCase().includes('nosniff')) {
    results.push({
      checkId: 'SEC-XCTO-01',
      category: 'http-headers',
      name: 'X-Content-Type-Options',
      status: 'warning',
      severity: 'low',
      observed: xcto || 'ヘッダー未設定',
      description:
        'X-Content-Type-Options: nosniff が設定されていません。ブラウザがレスポンスのMIMEタイプを誤解釈（スニッフィング）して悪意あるスクリプトを実行するリスクがあります。',
      recommendation: 'Webサーバーで「X-Content-Type-Options: nosniff」を付与してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/X-Content-Type-Options'],
      scope: url,
    });
  } else {
    results.push({
      checkId: 'SEC-XCTO-00',
      category: 'http-headers',
      name: 'X-Content-Type-Options',
      status: 'pass',
      severity: 'info',
      observed: 'nosniff',
      description: 'MIMEタイプスニッフィング防止が有効です。',
      recommendation: '現状の設定を維持してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/X-Content-Type-Options'],
      scope: url,
    });
  }

  // --- 5. Referrer-Policy (v1.7.0 T07 / SPEC-12 / v1.7.1 T01) ---
  const referrerPolicy = getHeader('referrer-policy');
  if (!referrerPolicy) {
    results.push({
      checkId: 'SEC-REF-01',
      category: 'http-headers',
      name: 'Referrer-Policy',
      status: 'info',
      severity: 'info',
      observed: 'ヘッダー未設定 (ブラウザ既定値 strict-origin-when-cross-origin)',
      description:
        'Referrer-Policyが明示されていません。モダンブラウザでは既定値が適用されますが、明示的なポリシー指定が推奨されます。',
      recommendation: '「Referrer-Policy: strict-origin-when-cross-origin」等の明示的なヘッダー設定を検討してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Referrer-Policy'],
      scope: url,
    });
  } else {
    const tokens = referrerPolicy
      .split(',')
      .map((t) => t.trim().toLowerCase())
      .filter(Boolean);
    const recognizedTokens = tokens.filter((t) => ALL_RECOGNIZED_REFERRER_POLICIES.has(t));
    const effectivePolicy =
      recognizedTokens.length > 0 ? recognizedTokens[recognizedTokens.length - 1] : null;

    if (!effectivePolicy) {
      results.push({
        checkId: 'SEC-REF-02',
        category: 'http-headers',
        name: 'Referrer-Policy (無効な設定値)',
        status: 'warning',
        severity: 'low',
        observed: referrerPolicy,
        description: `Referrer-Policy に認識できない値 (${referrerPolicy}) が指定されています。ブラウザによって無視され、意図したリファラー制御が行われない恐れがあります。`,
        recommendation:
          '「strict-origin-when-cross-origin」や「no-referrer」など、仕様で定義された有効なポリシー値を指定してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Referrer-Policy'],
        scope: url,
      });
    } else if (effectivePolicy === 'unsafe-url') {
      results.push({
        checkId: 'SEC-REF-02',
        category: 'http-headers',
        name: 'Referrer-Policy (unsafe-url)',
        status: 'warning',
        severity: 'low',
        observed: referrerPolicy,
        description:
          'Referrer-Policy に unsafe-url が指定されています。クロスオリジン通信やHTTPSからHTTPへのダウングレード時にもクエリパラメータを含むURL全体が送信されるため、URL内の機密情報が外部へ漏洩するリスクがあります。',
        recommendation:
          '「strict-origin-when-cross-origin」、「strict-origin」、または「no-referrer」への変更を検討してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Referrer-Policy'],
        scope: url,
      });
    } else if (effectivePolicy === 'no-referrer-when-downgrade') {
      results.push({
        checkId: 'SEC-REF-03',
        category: 'http-headers',
        name: 'Referrer-Policy (no-referrer-when-downgrade)',
        status: 'info',
        severity: 'info',
        observed: referrerPolicy,
        description:
          'Referrer-Policy に no-referrer-when-downgrade が指定されています。HTTPSからHTTPへの通信ではリファラーが省略されますが、HTTPS間のクロスオリジン通信ではパスやクエリを含むURL全体が送信されます。',
        recommendation:
          'クロスオリジンへのパス・クエリ送信を抑止したい場合は「strict-origin-when-cross-origin」への変更を検討してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Referrer-Policy'],
        scope: url,
      });
    } else {
      results.push({
        checkId: 'SEC-REF-00',
        category: 'http-headers',
        name: 'Referrer-Policy',
        status: 'pass',
        severity: 'info',
        observed: referrerPolicy,
        description: `Referrer-Policyが適切に明示されています (${referrerPolicy})。`,
        recommendation: '現状の設定を維持してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Referrer-Policy'],
        scope: url,
      });
    }
  }

  // --- 6. Permissions-Policy (Feature-Policy) ---
  const permissionsPolicy = getHeader('permissions-policy');
  if (!permissionsPolicy) {
    results.push({
      checkId: 'SEC-PERM-01',
      category: 'http-headers',
      name: 'Permissions-Policy',
      status: 'info',
      severity: 'info',
      observed: 'ヘッダー未設定',
      description:
        'Permissions-Policyが設定されていません。カメラ、マイク、位置情報などのブラウザ機能へのアクセス制御を制限することで、不要な権限の濫用を防ぐことができます。',
      recommendation: 'カメラ・マイク等を使わないページでは、geolocation=(), microphone=(), camera=() などを宣言して権限を制限することを推奨します。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Permissions-Policy'],
      scope: url,
    });
  }

  // --- 7. CORS (Access-Control-Allow-Origin) (v1.7.0 T07 / SPEC-12) ---
  const acao = getHeader('access-control-allow-origin');
  const acac = getHeader('access-control-allow-credentials');
  if (acao) {
    if (acao.trim() === '*' && acac?.trim().toLowerCase() === 'true') {
      results.push({
        checkId: 'SEC-CORS-01',
        category: 'cors',
        name: 'CORS設定 (クロスオリジン許可)',
        status: 'info',
        severity: 'info',
        observed: `Access-Control-Allow-Origin: * / Access-Control-Allow-Credentials: true`,
        description:
          'Access-Control-Allow-Origin: * と Access-Control-Allow-Credentials: true が同時に指定されています。この組み合わせはCORS仕様によりブラウザ側で拒否されるため直接の情報流出には至りませんが、サーバー側の設定ミスの可能性があります。',
        recommendation:
          '認証情報（Credentials）を伴う通信を許可する場合は特定の信頼できるOriginを明示し、不要な場合は Access-Control-Allow-Credentials ヘッダーを削除してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/CORS'],
        scope: url,
      });
    } else if (acao.trim() === '*') {
      results.push({
        checkId: 'SEC-CORS-02',
        category: 'cors',
        name: 'CORS設定 (クロスオリジン許可)',
        status: 'info',
        severity: 'info',
        observed: `Access-Control-Allow-Origin: *`,
        description: 'すべてのOriginからのクロスオリジン読み込みが許可されています（公開APIや静的リソースの場合は一般的）。',
        recommendation: '認証や機密データを伴うエンドポイントの場合は、許可するOriginを限定してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/CORS'],
        scope: url,
      });
    }
  }

  // --- 8. 情報露出 (Server, X-Powered-By, X-AspNet-Version) ---
  const server = getHeader('server');
  const xPoweredBy = getHeader('x-powered-by');
  const xAspNetVersion = getHeader('x-aspnet-version');

  if (server && /[0-9]+\.[0-9]+/.test(server)) {
    results.push({
      checkId: 'SEC-DISC-01',
      category: 'information-disclosure',
      name: 'Webサーバー詳細バージョン露出',
      status: 'warning',
      severity: 'low',
      observed: `Server: ${server}`,
      description:
        `Webサーバーの正確なバージョン番号が公開されています。既知の脆弱性（CVE）を抱えるバージョンである場合、攻撃者の標的となりやすくなります。`,
      recommendation:
        'サーバー設定（ApacheのServerTokens Prod、Nginxのserver_tokens offなど）でバージョン情報を非表示にすることを推奨します。',
      referenceUrls: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server'],
      scope: url,
    });
  }

  if (xPoweredBy) {
    results.push({
      checkId: 'SEC-DISC-02',
      category: 'information-disclosure',
      name: 'バックエンド技術情報露出 (X-Powered-By)',
      status: 'warning',
      severity: 'low',
      observed: `X-Powered-By: ${xPoweredBy}`,
      description:
        `バックエンドで使用しているプログラミング言語やフレームワーク（${xPoweredBy}）が明示されています。攻撃者に内部構成のヒントを与えてしまいます。`,
      recommendation:
        'Webサーバーまたはアプリケーションの設定（PHPのexpose_php = Off、Expressのapp.disable("x-powered-by")等）でヘッダーを削除してください。',
      referenceUrls: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework'],
      scope: url,
    });
  }

  if (xAspNetVersion) {
    results.push({
      checkId: 'SEC-DISC-03',
      category: 'information-disclosure',
      name: 'バックエンド技術情報露出 (X-AspNet-Version)',
      status: 'warning',
      severity: 'low',
      observed: `X-AspNet-Version: ${xAspNetVersion}`,
      description:
        `ASP.NET の詳細な CLR バージョン情報（${xAspNetVersion}）が公開されています。攻撃者に内部構成やランタイム世代のヒントを与えてしまいます。`,
      recommendation:
        'Web.config の <httpRuntime enableVersionHeader="false" /> 設定等により X-AspNet-Version ヘッダーを非表示にすることを推奨します。',
      referenceUrls: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework'],
      scope: url,
    });
  }

  return results;
}
