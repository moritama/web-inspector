/**
 * Web Technology & Security Inspector
 * HTTPセキュリティヘッダー診断 (src/security/headers.ts)
 */

import { SecurityCheckResult } from '../shared/types';
import { analyzeCSPHeader } from './csp-parser';

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

  // --- 1. HSTS (Strict-Transport-Security) ---
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
      const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
      const hasSubDomains = /includeSubDomains/i.test(hsts);

      if (maxAge < 10368000) {
        // 約120日未満
        results.push({
          checkId: 'SEC-HSTS-02',
          category: 'http-headers',
          name: 'HSTS (Strict-Transport-Security)',
          status: 'warning',
          severity: 'low',
          observed: hsts,
          description: `HSTSのmax-ageが ${maxAge} 秒（約 ${Math.round(maxAge / 86400)} 日）と短めに設定されています。`,
          recommendation: 'HSTSの有効期間は少なくとも180日以上（推奨: 31536000秒 = 1年）を設定することを検討してください。',
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

  // --- 2. CSP (Content-Security-Policy) ---
  const csp = getHeader('content-security-policy');
  const cspReportOnly = getHeader('content-security-policy-report-only');

  if (!csp && !cspReportOnly) {
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
  } else if (!csp && cspReportOnly) {
    results.push({
      checkId: 'SEC-CSP-02',
      category: 'http-headers',
      name: 'CSP (Content-Security-Policy)',
      status: 'info',
      severity: 'low',
      observed: `Report-Only設定中: ${cspReportOnly}`,
      description:
        'CSPはReport-Onlyモードでのみ動作しており、悪意あるスクリプトの実行は遮断されません（レポート収集段階）。',
      recommendation:
        '動作検証が完了した後、本番のContent-Security-Policyヘッダーとして適用し実行をブロックしてください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only'],
      scope: url,
    });
  } else if (csp) {
    const hasXfo = !!getHeader('x-frame-options');
    results.push(...analyzeCSPHeader(csp, url, hasXfo));
  }

  // --- 3. X-Frame-Options (クリックジャッキング対策) ---
  const xfo = getHeader('x-frame-options');
  const hasCspFrameAncestors = csp && /frame-ancestors/i.test(csp);

  if (!xfo && !hasCspFrameAncestors) {
    results.push({
      checkId: 'SEC-XFO-01',
      category: 'http-headers',
      name: 'X-Frame-Options (クリックジャッキング対策)',
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
  } else if (!xfo && hasCspFrameAncestors) {
    results.push({
      checkId: 'SEC-XFO-00',
      category: 'http-headers',
      name: 'クリックジャッキング対策 (frame-ancestors)',
      status: 'pass',
      severity: 'info',
      observed: 'CSP frame-ancestors により保護',
      description:
        'X-Frame-Optionsヘッダーはありませんが、モダンなCSP frame-ancestorsディレクティブによりiframe埋め込みが制御されています。',
      recommendation: '現状の設定を維持してください。古いブラウザ対応が必要な場合はX-Frame-Optionsの併用も検討可能です。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors'],
      scope: url,
    });
  } else {
    results.push({
      checkId: 'SEC-XFO-00',
      category: 'http-headers',
      name: 'X-Frame-Options',
      status: 'pass',
      severity: 'info',
      observed: xfo || '',
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

  // --- 5. Referrer-Policy ---
  const referrerPolicy = getHeader('referrer-policy');
  if (!referrerPolicy) {
    results.push({
      checkId: 'SEC-REF-01',
      category: 'http-headers',
      name: 'Referrer-Policy',
      status: 'info',
      severity: 'low',
      observed: 'ヘッダー未設定 (ブラウザ既定値 strict-origin-when-cross-origin)',
      description:
        'Referrer-Policyが明示されていません。モダンブラウザでは既定値が適用されますが、明示的なポリシー指定が推奨されます。',
      recommendation: '「Referrer-Policy: strict-origin-when-cross-origin」等の明示的なヘッダー設定を検討してください。',
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
      description: `Referrer-Policyが明示されています (${referrerPolicy})。`,
      recommendation: '現状の設定を維持してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Referrer-Policy'],
      scope: url,
    });
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

  // --- 7. CORS (Access-Control-Allow-Origin) ---
  const acao = getHeader('access-control-allow-origin');
  const acac = getHeader('access-control-allow-credentials');
  if (acao) {
    if (acao === '*' && acac === 'true') {
      results.push({
        checkId: 'SEC-CORS-01',
        category: 'cors',
        name: 'CORS設定 (クロスオリジン許可)',
        status: 'fail',
        severity: 'high',
        observed: `Access-Control-Allow-Origin: * / Access-Control-Allow-Credentials: true`,
        description:
          'ワイルドカード(*)と認証情報(Credentials)の併用は極めて危険であり、モダンブラウザではブロックされるか情報流出のリスクがあります。',
        recommendation: '特定の信頼できるOriginのみを明示的に許可し、ワイルドカードを使用しないでください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/CORS'],
        scope: url,
      });
    } else if (acao === '*') {
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

  // --- 8. 情報露出 (Server, X-Powered-By) ---
  const server = getHeader('server');
  const xPoweredBy = getHeader('x-powered-by');

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

  return results;
}
