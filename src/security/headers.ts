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
  'x-aspnetmvc-version',
  'x-xss-protection',
  'server-timing',
  'reporting-endpoints',
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

/**
 * RFC 9651 (Structured Fields) に基づく Permissions-Policy Dictionary 解析結果 (v1.8.0 T06)
 */
export interface PermissionsPolicyAllowlist {
  /** トークン * か、* を含む Inner List */
  all: boolean;
  /** 値に含まれていた項目（self や "https://…" など。表示用） */
  items: string[];
}

/**
 * Permissions-Policy の値を RFC 9651 の Dictionary として解析する (v1.8.0 T06)。
 * 構文エラーがある場合は null を返す。
 */
export function parsePermissionsPolicy(value: string): Map<string, PermissionsPolicyAllowlist> | null {
  const input = value;
  const len = input.length;
  let pos = 0;

  const skipSP = (): void => {
    while (pos < len && (input[pos] === ' ' || input[pos] === '\t')) {
      pos++;
    }
  };

  skipSP();
  if (pos >= len) {
    return new Map();
  }

  const result = new Map<string, PermissionsPolicyAllowlist>();

  // トークン文字判定 (RFC 9651 §4.2.6)
  const isTokenChar = (c: string): boolean => {
    return /[a-zA-Z0-9!#$%&'*+\-.^_`|~:/]/.test(c);
  };

  const parseKey = (): string | null => {
    if (pos >= len) return null;
    const first = input[pos];
    // key は lcalpha または * で始まる
    if (!(/[a-z*]/.test(first))) return null;
    let key = '';
    while (pos < len) {
      const c = input[pos];
      if (/[a-z0-9_\-.*]/.test(c)) {
        key += c;
        pos++;
      } else {
        break;
      }
    }
    return key;
  };

  const parseBareItem = (): { type: 'token' | 'string' | 'other'; value: string } | null => {
    if (pos >= len) return null;
    const c = input[pos];

    if (c === '"') {
      // 文字列
      pos++;
      let str = '';
      let closed = false;
      while (pos < len) {
        const ch = input[pos];
        if (ch === '\\') {
          pos++;
          if (pos >= len) return null;
          const next = input[pos];
          if (next !== '"' && next !== '\\') return null;
          str += next;
          pos++;
        } else if (ch === '"') {
          pos++;
          closed = true;
          break;
        } else if (ch < ' ' || ch > '~') {
          return null;
        } else {
          str += ch;
          pos++;
        }
      }
      if (!closed) return null;
      return { type: 'string', value: str };
    }

    if (c === '?') {
      // boolean
      pos++;
      if (pos < len && (input[pos] === '0' || input[pos] === '1')) {
        const v = input[pos];
        pos++;
        return { type: 'other', value: `?${v}` };
      }
      return null;
    }

    if (c === ':') {
      // byte sequence
      pos++;
      let b64 = '';
      let closed = false;
      while (pos < len) {
        const ch = input[pos];
        if (ch === ':') {
          pos++;
          closed = true;
          break;
        }
        b64 += ch;
        pos++;
      }
      if (!closed) return null;
      return { type: 'other', value: `:${b64}:` };
    }

    if (c === '-' || /[0-9]/.test(c)) {
      // integer / decimal
      let num = '';
      while (pos < len && /[0-9.\-]/.test(input[pos])) {
        num += input[pos];
        pos++;
      }
      return { type: 'other', value: num };
    }

    if (/[a-zA-Z*]/.test(c)) {
      // token
      let tok = '';
      while (pos < len && isTokenChar(input[pos])) {
        tok += input[pos];
        pos++;
      }
      return { type: 'token', value: tok };
    }

    return null;
  };

  const parseParameters = (): boolean => {
    while (pos < len && input[pos] === ';') {
      pos++;
      skipSP();
      const pKey = parseKey();
      if (!pKey) return false;
      skipSP();
      if (pos < len && input[pos] === '=') {
        pos++;
        skipSP();
        const pVal = parseBareItem();
        if (!pVal) return false;
      }
      skipSP();
    }
    return true;
  };

  while (pos < len) {
    const key = parseKey();
    if (!key) return null;
    skipSP();

    let allowlist: PermissionsPolicyAllowlist = { all: false, items: [] };

    if (pos < len && input[pos] === '=') {
      pos++;
      skipSP();
      if (pos >= len) return null;

      if (input[pos] === '(') {
        // Inner List
        pos++;
        let closed = false;
        const innerItems: string[] = [];
        let hasAll = false;

        while (pos < len) {
          skipSP();
          if (pos < len && input[pos] === ')') {
            pos++;
            closed = true;
            break;
          }
          const item = parseBareItem();
          if (!item) return null;

          if (item.type === 'token' && item.value === '*') {
            hasAll = true;
          }
          innerItems.push(item.type === 'string' ? `"${item.value}"` : item.value);

          if (!parseParameters()) return null;

          if (pos >= len) return null;

          const nextChar = input[pos];
          if (nextChar === ')') {
            pos++;
            closed = true;
            break;
          } else if (nextChar === ' ' || nextChar === '\t') {
            skipSP();
          } else {
            // Inner List のアイテム区切りは SP のみ（',' などは不正）
            return null;
          }
        }

        if (!closed) return null;
        if (!parseParameters()) return null;

        allowlist = { all: hasAll, items: innerItems };
      } else {
        // Item
        const item = parseBareItem();
        if (!item) return null;
        if (!parseParameters()) return null;

        const isAll = item.type === 'token' && item.value === '*';
        allowlist = {
          all: isAll,
          items: [item.type === 'string' ? `"${item.value}"` : item.value],
        };
      }
    } else {
      // '=' がない場合は Boolean true (?1)
      if (!parseParameters()) return null;
      allowlist = { all: false, items: ['?1'] };
    }

    result.set(key, allowlist);

    skipSP();
    if (pos >= len) break;

    if (input[pos] === ',') {
      pos++;
      skipSP();
      if (pos >= len) {
        // 末尾のカンマ (trailing comma) はエラー
        return null;
      }
    } else {
      // カンマでもなく終端でもない場合はエラー
      return null;
    }
  }

  return result;
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
 * checkHttpHeaders の追加オプション (meta CSP 併用評価用)
 */
export interface CheckHttpHeadersOptions {
  metaCsp?: string[];
  metaCspReportOnly?: string[];
}

/**
 * HTTPレスポンスヘッダーを診断する
 *
 * @param headers レスポンスヘッダーのマップ (キーは小文字)
 * @param url 調査対象URL
 * @param isHttps HTTPS接続かどうか
 * @param options meta 要素由来の CSP などの補助入力（任意）
 * @returns セキュリティチェック結果一覧
 */
export function checkHttpHeaders(
  headers: Record<string, string[]>,
  url: string,
  isHttps: boolean,
  options?: CheckHttpHeadersOptions
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
      const hasSubDomains = /\bincludeSubDomains\b/i.test(hsts);
      const hasPreload = /\bpreload\b/i.test(hsts);

      // preload が指定されているが max-age が 1 年未満の場合の注記 (v1.8.0 T03)
      const preloadNote = hasPreload
        ? ' また、preload が指定されていますが、preload の登録条件も満たしていない状態です（max-age が 1 年（31536000秒）未満）。'
        : '';

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
            (maxAge === 0
              ? 'HSTSのmax-ageが 0 に設定されており、HSTSが明示的に無効化されています。中間者攻撃やダウングレード攻撃（SSL Stripping）のリスクがあります。'
              : 'HSTSヘッダーに有効なmax-ageディレクティブが含まれていません。') + preloadNote,
          recommendation:
            'HSTSを有効にするため、max-age=31536000（1年）以上の値を設定してください。',
          referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Strict-Transport-Security'],
          scope: url,
        });
      } else if (maxAge < 86400) {
        // 1日（86400秒）未満（max-age=0 を除く）は MEDIUM (v1.7.1 T11 / N11)
        results.push({
          checkId: 'SEC-HSTS-02',
          category: 'http-headers',
          name: 'HSTS (Strict-Transport-Security)',
          status: 'warning',
          severity: 'medium',
          observed: hsts,
          description:
            `HSTSのmax-ageが ${maxAge} 秒と1日（86400秒）未満に設定されており、有効期間が極端に短いため十分な保護効果が得られません。` +
            preloadNote,
          recommendation: 'HSTSの有効期間は1年以上（推奨: 31536000秒 = 1年）を設定してください。',
          referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Strict-Transport-Security'],
          scope: url,
        });
      } else if (maxAge < 31536000) {
        // 1日以上・1年（31536000秒）未満
        results.push({
          checkId: 'SEC-HSTS-02',
          category: 'http-headers',
          name: 'HSTS (Strict-Transport-Security)',
          status: 'warning',
          severity: 'low',
          observed: hsts,
          description:
            `HSTSのmax-ageが ${maxAge} 秒（約 ${Math.round(maxAge / 86400)} 日）と1年（31536000秒）未満に設定されています。` +
            preloadNote,
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

      // preload があり max-age が 1 年以上で includeSubDomains だけが無いときに限る (v1.8.0 T03)
      if (hasPreload && maxAge !== null && maxAge >= 31536000 && !hasSubDomains) {
        results.push({
          checkId: 'SEC-HSTS-03',
          category: 'http-headers',
          name: 'HSTS (Strict-Transport-Security)',
          status: 'info',
          severity: 'info',
          observed: `${hsts} (preload の登録条件を満たしていない: includeSubDomains が未指定)`,
          description:
            'HSTSヘッダーに preload が指定されていますが、preload の登録条件を満たしていない状態（includeSubDomains が未指定）です。HSTS Preload リストへの登録には max-age=31536000（1年）以上かつ includeSubDomains の指定が必要です。',
          recommendation:
            'HSTS Preload を利用する場合は includeSubDomains を設定してください。Preload リストへの登録を意図しない場合は preload ディレクティブを削除してください。',
          referenceUrls: [
            'https://hstspreload.org/',
            'https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Strict-Transport-Security',
          ],
          scope: url,
        });
      }
    }
  }

  // --- 2. CSP (Content-Security-Policy) (v1.7.0 T06 / SPEC-07 / v1.7.1 T10: ヘッダーと meta の積集合評価) ---
  const cspPolicies = [
    ...parseCSPHeaderValues(headers['content-security-policy'], 'response-header', 'enforce'),
    ...parseCSPHeaderValues(
      headers['content-security-policy-report-only'],
      'response-header',
      'report-only'
    ),
    ...parseCSPHeaderValues(options?.metaCsp, 'meta', 'enforce'),
    ...parseCSPHeaderValues(options?.metaCspReportOnly, 'meta', 'report-only'),
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
    results.push(...analyzeCSPPolicies(cspPolicies, url, validXfo, xfo).results);
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
        name: 'Referrer-Policy',
        status: 'warning',
        severity: 'low',
        observed: `${referrerPolicy} (無効な設定値)`,
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
        name: 'Referrer-Policy',
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
        name: 'Referrer-Policy',
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

  // --- 6. Permissions-Policy (Feature-Policy) (v1.8.0 T06 / NEW-03a) ---
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
  } else {
    const parsedPolicy = parsePermissionsPolicy(permissionsPolicy);
    if (parsedPolicy === null) {
      results.push({
        checkId: 'SEC-PERM-03',
        category: 'http-headers',
        name: 'Permissions-Policy',
        status: 'info',
        severity: 'info',
        observed: permissionsPolicy,
        description:
          'Permissions-Policy ヘッダーの構文が RFC 9651 (Structured Fields) に準拠していないか、解釈できません。ブラウザによってヘッダー全体が無効化される可能性があります。',
        recommendation:
          'Permissions-Policy は Structured Fields の Dictionary 構文（例: geolocation=(), camera=()）で正しく指定してください。古い Feature-Policy 構文（セミコロン区切り等）を使用している場合は見直してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Permissions-Policy'],
        scope: url,
      });
    } else {
      const POWERFUL_FEATURES = ['camera', 'microphone', 'geolocation', 'payment', 'usb'];
      const wildcards = POWERFUL_FEATURES.filter((f) => parsedPolicy.get(f)?.all === true);
      if (wildcards.length > 0) {
        results.push({
          checkId: 'SEC-PERM-02',
          category: 'http-headers',
          name: 'Permissions-Policy',
          status: 'warning',
          severity: 'low',
          observed: permissionsPolicy,
          description: `Permissions-Policy において、強い権限（${wildcards.join(', ')}）がすべてのオリジン（*）に対して許可されています。不要な権限の濫用やクロスオリジン iframe からの不正アクセスのリスクがあります。`,
          recommendation:
            'カメラ・マイク・位置情報等の強い権限は * で無制限に許可せず、自オリジンのみ (self) に制限するか、() を指定して無効化することを推奨します。',
          referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Permissions-Policy'],
          scope: url,
        });
      }
    }
  }

  // --- 7. CORS (Access-Control-Allow-Origin) (v1.7.0 T07 / SPEC-12 / v1.7.1 T11 R05 項目名統一) ---
  const acao = getHeader('access-control-allow-origin');
  const acac = getHeader('access-control-allow-credentials');
  if (acao) {
    if (acao.trim() === '*' && acac?.trim().toLowerCase() === 'true') {
      results.push({
        checkId: 'SEC-CORS-01',
        category: 'cors',
        name: 'CORS (Cross-Origin Resource Sharing)',
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
        name: 'CORS (Cross-Origin Resource Sharing)',
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

  // --- 7.5 Cross-Origin 系ヘッダー (COOP / COEP / CORP) & X-XSS-Protection (v1.8.0 T06 / NEW-03a) ---
  // COOP (Cross-Origin-Opener-Policy)
  const coop = getHeader('cross-origin-opener-policy');
  const validCoopValues = new Set(['same-origin', 'same-origin-allow-popups', 'noopener-allow-popups']);
  if (!coop) {
    results.push({
      checkId: 'SEC-COOP-01',
      category: 'http-headers',
      name: 'Cross-Origin-Opener-Policy (COOP)',
      status: 'info',
      severity: 'info',
      observed: 'ヘッダー未設定',
      description:
        'Cross-Origin-Opener-Policy (COOP) が設定されていません。閲覧コンテキストを他から分離することで、Spectre などのサイドチャネル攻撃やクロスオリジンの情報漏洩リスクを低減できます。',
      recommendation:
        '同一オリジン間の分離を行う場合は same-origin、ポップアップ連携が必要な場合は same-origin-allow-popups の設定を検討してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy'],
      scope: url,
    });
  } else {
    const coopMain = coop.split(';')[0].trim();
    if (!validCoopValues.has(coopMain)) {
      results.push({
        checkId: 'SEC-COOP-01',
        category: 'http-headers',
        name: 'Cross-Origin-Opener-Policy (COOP)',
        status: 'info',
        severity: 'info',
        observed: coop,
        description:
          coopMain === 'unsafe-none'
            ? 'Cross-Origin-Opener-Policy (COOP) に unsafe-none が指定されています。クロスオリジンからの同一コンテキストでのポップアップ操作やプロセス共有が許可されます。'
            : `Cross-Origin-Opener-Policy (COOP) に仕様外または無効な値（${coopMain}）が指定されています。ブラウザはこれを無視し、既定の unsafe-none として扱います。`,
        recommendation:
          '同一オリジン間の分離を行う場合は same-origin、ポップアップ連携が必要な場合は same-origin-allow-popups の設定を検討してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy'],
        scope: url,
      });
    }
  }

  // COEP (Cross-Origin-Embedder-Policy) - 既定では推奨せず、値の誤りだけ指摘
  const coep = getHeader('cross-origin-embedder-policy');
  if (coep) {
    const coepMain = coep.split(';')[0].trim();
    const validCoepValues = new Set(['require-corp', 'credentialless', 'unsafe-none']);
    if (!validCoepValues.has(coepMain)) {
      results.push({
        checkId: 'SEC-COEP-01',
        category: 'http-headers',
        name: 'Cross-Origin-Embedder-Policy (COEP)',
        status: 'info',
        severity: 'info',
        observed: coep,
        description: `Cross-Origin-Embedder-Policy (COEP) に仕様で定義されていない値（${coepMain}）が指定されています。`,
        recommendation:
          '値を require-corp または credentialless に修正するか、COEP を使用しない場合はヘッダーを削除してください（COEP の安易な設定は外部リソースの読み込みを阻害する可能性があります）。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy'],
        scope: url,
      });
    }
  }

  // CORP (Cross-Origin-Resource-Policy) - 引数を持たず case-sensitive
  const corp = getHeader('cross-origin-resource-policy');
  if (corp) {
    const corpTrimmed = corp.trim();
    const validCorpValues = new Set(['same-origin', 'same-site', 'cross-origin']);
    if (!validCorpValues.has(corpTrimmed)) {
      results.push({
        checkId: 'SEC-CORP-01',
        category: 'http-headers',
        name: 'Cross-Origin-Resource-Policy (CORP)',
        status: 'info',
        severity: 'info',
        observed: corp,
        description: `Cross-Origin-Resource-Policy (CORP) に仕様で定義されていない値（${corpTrimmed}）が指定されています。`,
        recommendation:
          'リソースの公開範囲に応じて same-origin、same-site、または cross-origin を正確に指定するか、不要な場合はヘッダーを削除してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy'],
        scope: url,
      });
    }
  }

  // X-XSS-Protection - 1 または 1; mode=block（旧式）
  const xxss = getHeader('x-xss-protection');
  if (xxss) {
    const xxssMain = xxss.split(';')[0].trim();
    if (xxssMain === '1') {
      results.push({
        checkId: 'SEC-XXSS-01',
        category: 'http-headers',
        name: 'X-XSS-Protection',
        status: 'info',
        severity: 'info',
        observed: xxss,
        description: `X-XSS-Protection ヘッダーが有効（${xxss}）に設定されています。このヘッダーは古いブラウザ向けのものであり、モダンブラウザでは非推奨・無効化されているほか、誤検知による脆弱性の誘発リスクも報告されています。`,
        recommendation: 'このヘッダーを削除するか 0 に設定し、XSS 対策には Content-Security-Policy (CSP) を利用してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/X-XSS-Protection'],
        scope: url,
      });
    }
  }

  // --- 8. 情報露出 (Server, X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version, Server-Timing) ---
  const server = getHeader('server');
  const xPoweredBy = getHeader('x-powered-by');
  const xAspNetVersion = getHeader('x-aspnet-version');
  const xAspNetMvcVersion = getHeader('x-aspnetmvc-version');
  const serverTiming = getHeader('server-timing');

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

  if (xAspNetMvcVersion) {
    results.push({
      checkId: 'SEC-DISC-04',
      category: 'information-disclosure',
      name: 'バックエンド技術情報露出 (X-AspNetMvc-Version)',
      status: 'warning',
      severity: 'low',
      observed: `X-AspNetMvc-Version: ${xAspNetMvcVersion}`,
      description:
        `ASP.NET MVC のバージョン情報（${xAspNetMvcVersion}）が公開されています。攻撃者に内部構成やフレームワーク世代のヒントを与えてしまいます。`,
      recommendation:
        'MvcHandler.DisableMvcResponseHeader = true などの設定により X-AspNetMvc-Version ヘッダーを非表示にすることを推奨します。',
      referenceUrls: ['https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'],
      scope: url,
    });
  }

  if (serverTiming) {
    results.push({
      checkId: 'SEC-DISC-05',
      category: 'information-disclosure',
      name: '内部処理情報の露出 (Server-Timing)',
      status: 'info',
      severity: 'info',
      observed: `Server-Timing: ${serverTiming}`,
      description:
        'Server-Timing ヘッダーにより、サーバー内部の処理時間やコンポーネント名が外部に公開されています。パフォーマンス計測に有用ですが、内部構成やボトルネックのヒントとなる可能性があります。',
      recommendation:
        '本番環境では内部処理名や詳細メトリクスを出力しないか、認証されたデバッグ用アクセスに限定することを推奨します。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Server-Timing'],
      scope: url,
    });
  }

  return results;
}
