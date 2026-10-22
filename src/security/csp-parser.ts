/**
 * Web Technology & Security Inspector
 * Content Security Policy (CSP) ディレクティブ構文解析・診断エンジン (src/security/csp-parser.ts)
 */

import { SecurityCheckResult, SecuritySeverity } from '../shared/types';

/**
 * CSPディレクティブのマップ定義
 * 例: { "default-src": ["'self'"], "script-src": ["'self'", "'unsafe-inline'"] }
 */
export interface CSPDirectiveMap {
  [directiveName: string]: string[];
}

/**
 * CSP診断結果の詳細アイテム
 */
export interface CSPIssue {
  id: string;
  directive: string;
  severity: SecuritySeverity;
  pattern: string;
  description: string;
  recommendation: string;
}

/**
 * CSPヘッダー文字列をディレクティブごとに分解（パース）する
 *
 * @param cspHeaderValue CSPヘッダー値 (セミコロン区切り文字列)
 * @returns CSPDirectiveMap
 */
export function parseCSP(cspHeaderValue: string): CSPDirectiveMap {
  const directives: CSPDirectiveMap = {};
  if (!cspHeaderValue || typeof cspHeaderValue !== 'string') {
    return directives;
  }

  const tokens = cspHeaderValue.split(';');

  for (const token of tokens) {
    const trimmed = token.trim();
    if (!trimmed) continue;

    // 空白文字（スペース、タブ、改行等）でディレクティブ名とソースリストを分割
    const parts = trimmed.split(/\s+/);
    const name = parts[0].toLowerCase();
    const values = parts.slice(1);

    // 既に存在する場合は追加（複数同名ディレクティブの場合は最初の定義が優先されるのがCSP仕様だが、解析用に結合）
    if (directives[name]) {
      directives[name].push(...values);
    } else {
      directives[name] = values;
    }
  }

  return directives;
}

/**
 * 指定ディレクティブの値を取得する。存在しない場合はフォールバック（default-src等）を参照する
 *
 * @param directives パース済みディレクティブマップ
 * @param directiveName 検索対象のディレクティブ名 (例: 'script-src')
 * @param fallbackDirective フォールバック先ディレクティブ名 (例: 'default-src')
 * @returns ソース値の配列、または未指定の場合 null
 */
export function getDirectiveValuesWithFallback(
  directives: CSPDirectiveMap,
  directiveName: string,
  fallbackDirective: string | null = 'default-src'
): { values: string[]; isFallback: boolean } | null {
  const target = directiveName.toLowerCase();
  if (directives[target] && directives[target].length > 0) {
    return { values: directives[target], isFallback: false };
  }

  if (fallbackDirective) {
    const fallback = fallbackDirective.toLowerCase();
    if (directives[fallback] && directives[fallback].length > 0) {
      return { values: directives[fallback], isFallback: true };
    }
  }

  return null;
}

/**
 * パース済みCSPディレクティブを診断し、セキュリティ上の指摘事項一覧を抽出する
 *
 * @param directives パース済みディレクティブマップ
 * @param hasXFrameOptions X-Frame-Optionsヘッダーが設定されているかどうか (frame-ancestors評価の代替確認用)
 * @returns CSPIssue[]
 */
export function evaluateCSPDirectives(
  directives: CSPDirectiveMap,
  hasXFrameOptions: boolean = false
): CSPIssue[] {
  const issues: CSPIssue[] = [];

  // --- 1. script-src (および default-src フォールバック) の検査 ---
  const scriptSources = getDirectiveValuesWithFallback(directives, 'script-src', 'default-src');
  const scriptDirectiveName = scriptSources ? (scriptSources.isFallback ? 'default-src (script-src代替)' : 'script-src') : null;

  if (scriptSources) {
    const vals = scriptSources.values.map((v) => v.toLowerCase().replace(/['"]/g, ''));
    const rawVals = scriptSources.values.map((v) => v.toLowerCase());

    // unsafe-inline チェック
    if (rawVals.includes("'unsafe-inline'") || vals.includes('unsafe-inline')) {
      issues.push({
        id: 'CSP-SCRIPT-UNSAFE-INLINE',
        directive: scriptDirectiveName!,
        severity: 'high',
        pattern: "'unsafe-inline'",
        description: `${scriptDirectiveName} に 'unsafe-inline' が許可されており、インラインスクリプトの実行を許容するためクロスサイトスクリプティング（XSS）防御が無効化されています。`,
        recommendation: "インラインスクリプトを外部化するか、Nonce (例: 'nonce-xxx') または SHA-256 ハッシュ値による個別許可に移行してください。",
      });
    }

    // unsafe-eval チェック
    if (rawVals.includes("'unsafe-eval'") || vals.includes('unsafe-eval')) {
      issues.push({
        id: 'CSP-SCRIPT-UNSAFE-EVAL',
        directive: scriptDirectiveName!,
        severity: 'medium',
        pattern: "'unsafe-eval'",
        description: `${scriptDirectiveName} に 'unsafe-eval' が許可されており、eval() や setTimeout/Function 等による動的な文字列スクリプト実行が許容されています。`,
        recommendation: "動的コード生成に依存するライブラリや実装を見直し、'unsafe-eval' を排除してください。",
      });
    }

    // ワイルドカード (*) チェック
    if (rawVals.includes('*') || vals.includes('*')) {
      issues.push({
        id: 'CSP-SCRIPT-WILDCARD',
        directive: scriptDirectiveName!,
        severity: 'high',
        pattern: '*',
        description: `${scriptDirectiveName} にワイルドカード (*) が指定されており、任意の外部ドメインからのスクリプト読み込みが許可されています。`,
        recommendation: "ワイルドカードを削除し、信頼できるドメイン（オリジン）のみを明示的に指定してください。",
      });
    }

    // data: スキーム チェック
    if (rawVals.includes('data:') || vals.includes('data:')) {
      issues.push({
        id: 'CSP-SCRIPT-DATA-SCHEME',
        directive: scriptDirectiveName!,
        severity: 'high',
        pattern: 'data:',
        description: `${scriptDirectiveName} に 'data:' スキームが許可されており、data:text/javascript 経由でのスクリプトインジェクションが可能です。`,
        recommendation: "スクリプト実行元から 'data:' スキームを削除してください。",
      });
    }
  } else {
    // script-src も default-src も未定義
    issues.push({
      id: 'CSP-SCRIPT-MISSING',
      directive: 'script-src / default-src',
      severity: 'high',
      pattern: '未指定',
      description: 'script-src および default-src が定義されていないため、スクリプトの読み込み元が制限されていません。',
      recommendation: "信頼できるオリジンを指定した script-src または default-src を設定してください。",
    });
  }

  // --- 2. object-src の検査 ---
  const objectSources = getDirectiveValuesWithFallback(directives, 'object-src', 'default-src');
  if (!objectSources) {
    issues.push({
      id: 'CSP-OBJECT-SRC-MISSING',
      directive: 'object-src',
      severity: 'medium',
      pattern: '未指定',
      description: "object-src (および default-src) が未指定です。Flashやプラグインによる悪意あるコンテンツ実行を防止できません。",
      recommendation: "object-src 'none' を明示的に指定してプラグイン実行を完全に無効化してください。",
    });
  } else {
    const rawVals = objectSources.values.map((v) => v.toLowerCase());
    const isNone = rawVals.includes("'none'");
    if (!isNone) {
      issues.push({
        id: 'CSP-OBJECT-SRC-NOT-NONE',
        directive: objectSources.isFallback ? 'default-src (object-src代替)' : 'object-src',
        severity: 'medium',
        pattern: objectSources.values.join(' '),
        description: "object-src に 'none' 以外の値が指定されています。不要なプラグイン実行を制限するために 'none' の指定が強く推奨されます。",
        recommendation: "object-src 'none' を指定してください。",
      });
    }
  }

  // --- 3. frame-ancestors の検査 (default-src にフォールバックしない) ---
  const frameAncestors = directives['frame-ancestors'];
  if (!frameAncestors || frameAncestors.length === 0) {
    issues.push({
      id: 'CSP-FRAME-ANCESTORS-MISSING',
      directive: 'frame-ancestors',
      severity: hasXFrameOptions ? 'low' : 'medium',
      pattern: '未指定',
      description: hasXFrameOptions
        ? 'frame-ancestors ディレクティブが未指定です（X-Frame-Options により基本防御は行われています）。'
        : 'frame-ancestors ディレクティブが未指定であり、X-Frame-Options も無いため、クリックジャッキング攻撃に脆弱です。',
      recommendation: "frame-ancestors 'none' または 'self' を指定して外部サイトでのiframe埋め込みを制御してください。",
    });
  }

  // --- 4. base-uri の検査 (default-src にフォールバックしない) ---
  const baseUri = directives['base-uri'];
  if (!baseUri || baseUri.length === 0) {
    issues.push({
      id: 'CSP-BASE-URI-MISSING',
      directive: 'base-uri',
      severity: 'low',
      pattern: '未指定',
      description: 'base-uri ディレクティブが未指定です。<base> タグの挿入による相対パスの乗っ取り攻撃（Base Manipulation）を防止できません。',
      recommendation: "base-uri 'self' または 'none' を明示的に指定してください。",
    });
  }

  return issues;
}

/**
 * CSPヘッダーの解析と SecurityCheckResult リストへの変換を行う
 *
 * @param cspHeaderValue CSPヘッダー文字列
 * @param url 調査対象URL
 * @param hasXFrameOptions X-Frame-Optionsヘッダーが存在するか
 * @returns SecurityCheckResult[]
 */
export function analyzeCSPHeader(
  cspHeaderValue: string,
  url: string,
  hasXFrameOptions: boolean = false
): SecurityCheckResult[] {
  const directives = parseCSP(cspHeaderValue);
  const issues = evaluateCSPDirectives(directives, hasXFrameOptions);

  if (issues.length === 0) {
    return [
      {
        checkId: 'SEC-CSP-00',
        category: 'http-headers',
        name: 'CSP (Content-Security-Policy)',
        status: 'pass',
        severity: 'info',
        observed: cspHeaderValue,
        description: '主要な危険ディレクティブが制限され、堅牢なCSPポリシーが設定されています。',
        recommendation: '現在のポリシー設定を維持してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/CSP'],
        scope: url,
      },
    ];
  }

  // 重大度の集計 (High > Medium > Low)
  let overallSeverity: SecuritySeverity = 'low';
  if (issues.some((i) => i.severity === 'high')) {
    overallSeverity = 'high';
  } else if (issues.some((i) => i.severity === 'medium')) {
    overallSeverity = 'medium';
  }

  const issueDescriptions = issues.map((i) => `・[${i.directive}] ${i.description}`).join('\n');
  const recommendations = Array.from(new Set(issues.map((i) => i.recommendation))).join(' ');

  return [
    {
      checkId: 'SEC-CSP-03',
      category: 'http-headers',
      name: 'CSP (Content-Security-Policy)',
      status: 'warning',
      severity: overallSeverity,
      observed: cspHeaderValue,
      description: `CSPヘッダーが検出されましたが、以下のディレクティブ設定に注意・改善点があります:\n${issueDescriptions}`,
      recommendation: recommendations,
      referenceUrls: [
        'https://developer.mozilla.org/ja/docs/Web/HTTP/CSP',
        'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html',
      ],
      scope: url,
    },
  ];
}
