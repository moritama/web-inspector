/**
 * Web Technology & Security Inspector
 * Content Security Policy (CSP) ディレクティブ構文解析・実効性評価エンジン (src/security/csp-parser.ts) - IMP-05 (Rev.2.1)
 * 
 * - 複数CSPポリシーの独立保持（ヘッダー複数、meta CSPの独立管理）
 * - meta CSP における無効ディレクティブ (frame-ancestors, sandbox, report-uri 等) の判定
 * - ディレクティブフォールバックチェーン (elem/attr -> script-src -> default-src)
 * - nonce/hash/strict-dynamic による unsafe-inline 実効的無効化の考慮
 * - 重複ディレクティブのブラウザ仕様準拠評価（初回定義優先）
 * - 安定ID (FindingIdentity) の付与
 */

import { generateFindingIdFromCheck } from '../shared/identity';
import {
  CSPPolicy,
  CSPSource,
  CspExtrasContext,
  SecurityCheckResult,
  SecuritySeverity,
} from '../shared/types';
import { evaluateCspExtraIssues } from './csp-extras';

/**
 * CSPディレクティブのマップ定義
 */
export interface CSPDirectiveMap {
  [directiveName: string]: string[];
}

/**
 * 単一ポリシー内の診断指摘事項
 */
export interface CSPIssue {
  id: string;
  policyId?: string;
  directive: string;
  severity: SecuritySeverity;
  pattern: string;
  description: string;
  recommendation: string;
}

/**
 * 単一のCSP文字列をパースし、CSPPolicy オブジェクトを生成する (IMP-05 / 4.2)
 *
 * @param rawCsp CSP文字列
 * @param source 取得元 ('response-header' | 'meta')
 * @param mode 適用モード ('enforce' | 'report-only')
 * @returns CSPPolicy
 */
export function parseCSPPolicy(
  rawCsp: string,
  source: CSPSource = 'response-header',
  mode: 'enforce' | 'report-only' = 'enforce'
): CSPPolicy {
  const directives: Record<string, string[]> = {};
  const warnings: string[] = [];
  const id = `csp_${source}_${mode}_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

  if (!rawCsp || typeof rawCsp !== 'string') {
    return {
      id,
      source,
      mode,
      directives,
      rawValue: rawCsp || '',
      warnings,
      observedAt: new Date().toISOString(),
    };
  }

  const tokens = rawCsp.split(';');

  for (const token of tokens) {
    const trimmed = token.trim();
    if (!trimmed) continue;

    const parts = trimmed.split(/\s+/);
    const name = parts[0].toLowerCase();
    const values = parts.slice(1);

    // ブラウザ仕様準拠: 同一ポリシー内で重複するディレクティブは最初の定義が優先され、後続は無視される
    if (directives[name]) {
      warnings.push(`ディレクティブ '${name}' が重複定義されています。ブラウザ仕様に従い最初の定義が優先されます。`);
    } else {
      directives[name] = values;
    }
  }

  return {
    id,
    source,
    mode,
    directives,
    rawValue: rawCsp,
    warnings,
    observedAt: new Date().toISOString(),
  };
}

/**
 * CSPヘッダー値（単一文字列または文字列配列）を配列要素ごと・カンマ区切りごとに分割し、
 * 個別の CSPPolicy オブジェクト配列を生成する (v1.7.0 T06 / SPEC-07)
 *
 * @param headerValues CSPヘッダー値または配列
 * @param source 取得元 ('response-header' | 'meta')
 * @param mode 適用モード ('enforce' | 'report-only')
 * @returns CSPPolicy[]
 */
export function parseCSPHeaderValues(
  headerValues: string | string[] | undefined | null,
  source: CSPSource = 'response-header',
  mode: 'enforce' | 'report-only' = 'enforce'
): CSPPolicy[] {
  if (!headerValues) return [];
  const rawList = Array.isArray(headerValues) ? headerValues : [headerValues];
  const policies: CSPPolicy[] = [];

  for (const rawItem of rawList) {
    if (!rawItem || typeof rawItem !== 'string') continue;
    const parts = rawItem.split(',');
    for (const part of parts) {
      const trimmed = part.trim();
      if (!trimmed) continue;
      policies.push(parseCSPPolicy(trimmed, source, mode));
    }
  }

  return policies;
}

/**
 * 後方互換用パース関数
 */
export function parseCSP(cspHeaderValue: string): CSPDirectiveMap {
  const policy = parseCSPPolicy(cspHeaderValue, 'response-header', 'enforce');
  return policy.directives;
}

/**
 * フォールバックチェーンに従ってディレクティブの値を取得する (IMP-05 / 4.4)
 */
export function getDirectiveValuesWithFallback(
  directives: CSPDirectiveMap,
  directiveName: string,
  fallbackChain: string[] = ['default-src']
): { values: string[]; effectiveDirective: string; isFallback: boolean } | null {
  const target = directiveName.toLowerCase();
  if (directives[target] && directives[target].length > 0) {
    return { values: directives[target], effectiveDirective: target, isFallback: false };
  }

  for (const fallback of fallbackChain) {
    const fb = fallback.toLowerCase();
    if (directives[fb] && directives[fb].length > 0) {
      return { values: directives[fb], effectiveDirective: fb, isFallback: true };
    }
  }

  return null;
}

/**
 * トークンが nonce-* または sha256/384/512-* であるか判定する
 */
function isNonceOrHashToken(token: string): boolean {
  const clean = token.toLowerCase().replace(/^['"]|['"]$/g, '');
  return (
    clean.startsWith('nonce-') ||
    clean.startsWith('sha256-') ||
    clean.startsWith('sha384-') ||
    clean.startsWith('sha512-')
  );
}

/**
 * トークンが広範な任意ホスト許可（*, https:, http:, https://* 等）であるか判定する (SPEC-08)
 */
function isBroadWildcardToken(token: string): boolean {
  const clean = token.toLowerCase().replace(/^['"]|['"]$/g, '');
  if (clean === '*' || clean === 'https:' || clean === 'http:') {
    return true;
  }
  if (/^(?:https?|wss?|\*):\/\/\*(?::(?:\d+|\*))?(?:\/.*)?$/i.test(clean)) {
    return true;
  }
  return false;
}

/**
 * トークンがサブドメインワイルドカード（*.example.com, https://*.cdn.example 等）であるか判定する (SPEC-08)
 */
function isSubdomainWildcardToken(token: string): boolean {
  const clean = token.toLowerCase().replace(/^['"]|['"]$/g, '');
  if (isBroadWildcardToken(clean)) return false;
  return /^(?:(?:https?|wss?|\*):\/\/)?\*\.[^/\s*]+/i.test(clean);
}

/**
 * 単一ポリシーの能力（Capability）プロファイル (v1.7.0 T06 / SPEC-07, SPEC-08)
 */
interface PolicyCapabilities {
  /** script-src および default-src が未指定か */
  scriptMissing: boolean;
  /** インラインスクリプト実行を許可しているか */
  allowsInline: boolean;
  /** eval() 等の動的コード実行を許可しているか */
  allowsEval: boolean;
  /** 任意ホストからのスクリプト読込許可レベル ('none' | 'subdomain' | 'broad' | 'unrestricted') */
  wildcardLevel: 'none' | 'subdomain' | 'broad' | 'unrestricted';
  /** data: スキームによるスクリプト読込を許可しているか */
  allowsDataScheme: boolean;
  /** style-src (または代替 default-src) で unsafe-inline を許可しているか */
  allowsStyleInline: boolean;
  /** object-src (または代替 default-src) の状態 ('none' = 遮断, 'not-none' = 'none'以外, 'missing' = 未指定) */
  objectSrcState: 'none' | 'not-none' | 'missing';
  /** base-uri が未指定（未制限）か */
  allowsBaseUri: boolean;
  /** frame-ancestors が実効的に未指定（meta由来は無効なため true）か */
  allowsFrameAncestors: boolean;
}

/**
 * 単一ポリシーの能力プロファイルを計算する (v1.7.0 T06 / SPEC-07, SPEC-08 / v1.7.1 T10)
 */
function analyzePolicyCapabilities(policy: CSPPolicy): PolicyCapabilities {
  const { directives, source } = policy;

  // 1. スクリプト関連能力 (インライン実行、eval、任意ホストからのスクリプト)
  const scriptSources = getDirectiveValuesWithFallback(directives, 'script-src', ['default-src']);
  let scriptMissing = false;
  let allowsInline = false;
  let allowsEval = false;
  let wildcardLevel: 'none' | 'subdomain' | 'broad' | 'unrestricted' = 'none';
  let allowsDataScheme = false;

  if (!scriptSources) {
    scriptMissing = true;
    allowsInline = true;
    allowsEval = true;
    wildcardLevel = 'unrestricted';
    allowsDataScheme = true;
  } else {
    const rawVals = scriptSources.values.map((v) => v.toLowerCase());
    const cleanVals = scriptSources.values.map((v) => v.toLowerCase().replace(/^['"]|['"]$/g, ''));

    const hasNonceOrHash = rawVals.some((v) => isNonceOrHashToken(v));
    const hasStrictDynamic = cleanVals.includes('strict-dynamic');
    const hasUnsafeInline = cleanVals.includes('unsafe-inline');
    const hasUnsafeEval = cleanVals.includes('unsafe-eval');
    const hasData = cleanVals.includes('data:');
    const hasBroadWildcard = scriptSources.values.some((v) => isBroadWildcardToken(v));
    const hasSubdomainWildcard = scriptSources.values.some((v) => isSubdomainWildcardToken(v));

    // nonce/hash または strict-dynamic があれば unsafe-inline は無視される
    const inlineIgnored = hasNonceOrHash || hasStrictDynamic;
    allowsInline = hasUnsafeInline && !inlineIgnored;

    // unsafe-eval は strict-dynamic 等では無視されない
    allowsEval = hasUnsafeEval;

    // nonce/hash + strict-dynamic (または strict-dynamic) があればホスト許可・スキーム許可は無視される
    const hostIgnored = hasStrictDynamic && hasNonceOrHash ? true : hasStrictDynamic;
    if (!hostIgnored) {
      if (hasBroadWildcard) {
        wildcardLevel = 'broad';
      } else if (hasSubdomainWildcard) {
        wildcardLevel = 'subdomain';
      }
      allowsDataScheme = hasData;
    }
  }

  // 1.5. style-src 能力
  const styleSources = getDirectiveValuesWithFallback(directives, 'style-src', ['default-src']);
  let allowsStyleInline = false;
  if (!styleSources) {
    allowsStyleInline = true;
  } else {
    const rawStyleVals = styleSources.values.map((v) => v.toLowerCase());
    const cleanStyleVals = styleSources.values.map((v) =>
      v.toLowerCase().replace(/^['"]|['"]$/g, '')
    );
    const hasStyleNonceOrHash = rawStyleVals.some((v) => isNonceOrHashToken(v));
    const hasStyleUnsafeInline = cleanStyleVals.includes('unsafe-inline');
    allowsStyleInline = hasStyleUnsafeInline && !hasStyleNonceOrHash;
  }

  // 2. object-src 能力
  const objectSources = getDirectiveValuesWithFallback(directives, 'object-src', ['default-src']);
  let objectSrcState: 'none' | 'not-none' | 'missing' = 'missing';
  if (objectSources) {
    const cleanObjVals = objectSources.values.map((v) => v.toLowerCase().replace(/^['"]|['"]$/g, ''));
    objectSrcState = cleanObjVals.includes('none') ? 'none' : 'not-none';
  }

  // 3. base-uri 能力 (default-src にフォールバックしない)
  const baseUri = directives['base-uri'];
  const allowsBaseUri = !baseUri || baseUri.length === 0;

  // 4. frame-ancestors 能力 (default-src にフォールバックしない。meta 要素では無効)
  const frameAncestors = directives['frame-ancestors'];
  const allowsFrameAncestors =
    source === 'meta' || !frameAncestors || frameAncestors.length === 0;

  return {
    scriptMissing,
    allowsInline,
    allowsEval,
    wildcardLevel,
    allowsDataScheme,
    allowsStyleInline,
    objectSrcState,
    allowsBaseUri,
    allowsFrameAncestors,
  };
}

/**
 * 単一のCSPPolicyを診断し、セキュリティ指摘事項を抽出する (IMP-05 / v1.7.0 T06 / v1.7.1 T10)
 */
export function evaluateSinglePolicy(
  policy: CSPPolicy,
  hasXFrameOptions: boolean = false
): CSPIssue[] {
  const issues: CSPIssue[] = [];
  const { directives, source, mode, id: policyId } = policy;

  // --- 0. meta 要素の Report-Only は仕様上ブラウザに無視される無効な指定 (SPEC-07) ---
  if (source === 'meta' && mode === 'report-only') {
    issues.push({
      id: 'CSP-META-REPORT-ONLY-IGNORED',
      policyId,
      directive: 'http-equiv="Content-Security-Policy-Report-Only"',
      severity: 'info',
      pattern: 'meta report-only',
      description:
        'meta 要素での Content-Security-Policy-Report-Only はブラウザ仕様上無視される無効な指定です。',
      recommendation:
        'Report-Only ポリシーを使用する場合は、HTTP レスポンスヘッダーとして送信してください。',
    });
    return issues;
  }

  // --- 1. meta CSP の制限チェック (IMP-05 / 4.3) ---
  if (source === 'meta') {
    // metaタグでは frame-ancestors, sandbox, report-uri, report-to は無効
    const invalidDirectives = ['frame-ancestors', 'sandbox', 'report-uri', 'report-to'];
    for (const invalid of invalidDirectives) {
      if (directives[invalid]) {
        issues.push({
          id: `CSP-META-INVALID-${invalid.toUpperCase()}`,
          policyId,
          directive: invalid,
          severity: 'medium',
          pattern: invalid,
          description: `meta CSP では '${invalid}' ディレクティブはブラウザのセキュリティ仕様上適用されず、無効化されます。HTTPレスポンスヘッダーで設定してください。`,
          recommendation: `対象ディレクティブ ('${invalid}') をWebサーバーのHTTPレスポンスヘッダー経由で送信してください。`,
        });
      }
    }
  }

  // --- 2. script-src (およびフォールバック) の実効性診断 (IMP-05 / 4.4 & 4.5 / SPEC-08 / v1.7.1 T10: 最大 MEDIUM) ---
  const scriptSources = getDirectiveValuesWithFallback(directives, 'script-src', ['default-src']);
  const scriptDirName = scriptSources
    ? scriptSources.isFallback
      ? 'default-src (script-src代替)'
      : 'script-src'
    : null;

  if (scriptSources) {
    const rawVals = scriptSources.values.map((v) => v.toLowerCase());
    const cleanVals = scriptSources.values.map((v) => v.toLowerCase().replace(/^['"]|['"]$/g, ''));

    // nonce や ハッシュの存在確認
    const hasNonceOrHash = rawVals.some((v) => isNonceOrHashToken(v));
    const hasStrictDynamic = cleanVals.includes('strict-dynamic');
    const hasUnsafeInline = cleanVals.includes('unsafe-inline');
    const hasUnsafeEval = cleanVals.includes('unsafe-eval');
    const hasData = cleanVals.includes('data:');
    const broadWildcards = scriptSources.values.filter((v) => isBroadWildcardToken(v));
    const subdomainWildcards = scriptSources.values.filter((v) => isSubdomainWildcardToken(v));

    // strict-dynamic の評価 (4.5)
    if (hasStrictDynamic) {
      issues.push({
        id: 'CSP-SCRIPT-STRICT-DYNAMIC-NOTE',
        policyId,
        directive: scriptDirName!,
        severity: 'info',
        pattern: "'strict-dynamic'",
        description: `${scriptDirName} に 'strict-dynamic' が指定されています。モダンブラウザではホスト名ホワイトリストが無効化され、nonceから生成されたスクリプトのみが実効的に許可されます。`,
        recommendation:
          '最新のブラウザ仕様に準拠した堅牢な設定です。レガシーブラウザ向けのフォールバックを確認してください。',
      });
    }

    // unsafe-inline の実効性評価 (4.5 / SPEC-08 / v1.7.1 T10)
    if (hasUnsafeInline) {
      if (hasNonceOrHash || hasStrictDynamic) {
        // nonce/hashまたはstrict-dynamicが存在する場合、モダンブラウザではunsafe-inlineは実効的に無視される
        issues.push({
          id: 'CSP-SCRIPT-UNSAFE-INLINE',
          policyId,
          directive: scriptDirName!,
          severity: 'info',
          pattern: "'unsafe-inline'",
          description: `${scriptDirName} に 'unsafe-inline' が含まれていますが、Nonceまたはハッシュが設定されているためモダンブラウザでは実効的に無視（無効化）されています（レガシー互換用）。`,
          recommendation:
            "古いブラウザのサポートが不要であれば、設定の明確化のため 'unsafe-inline' の削除を検討してください。",
        });
      } else {
        // nonce/hashなしでunsafe-inlineがある場合 -> XSSリスク (T10 E1: 最大 MEDIUM)
        issues.push({
          id: 'CSP-SCRIPT-UNSAFE-INLINE',
          policyId,
          directive: scriptDirName!,
          severity: mode === 'report-only' ? 'low' : 'medium',
          pattern: "'unsafe-inline'",
          description: `${scriptDirName} に 'unsafe-inline' が許可されており、Nonceやハッシュによる制限もないため、インラインスクリプト実行（XSS）を防御できません。`,
          recommendation:
            "インラインスクリプトを外部化するか、Nonce ('nonce-xxx') または SHA-256 ハッシュ値による個別許可に移行してください。",
        });
      }
    }

    // unsafe-eval
    if (hasUnsafeEval) {
      issues.push({
        id: 'CSP-SCRIPT-UNSAFE-EVAL',
        policyId,
        directive: scriptDirName!,
        severity: mode === 'report-only' ? 'low' : 'medium',
        pattern: "'unsafe-eval'",
        description: `${scriptDirName} に 'unsafe-eval' が許可されており、eval() や動的文字列スクリプト実行が許容されています。`,
        recommendation:
          "動的コード生成に依存するライブラリを見直し、'unsafe-eval' を排除してください。",
      });
    }

    // nonce/hash + strict-dynamic (または strict-dynamic) が存在する場合はホスト許可が無視される (SPEC-08)
    const hostIgnored = hasStrictDynamic && hasNonceOrHash ? true : hasStrictDynamic;

    if (!hostIgnored) {
      // 任意ホスト許可: *, https:, http:, *.example.com は medium (v1.7.1 T10 E1)
      if (broadWildcards.length > 0) {
        issues.push({
          id: 'CSP-SCRIPT-WILDCARD',
          policyId,
          directive: scriptDirName!,
          severity: mode === 'report-only' ? 'low' : 'medium',
          pattern: broadWildcards.join(' '),
          description: `${scriptDirName} に広範なホストまたはスキーム (${broadWildcards.join(', ')}) が指定されており、任意の外部ドメインからのスクリプト読み込みが許可されています。`,
          recommendation:
            'ワイルドカードやスキーム全体の許可を削除し、信頼できる特定のオリジンのみを明示的に指定してください。',
        });
      } else if (subdomainWildcards.length > 0) {
        issues.push({
          id: 'CSP-SCRIPT-WILDCARD',
          policyId,
          directive: scriptDirName!,
          severity: mode === 'report-only' ? 'low' : 'medium',
          pattern: subdomainWildcards.join(' '),
          description: `${scriptDirName} にサブドメインワイルドカード (${subdomainWildcards.join(', ')}) が指定されており、任意のサブドメインからのスクリプト読み込みが許可されています。`,
          recommendation:
            'サブドメイン全体のワイルドカードを避け、使用する特定のサブドメイン（ホスト名）を明示的に指定してください。',
        });
      }

      // data: スキーム
      if (hasData) {
        issues.push({
          id: 'CSP-SCRIPT-DATA-SCHEME',
          policyId,
          directive: scriptDirName!,
          severity: mode === 'report-only' ? 'low' : 'medium',
          pattern: 'data:',
          description: `${scriptDirName} に 'data:' スキームが許可されており、data:text/javascript 経由でのインジェクションが可能です。`,
          recommendation: "スクリプト実行元から 'data:' スキームを削除してください。",
        });
      }
    }
  } else {
    // script-src も default-src も未定義 (v1.7.1 T10 E1: MEDIUM)
    issues.push({
      id: 'CSP-SCRIPT-MISSING',
      policyId,
      directive: 'script-src / default-src',
      severity: mode === 'report-only' ? 'low' : 'medium',
      pattern: '未指定',
      description:
        'script-src および default-src が定義されていないため、スクリプトの読み込み元が制限されていません。',
      recommendation: '信頼できるオリジンを指定した script-src または default-src を設定してください。',
    });
  }

  // --- 2.5. style-src の unsafe-inline 検査 (v1.7.1 T10: style だけの unsafe-inline は INFO) ---
  const styleSources = getDirectiveValuesWithFallback(directives, 'style-src', ['default-src']);
  if (styleSources && (!styleSources.isFallback || Boolean(directives['script-src']?.length))) {
    const rawStyleVals = styleSources.values.map((v) => v.toLowerCase());
    const cleanStyleVals = styleSources.values.map((v) =>
      v.toLowerCase().replace(/^['"]|['"]$/g, '')
    );
    const hasStyleNonceOrHash = rawStyleVals.some((v) => isNonceOrHashToken(v));
    const hasStyleUnsafeInline = cleanStyleVals.includes('unsafe-inline');
    if (hasStyleUnsafeInline && !hasStyleNonceOrHash) {
      const styleDirName = styleSources.isFallback
        ? 'default-src (style-src代替)'
        : 'style-src';
      issues.push({
        id: 'CSP-STYLE-UNSAFE-INLINE',
        policyId,
        directive: styleDirName,
        severity: 'info',
        pattern: "'unsafe-inline'",
        description: `${styleDirName} に 'unsafe-inline' が指定されています（スタイルのインライン適用のみ許可）。`,
        recommendation:
          'インラインスタイルの制限が必要な場合は、外部CSSへの分離または Nonce の利用を検討してください。',
      });
    }
  }

  // --- 3. object-src の検査 (IMP-05 / 4.7 & P18 / v1.7.1 T10: LOW) ---
  const objectSources = getDirectiveValuesWithFallback(directives, 'object-src', ['default-src']);
  if (!objectSources) {
    issues.push({
      id: 'CSP-OBJECT-SRC-MISSING',
      policyId,
      directive: 'object-src',
      severity: 'low',
      pattern: '未指定',
      description:
        'object-src (および default-src) が未指定です。Flashやプラグインによるスクリプト実行を制限できません。',
      recommendation: "object-src 'none' を指定してプラグイン実行を完全に無効化してください。",
    });
  } else {
    const rawVals = objectSources.values.map((v) => v.toLowerCase().replace(/^['"]|['"]$/g, ''));
    const isNone = rawVals.includes('none');
    if (!isNone) {
      issues.push({
        id: 'CSP-OBJECT-SRC-NOT-NONE',
        policyId,
        directive: objectSources.effectiveDirective,
        severity: 'low',
        pattern: objectSources.values.join(' '),
        description:
          "object-src に 'none' 以外の値が指定されています。不要なプラグイン実行を制限するために 'none' の指定が強く推奨されます。",
        recommendation: "object-src 'none' を指定してください。",
      });
    }
  }

  // --- 4. frame-ancestors の検査 (default-src にフォールバックしない) ---
  if (source !== 'meta') {
    const frameAncestors = directives['frame-ancestors'];
    if (!frameAncestors || frameAncestors.length === 0) {
      issues.push({
        id: 'CSP-FRAME-ANCESTORS-MISSING',
        policyId,
        directive: 'frame-ancestors',
        severity: hasXFrameOptions ? 'info' : 'low',
        pattern: '未指定',
        description: hasXFrameOptions
          ? 'frame-ancestors ディレクティブが未指定です（X-Frame-Options により代替防御されています）。'
          : 'frame-ancestors ディレクティブが未指定であり、X-Frame-Options も無いため、クリックジャッキング攻撃に脆弱です。',
        recommendation: "frame-ancestors 'none' または 'self' を設定してください。",
      });
    }
  }

  // --- 5. base-uri の検査 (default-src にフォールバックしない / v1.7.1 T10: LOW) ---
  const baseUri = directives['base-uri'];
  if (!baseUri || baseUri.length === 0) {
    issues.push({
      id: 'CSP-BASE-URI-MISSING',
      policyId,
      directive: 'base-uri',
      severity: 'low',
      pattern: '未指定',
      description:
        'base-uri ディレクティブが未指定です。<base> タグの挿入による相対URL改変攻撃（Base Manipulation）を防止できません。',
      recommendation: "base-uri 'self' または 'none' を明示的に指定してください。",
    });
  }

  return issues;
}

/**
 * 後方互換用ディレクティブ診断関数
 */
export function evaluateCSPDirectives(
  directives: CSPDirectiveMap,
  hasXFrameOptions: boolean = false
): CSPIssue[] {
  const dummyPolicy: CSPPolicy = {
    id: 'csp_legacy',
    source: 'response-header',
    mode: 'enforce',
    directives,
    rawValue: '',
    warnings: [],
    observedAt: new Date().toISOString(),
  };
  return evaluateSinglePolicy(dummyPolicy, hasXFrameOptions);
}

/**
 * wildcardLevel を数値ランクに変換する（積集合での最小許可範囲算出用）
 */
function getWildcardRank(level: PolicyCapabilities['wildcardLevel']): number {
  switch (level) {
    case 'none':
      return 0;
    case 'subdomain':
      return 1;
    case 'broad':
      return 2;
    case 'unrestricted':
      return 3;
  }
}

/**
 * 強制ポリシー群の能力（Capability）積集合（AND）に基づいて、
 * 他の強制ポリシーによって遮断（防御）されている能力の指摘事項を除外・調整する (v1.7.0 T06 / SPEC-07 / v1.7.1 T10)
 */
function filterEnforceIssuesByIntersection(
  enforcePolicies: CSPPolicy[],
  rawEnforceIssues: CSPIssue[],
  deduplicate: boolean = true
): CSPIssue[] {
  if (enforcePolicies.length <= 1) {
    return rawEnforceIssues;
  }

  const caps = enforcePolicies.map((p) => analyzePolicyCapabilities(p));

  // 各能力の積集合（すべての強制ポリシーが許可したものだけが通る＝1つでもブロックしていれば防御されている）
  const effectiveScriptMissing = caps.every((c) => c.scriptMissing);
  const effectiveAllowsInline = caps.every((c) => c.allowsInline);
  const effectiveAllowsEval = caps.every((c) => c.allowsEval);
  const effectiveAllowsData = caps.every((c) => c.allowsDataScheme);
  const effectiveWildcardRank = Math.min(...caps.map((c) => getWildcardRank(c.wildcardLevel)));
  const effectiveAllowsStyleInline = caps.every((c) => c.allowsStyleInline);
  const effectiveAllowsObject = caps.every((c) => c.objectSrcState !== 'none');
  const allObjectMissing = caps.every((c) => c.objectSrcState === 'missing');
  const effectiveAllowsBaseUri = caps.every((c) => c.allowsBaseUri);
  const effectiveAllowsFrameAncestors = caps.every((c) => c.allowsFrameAncestors);

  const filtered: CSPIssue[] = [];
  const seenIssueIds = new Set<string>();

  for (const issue of rawEnforceIssues) {
    switch (issue.id) {
      case 'CSP-SCRIPT-MISSING':
        if (!effectiveScriptMissing) continue;
        break;
      case 'CSP-SCRIPT-UNSAFE-INLINE':
        // info 注記（同一ポリシー内で nonce/hash により無視されている旨の注記）は維持
        if (issue.severity !== 'info' && !effectiveAllowsInline) continue;
        break;
      case 'CSP-SCRIPT-UNSAFE-EVAL':
        if (!effectiveAllowsEval) continue;
        break;
      case 'CSP-SCRIPT-DATA-SCHEME':
        if (!effectiveAllowsData) continue;
        break;
      case 'CSP-SCRIPT-WILDCARD':
        if (effectiveWildcardRank === 0) continue;
        if (
          deduplicate &&
          effectiveWildcardRank === 1 &&
          issue.pattern.split(/\s+/).some((t) => isBroadWildcardToken(t))
        ) {
          continue;
        }
        break;
      case 'CSP-STYLE-UNSAFE-INLINE':
        if (!effectiveAllowsStyleInline) continue;
        break;
      case 'CSP-OBJECT-SRC-MISSING':
        if (!effectiveAllowsObject || !allObjectMissing) continue;
        break;
      case 'CSP-OBJECT-SRC-NOT-NONE':
        if (!effectiveAllowsObject) continue;
        break;
      case 'CSP-BASE-URI-MISSING':
        if (!effectiveAllowsBaseUri) continue;
        break;
      case 'CSP-FRAME-ANCESTORS-MISSING':
        if (!effectiveAllowsFrameAncestors) continue;
        break;
      default:
        break;
    }

    if (deduplicate) {
      // 複数ポリシー間で同一の指摘ID（かつ同一severity）が重複する場合は1件に集約
      const dedupKey = `${issue.id}:${issue.severity}`;
      if (seenIssueIds.has(dedupKey)) {
        continue;
      }
      seenIssueIds.add(dedupKey);
    }
    filtered.push(issue);
  }

  return filtered;
}

/**
 * ポリシーオブジェクトの directives が未パースの場合に rawValue から補完する
 */
function ensureParsedPolicy(policy: CSPPolicy): CSPPolicy {
  if (policy.directives && Object.keys(policy.directives).length > 0) {
    return policy;
  }
  const parsed = parseCSPPolicy(policy.rawValue || '', policy.source, policy.mode);
  return {
    ...policy,
    directives: parsed.directives,
    warnings: policy.warnings && policy.warnings.length > 0 ? policy.warnings : parsed.warnings,
  };
}

/**
 * Markdown 第 8 節（CSP 診断）などのポリシー別問題点表示向けに、
 * 複数強制ポリシーの積集合評価を反映した単一ポリシーの指摘リストを返す (v1.7.1 T10 / 指摘 3)
 */
export function evaluatePolicyIssuesWithIntersection(
  policy: CSPPolicy,
  allPolicies: CSPPolicy[],
  hasXFrameOptions: boolean = false,
  extrasContext?: CspExtrasContext
): CSPIssue[] {
  const normalizedTarget = ensureParsedPolicy(policy);
  const rawIssues = evaluateSinglePolicy(normalizedTarget, hasXFrameOptions);

  // strict-dynamic の肯定注記や nonce により実効的に無視されている unsafe-inline 注記、
  // XFO で代替保護されている場合の frame-ancestors 未指定は「問題点」ではないため除外
  const problemCandidates = rawIssues.filter((issue) => {
    if (issue.id === 'CSP-SCRIPT-STRICT-DYNAMIC-NOTE') return false;
    if (issue.id === 'CSP-SCRIPT-UNSAFE-INLINE' && issue.severity === 'info') return false;
    if (issue.id === 'CSP-FRAME-ANCESTORS-MISSING' && issue.severity === 'info') return false;
    return true;
  });

  const extraIssues = extrasContext ? evaluateCspExtraIssues(normalizedTarget, allPolicies, extrasContext) : [];

  if (normalizedTarget.mode !== 'enforce') {
    return [...problemCandidates, ...extraIssues];
  }

  const enforcePolicies = (allPolicies || [])
    .filter((p) => p.mode === 'enforce')
    .map(ensureParsedPolicy);

  return [...filterEnforceIssuesByIntersection(enforcePolicies, problemCandidates, false), ...extraIssues];
}

/**
 * CSP の指摘事項リストから SEC-CSP-03.observed 用の要約文字列を生成する (v1.7.1 T10 / 指摘 3)
 */
export function summarizeCSPIssues(issues: CSPIssue[]): string {
  const labels: string[] = [];
  const severityPriority: Record<string, number> = {
    medium: 0,
    low: 1,
  };

  // medium を low より先に並べつつ、同一重大度内では元の出現順を保つ
  const orderedIssues = issues
    .filter((issue) => issue.severity !== 'info')
    .map((issue, idx) => ({ issue, idx }))
    .sort((a, b) => {
      const pa = severityPriority[a.issue.severity] ?? 2;
      const pb = severityPriority[b.issue.severity] ?? 2;
      return pa !== pb ? pa - pb : a.idx - b.idx;
    })
    .map((entry) => entry.issue);

  for (const issue of orderedIssues) {
    let label: string;
    switch (issue.id) {
      case 'CSP-SCRIPT-MISSING':
        label = 'script-src 未指定';
        break;
      case 'CSP-SCRIPT-UNSAFE-INLINE':
        label = "'unsafe-inline' あり";
        break;
      case 'CSP-SCRIPT-UNSAFE-EVAL':
        label = "'unsafe-eval' あり";
        break;
      case 'CSP-SCRIPT-WILDCARD':
        label = `任意ホスト許可 (${issue.pattern})`;
        break;
      case 'CSP-SCRIPT-DATA-SCHEME':
        label = "'data:' スキーム許可";
        break;
      case 'CSP-OBJECT-SRC-MISSING':
        label = 'object-src 未指定';
        break;
      case 'CSP-OBJECT-SRC-NOT-NONE':
        label = "object-src が 'none' 以外";
        break;
      case 'CSP-BASE-URI-MISSING':
        label = 'base-uri 未指定';
        break;
      case 'CSP-FRAME-ANCESTORS-MISSING':
        label = 'frame-ancestors 未指定';
        break;
      default:
        if (issue.id.startsWith('CSP-META-INVALID-')) {
          label = `meta 無効ディレクティブ (${issue.directive})`;
        } else {
          label = `${issue.directive} (${issue.pattern})`;
        }
        break;
    }

    if (!labels.includes(label)) {
      labels.push(label);
    }
  }

  return labels.join(' / ');
}

/**
 * X-Frame-Options ヘッダー文字列を正規化した意味 ('none' | 'self' | 'other') に変換する
 */
function normalizeXfoMeaning(xfoHeaderValue: string): 'none' | 'self' | 'other' {
  const tokens = xfoHeaderValue
    .split(',')
    .map((t) => t.trim().toUpperCase())
    .filter(Boolean);
  if (tokens.length === 0) return 'other';
  if (tokens.every((t) => t === 'DENY')) return 'none';
  if (tokens.every((t) => t === 'SAMEORIGIN')) return 'self';
  return 'other';
}

/**
 * X-Frame-Options と CSP frame-ancestors の両方が存在し、意味が異なる場合に
 * 「実際に効くのは frame-ancestors」である旨の INFO 注記を生成する (v1.7.1 T10 / 指摘 3)
 */
export function checkXfoAndFrameAncestorsConflict(
  xfoHeaderValue: string | null | undefined,
  policies: CSPPolicy[],
  url: string
): SecurityCheckResult | null {
  const xfoTrimmed = (xfoHeaderValue || '').trim();
  if (!xfoTrimmed) return null;

  const headerFaPolicies = (policies || [])
    .map(ensureParsedPolicy)
    .filter(
      (p) =>
        p.mode === 'enforce' &&
        p.source === 'response-header' &&
        Array.isArray(p.directives['frame-ancestors']) &&
        p.directives['frame-ancestors'].length > 0
    );

  if (headerFaPolicies.length === 0) return null;

  const xfoMeaning = normalizeXfoMeaning(xfoTrimmed);

  // frame-ancestors の実効的な意味を算出（複数ある場合は積集合: 1つでも 'none' なら 'none'）
  const faMeanings = headerFaPolicies.map((p) => {
    const tokens = p.directives['frame-ancestors'].map((t) =>
      t.trim().toLowerCase().replace(/^['"]|['"]$/g, '')
    );
    if (tokens.length === 1 && tokens[0] === 'none') return 'none';
    if (tokens.length === 1 && tokens[0] === 'self') return 'self';
    return 'other';
  });

  let effectiveFaMeaning: 'none' | 'self' | 'other' = 'other';
  if (faMeanings.includes('none')) {
    effectiveFaMeaning = 'none';
  } else if (faMeanings.every((m) => m === 'self')) {
    effectiveFaMeaning = 'self';
  }

  if (xfoMeaning === effectiveFaMeaning && xfoMeaning !== 'other') {
    return null;
  }

  const faDisplay = headerFaPolicies
    .map((p) => p.directives['frame-ancestors'].join(' '))
    .join(', ');

  return {
    checkId: 'SEC-CSP-XFO-CONFLICT',
    category: 'http-headers',
    name: 'CSP (frame-ancestors と X-Frame-Options の優先関係)',
    status: 'info',
    severity: 'info',
    observed: `X-Frame-Options: ${xfoTrimmed} / frame-ancestors: ${faDisplay}（実際に効くのは frame-ancestors）`,
    description: `X-Frame-Options (${xfoTrimmed}) と CSP frame-ancestors (${faDisplay}) の指定内容が異なります。モダンブラウザでは X-Frame-Options は無視され、実際に効くのは frame-ancestors です。`,
    recommendation:
      '意図した埋め込み制限になっているか確認し、不要な混乱を避けるため X-Frame-Options と frame-ancestors の指定を揃えることを検討してください。',
    referenceUrls: [
      'https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors',
      'https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/X-Frame-Options',
    ],
    scope: url,
  };
}

/**
 * 複数のCSPポリシー（ヘッダー複数、meta CSP等）を統合診断する (IMP-05 / 4.6 / v1.7.0 T06 / v1.7.1 T10)
 *
 * @param policies CSPPolicy の配列
 * @param url 対象URL
 * @param hasXFrameOptions X-Frame-Optionsヘッダーが存在するか（またはXFOヘッダー値文字列）
 * @param xfoHeaderValue X-Frame-Optionsヘッダーの生値（frame-ancestorsとの矛盾注記判定用・任意）
 * @returns { policies, issues, results }
 */
export function analyzeCSPPolicies(
  policies: CSPPolicy[],
  url: string,
  hasXFrameOptions: boolean | string = false,
  xfoHeaderValue?: string | null
): {
  policies: CSPPolicy[];
  issues: CSPIssue[];
  results: SecurityCheckResult[];
} {
  const results: SecurityCheckResult[] = [];
  const rawXfoString =
    typeof hasXFrameOptions === 'string' ? hasXFrameOptions : xfoHeaderValue ?? null;
  const hasXfoBool =
    typeof hasXFrameOptions === 'string'
      ? normalizeXfoMeaning(hasXFrameOptions) !== 'other'
      : Boolean(hasXFrameOptions);

  if (!policies || policies.length === 0) {
    results.push({
      checkId: 'SEC-CSP-01',
      category: 'http-headers',
      name: 'CSP (Content-Security-Policy)',
      status: 'warning',
      severity: 'medium',
      observed: 'ポリシー未設定',
      description: 'CSPポリシーが検出されませんでした。クロスサイトスクリプティング（XSS）防御が不足しています。',
      recommendation: '信頼できるリソースのみを読み込むCSPポリシーを設定してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/CSP'],
      scope: url,
    });
    return { policies: [], issues: [], results };
  }

  const normalizedPolicies = policies.map(ensureParsedPolicy);

  // meta 要素の Report-Only（ブラウザは無視する無効な指定）を分離 (SPEC-07)
  const metaReportOnlyPolicies = normalizedPolicies.filter(
    (p) => p.source === 'meta' && p.mode === 'report-only'
  );
  const enforcePolicies = normalizedPolicies.filter((p) => p.mode === 'enforce');
  const reportOnlyPolicies = normalizedPolicies.filter(
    (p) => p.source !== 'meta' && p.mode === 'report-only'
  );

  const rawEnforceIssues: CSPIssue[] = [];
  for (const policy of enforcePolicies) {
    rawEnforceIssues.push(...evaluateSinglePolicy(policy, hasXfoBool));
  }
  const enforceIssues = filterEnforceIssuesByIntersection(enforcePolicies, rawEnforceIssues);

  const reportOnlyIssues: CSPIssue[] = [];
  for (const policy of reportOnlyPolicies) {
    reportOnlyIssues.push(...evaluateSinglePolicy(policy, hasXfoBool));
  }

  const metaReportOnlyIssues: CSPIssue[] = [];
  for (const policy of metaReportOnlyPolicies) {
    metaReportOnlyIssues.push(...evaluateSinglePolicy(policy, hasXfoBool));
  }

  const allIssues: CSPIssue[] = [
    ...enforceIssues,
    ...reportOnlyIssues,
    ...metaReportOnlyIssues,
  ];

  // 有効なポリシー（enforce も header report-only も）が1件もない場合は「未設定」扱い
  if (enforcePolicies.length === 0 && reportOnlyPolicies.length === 0) {
    results.push({
      checkId: 'SEC-CSP-01',
      category: 'http-headers',
      name: 'CSP (Content-Security-Policy)',
      status: 'warning',
      severity: 'medium',
      observed: 'ポリシー未設定',
      description: 'CSPポリシーが検出されませんでした。クロスサイトスクリプティング（XSS）防御が不足しています。',
      recommendation: '信頼できるリソースのみを読み込むCSPポリシーを設定してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/CSP'],
      scope: url,
    });
  }

  // Report-Only（ヘッダー）のみの評価
  if (enforcePolicies.length === 0 && reportOnlyPolicies.length > 0) {
    results.push({
      checkId: 'SEC-CSP-02',
      category: 'http-headers',
      name: 'CSP (Content-Security-Policy)',
      status: 'info',
      severity: 'low',
      observed: `Report-Only設定中 (${reportOnlyPolicies.length} 件)`,
      description: 'CSPはReport-Onlyモードでのみ動作しており、悪意あるスクリプトの実行は遮断されません（レポート収集段階）。',
      recommendation: '動作検証完了後、本番のContent-Security-Policyヘッダーとして適用してください。',
      referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only'],
      scope: url,
    });
  }

  // 強制適用ポリシーの評価（info の注記は指摘の件数に含めず、status を warning にしない: SPEC-08 / v1.7.1 T10）
  if (enforcePolicies.length > 0) {
    const actionableEnforceIssues = enforceIssues.filter((i) => i.severity !== 'info');

    if (actionableEnforceIssues.length === 0) {
      results.push({
        checkId: 'SEC-CSP-00',
        category: 'http-headers',
        name: 'CSP (Content-Security-Policy)',
        status: 'pass',
        severity: 'info',
        observed: `${enforcePolicies.length} 件のポリシーが有効`,
        description: '主要な危険ディレクティブが制限され、堅牢なCSPポリシーが設定されています。',
        recommendation: '現在のポリシー設定を維持してください。',
        referenceUrls: ['https://developer.mozilla.org/ja/docs/Web/HTTP/CSP'],
        scope: url,
      });
    } else {
      let overallSeverity: SecuritySeverity = 'low';
      if (actionableEnforceIssues.some((i) => i.severity === 'medium')) {
        overallSeverity = 'medium';
      }

      const issueSummary =
        summarizeCSPIssues(actionableEnforceIssues) ||
        `${enforcePolicies.length} 件のポリシーに改善点あり`;
      const issueDescriptions = actionableEnforceIssues
        .map((i) => `・[${i.directive}] ${i.description}`)
        .join('\n');
      const recommendations = Array.from(
        new Set(actionableEnforceIssues.map((i) => i.recommendation))
      ).join(' ');

      const stableId = generateFindingIdFromCheck('SEC-CSP-03', url);

      results.push({
        checkId: 'SEC-CSP-03',
        category: 'http-headers',
        name: 'CSP (Content-Security-Policy)',
        status: 'warning',
        severity: overallSeverity,
        observed: issueSummary,
        description: `CSPポリシーが検出されましたが、以下のディレクティブ設定に注意・改善点があります:\n${issueDescriptions}`,
        recommendation: recommendations,
        referenceUrls: [
          'https://developer.mozilla.org/ja/docs/Web/HTTP/CSP',
          'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html',
        ],
        scope: url,
        findingId: stableId,
      });
    }
  }

  // meta 要素の Report-Only は「無効な指定」として info で 1 件示す (SPEC-07)
  if (metaReportOnlyPolicies.length > 0) {
    results.push({
      checkId: 'SEC-CSP-META-RO',
      category: 'http-headers',
      name: 'CSP (meta Content-Security-Policy-Report-Only)',
      status: 'info',
      severity: 'info',
      observed: `無効な指定 (${metaReportOnlyPolicies.length} 件)`,
      description:
        'meta 要素で Content-Security-Policy-Report-Only が指定されていますが、ブラウザ仕様上 meta 要素での Report-Only は無視される無効な指定です。',
      recommendation:
        'Report-Only ポリシーを使用する場合は、HTTP レスポンスヘッダー (Content-Security-Policy-Report-Only) として送信してください。',
      referenceUrls: [
        'https://developer.mozilla.org/ja/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only',
      ],
      scope: url,
    });
  }

  // XFO ヘッダー文字列が直接渡された場合は frame-ancestors との矛盾注記を付加 (v1.7.1 T10)
  if (rawXfoString) {
    const conflictNote = checkXfoAndFrameAncestorsConflict(rawXfoString, normalizedPolicies, url);
    if (conflictNote) {
      results.push(conflictNote);
    }
  }

  return { policies: normalizedPolicies, issues: allIssues, results };
}

/**
 * CSPヘッダーの解析用関数 (配列・カンマ区切り対応)
 */
export function analyzeCSPHeader(
  cspHeaderValue: string | string[],
  url: string,
  hasXFrameOptions: boolean | string = false
): SecurityCheckResult[] {
  const policies = parseCSPHeaderValues(cspHeaderValue, 'response-header', 'enforce');
  const { results } = analyzeCSPPolicies(policies, url, hasXFrameOptions);
  return results;
}
