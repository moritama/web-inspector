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

import { generateFindingId } from '../shared/identity';
import {
  CSPPolicy,
  CSPSource,
  SecurityCheckResult,
  SecuritySeverity,
} from '../shared/types';

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
  /** 任意ホストからのスクリプト読込許可レベル ('none' | 'medium' | 'high' | 'unrestricted') */
  wildcardLevel: 'none' | 'medium' | 'high' | 'unrestricted';
  /** data: スキームによるスクリプト読込を許可しているか */
  allowsDataScheme: boolean;
  /** object-src (または代替 default-src) の状態 ('none' = 遮断, 'not-none' = 'none'以外, 'missing' = 未指定) */
  objectSrcState: 'none' | 'not-none' | 'missing';
  /** base-uri が未指定（未制限）か */
  allowsBaseUri: boolean;
  /** frame-ancestors が実効的に未指定（meta由来は無効なため true）か */
  allowsFrameAncestors: boolean;
}

/**
 * 単一ポリシーの能力プロファイルを計算する (v1.7.0 T06 / SPEC-07, SPEC-08)
 */
function analyzePolicyCapabilities(policy: CSPPolicy): PolicyCapabilities {
  const { directives, source } = policy;

  // 1. スクリプト関連能力 (インライン実行、eval、任意ホストからのスクリプト)
  const scriptSources = getDirectiveValuesWithFallback(directives, 'script-src', ['default-src']);
  let scriptMissing = false;
  let allowsInline = false;
  let allowsEval = false;
  let wildcardLevel: 'none' | 'medium' | 'high' | 'unrestricted' = 'none';
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
        wildcardLevel = 'high';
      } else if (hasSubdomainWildcard) {
        wildcardLevel = 'medium';
      }
      allowsDataScheme = hasData;
    }
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
    objectSrcState,
    allowsBaseUri,
    allowsFrameAncestors,
  };
}

/**
 * 単一のCSPPolicyを診断し、セキュリティ指摘事項を抽出する (IMP-05 / v1.7.0 T06)
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

  // --- 2. script-src (およびフォールバック) の実効性診断 (IMP-05 / 4.4 & 4.5 / SPEC-08) ---
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

    // unsafe-inline の実効性評価 (4.5 / SPEC-08)
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
        // nonce/hashなしでunsafe-inlineがある場合 -> 深刻なXSSリスク
        issues.push({
          id: 'CSP-SCRIPT-UNSAFE-INLINE',
          policyId,
          directive: scriptDirName!,
          severity: mode === 'report-only' ? 'low' : 'high',
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
      // 任意ホスト許可: *, https:, http: は high、*.example.com は medium (SPEC-08)
      if (broadWildcards.length > 0) {
        issues.push({
          id: 'CSP-SCRIPT-WILDCARD',
          policyId,
          directive: scriptDirName!,
          severity: mode === 'report-only' ? 'low' : 'high',
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
          severity: mode === 'report-only' ? 'low' : 'high',
          pattern: 'data:',
          description: `${scriptDirName} に 'data:' スキームが許可されており、data:text/javascript 経由でのインジェクションが可能です。`,
          recommendation: "スクリプト実行元から 'data:' スキームを削除してください。",
        });
      }
    }
  } else {
    // script-src も default-src も未定義
    issues.push({
      id: 'CSP-SCRIPT-MISSING',
      policyId,
      directive: 'script-src / default-src',
      severity: mode === 'report-only' ? 'low' : 'high',
      pattern: '未指定',
      description:
        'script-src および default-src が定義されていないため、スクリプトの読み込み元が制限されていません。',
      recommendation: '信頼できるオリジンを指定した script-src または default-src を設定してください。',
    });
  }

  // --- 3. object-src の検査 (IMP-05 / 4.7 & P18) ---
  const objectSources = getDirectiveValuesWithFallback(directives, 'object-src', ['default-src']);
  if (!objectSources) {
    issues.push({
      id: 'CSP-OBJECT-SRC-MISSING',
      policyId,
      directive: 'object-src',
      severity: 'medium',
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
        severity: 'medium',
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
        severity: hasXFrameOptions ? 'low' : 'medium',
        pattern: '未指定',
        description: hasXFrameOptions
          ? 'frame-ancestors ディレクティブが未指定です（X-Frame-Options により代替防御されています）。'
          : 'frame-ancestors ディレクティブが未指定であり、X-Frame-Options も無いため、クリックジャッキング攻撃に脆弱です。',
        recommendation: "frame-ancestors 'none' または 'self' を設定してください。",
      });
    }
  }

  // --- 5. base-uri の検査 (default-src にフォールバックしない) ---
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
    case 'medium':
      return 1;
    case 'high':
      return 2;
    case 'unrestricted':
      return 3;
  }
}

/**
 * 強制ポリシー群の能力（Capability）積集合（AND）に基づいて、
 * 他の強制ポリシーによって遮断（防御）されている能力の指摘事項を除外・調整する (v1.7.0 T06 / SPEC-07)
 */
function filterEnforceIssuesByIntersection(
  enforcePolicies: CSPPolicy[],
  rawEnforceIssues: CSPIssue[]
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
        if (effectiveWildcardRank === 1 && issue.severity === 'high') {
          // 積集合でサブドメインワイルドカード (medium) に制限されている場合は medium に調整
          issue.severity = 'medium';
        }
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

    // 複数ポリシー間で同一の指摘ID（かつ同一severity）が重複する場合は1件に集約
    const dedupKey = `${issue.id}:${issue.severity}`;
    if (seenIssueIds.has(dedupKey)) {
      continue;
    }
    seenIssueIds.add(dedupKey);
    filtered.push(issue);
  }

  return filtered;
}

/**
 * 複数のCSPポリシー（ヘッダー複数、meta CSP等）を統合診断する (IMP-05 / 4.6 / v1.7.0 T06)
 *
 * @param policies CSPPolicy の配列
 * @param url 対象URL
 * @param hasXFrameOptions X-Frame-Optionsヘッダーが存在するか
 * @returns { policies, issues, results }
 */
export function analyzeCSPPolicies(
  policies: CSPPolicy[],
  url: string,
  hasXFrameOptions: boolean = false
): {
  policies: CSPPolicy[];
  issues: CSPIssue[];
  results: SecurityCheckResult[];
} {
  const results: SecurityCheckResult[] = [];

  let origin = 'https://unknown';
  try {
    origin = new URL(url).origin;
  } catch {
    origin = url;
  }

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

  // meta 要素の Report-Only（ブラウザは無視する無効な指定）を分離 (SPEC-07)
  const metaReportOnlyPolicies = policies.filter(
    (p) => p.source === 'meta' && p.mode === 'report-only'
  );
  const enforcePolicies = policies.filter((p) => p.mode === 'enforce');
  const reportOnlyPolicies = policies.filter(
    (p) => p.source !== 'meta' && p.mode === 'report-only'
  );

  const rawEnforceIssues: CSPIssue[] = [];
  for (const policy of enforcePolicies) {
    rawEnforceIssues.push(...evaluateSinglePolicy(policy, hasXFrameOptions));
  }
  const enforceIssues = filterEnforceIssuesByIntersection(enforcePolicies, rawEnforceIssues);

  const reportOnlyIssues: CSPIssue[] = [];
  for (const policy of reportOnlyPolicies) {
    reportOnlyIssues.push(...evaluateSinglePolicy(policy, hasXFrameOptions));
  }

  const metaReportOnlyIssues: CSPIssue[] = [];
  for (const policy of metaReportOnlyPolicies) {
    metaReportOnlyIssues.push(...evaluateSinglePolicy(policy, hasXFrameOptions));
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

  // 強制適用ポリシーの評価（info の注記は指摘の件数に含めず、status を warning にしない: SPEC-08）
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
      if (actionableEnforceIssues.some((i) => i.severity === 'high')) {
        overallSeverity = 'high';
      } else if (actionableEnforceIssues.some((i) => i.severity === 'medium')) {
        overallSeverity = 'medium';
      }

      const issueDescriptions = actionableEnforceIssues
        .map((i) => `・[${i.directive}] ${i.description}`)
        .join('\n');
      const recommendations = Array.from(
        new Set(actionableEnforceIssues.map((i) => i.recommendation))
      ).join(' ');

      const stableId = generateFindingId({
        ruleId: 'SEC-CSP-DIRECTIVE-ISSUE',
        origin,
        resourceKey: 'csp',
        targetKey: actionableEnforceIssues.map((i) => i.id).join(','),
      });

      results.push({
        checkId: 'SEC-CSP-03',
        category: 'http-headers',
        name: 'CSP (Content-Security-Policy)',
        status: 'warning',
        severity: overallSeverity,
        observed: `${enforcePolicies.length} 件のポリシーに改善点あり`,
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

  return { policies, issues: allIssues, results };
}

/**
 * CSPヘッダーの解析用関数 (配列・カンマ区切り対応)
 */
export function analyzeCSPHeader(
  cspHeaderValue: string | string[],
  url: string,
  hasXFrameOptions: boolean = false
): SecurityCheckResult[] {
  const policies = parseCSPHeaderValues(cspHeaderValue, 'response-header', 'enforce');
  const { results } = analyzeCSPPolicies(policies, url, hasXFrameOptions);
  return results;
}
