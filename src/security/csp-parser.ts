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
  CSPFinding,
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
 * 単一のCSPPolicyを診断し、セキュリティ指摘事項を抽出する (IMP-05)
 */
export function evaluateSinglePolicy(
  policy: CSPPolicy,
  hasXFrameOptions: boolean = false
): CSPIssue[] {
  const issues: CSPIssue[] = [];
  const { directives, source, mode, id: policyId } = policy;

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

  // --- 2. script-src (およびフォールバック) の実効性診断 (IMP-05 / 4.4 & 4.5) ---
  const scriptSources = getDirectiveValuesWithFallback(directives, 'script-src', ['default-src']);
  const scriptDirName = scriptSources ? (scriptSources.isFallback ? 'default-src (script-src代替)' : 'script-src') : null;

  if (scriptSources) {
    const rawVals = scriptSources.values.map((v) => v.toLowerCase());
    const cleanVals = scriptSources.values.map((v) => v.toLowerCase().replace(/['"]/g, ''));

    // nonce や ハッシュの存在確認
    const hasNonceOrHash = rawVals.some(
      (v) =>
        v.startsWith("'nonce-") ||
        v.startsWith("'sha256-") ||
        v.startsWith("'sha384-") ||
        v.startsWith("'sha512-")
    );
    const hasStrictDynamic = rawVals.includes("'strict-dynamic'") || cleanVals.includes('strict-dynamic');
    const hasUnsafeInline = rawVals.includes("'unsafe-inline'") || cleanVals.includes('unsafe-inline');
    const hasUnsafeEval = rawVals.includes("'unsafe-eval'") || cleanVals.includes('unsafe-eval');
    const hasWildcard = rawVals.includes('*') || cleanVals.includes('*');
    const hasData = rawVals.includes('data:') || cleanVals.includes('data:');

    // strict-dynamic の評価 (4.5)
    if (hasStrictDynamic) {
      issues.push({
        id: 'CSP-SCRIPT-STRICT-DYNAMIC-NOTE',
        policyId,
        directive: scriptDirName!,
        severity: 'info',
        pattern: "'strict-dynamic'",
        description: `${scriptDirName} に 'strict-dynamic' が指定されています。モダンブラウザではホスト名ホワイトリストが無効化され、nonceから生成されたスクリプトのみが実効的に許可されます。`,
        recommendation: '最新のブラウザ仕様に準拠した堅牢な設定です。レガシーブラウザ向けのフォールバックを確認してください。',
      });
    }

    // unsafe-inline の実効性評価 (4.5)
    if (hasUnsafeInline) {
      if (hasNonceOrHash) {
        // nonce/hashが存在する場合、CSP Level 2以降のブラウザではunsafe-inlineは実効的に無視される
        issues.push({
          id: 'CSP-SCRIPT-UNSAFE-INLINE',
          policyId,
          directive: scriptDirName!,
          severity: 'low',
          pattern: "'unsafe-inline'",
          description: `${scriptDirName} に 'unsafe-inline' が含まれていますが、Nonceまたはハッシュが設定されているためモダンブラウザでは実効的に無視（無効化）されています（レガシー互換用）。`,
          recommendation: "古いブラウザのサポートが不要であれば、設定の明確化のため 'unsafe-inline' の削除を検討してください。",
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
          recommendation: "インラインスクリプトを外部化するか、Nonce ('nonce-xxx') または SHA-256 ハッシュ値による個別許可に移行してください。",
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
        recommendation: "動的コード生成に依存するライブラリを見直し、'unsafe-eval' を排除してください。",
      });
    }

    // ワイルドカード (*)
    if (hasWildcard) {
      issues.push({
        id: 'CSP-SCRIPT-WILDCARD',
        policyId,
        directive: scriptDirName!,
        severity: mode === 'report-only' ? 'low' : 'high',
        pattern: '*',
        description: `${scriptDirName} にワイルドカード (*) が指定されており、任意の外部ドメインからのスクリプト読み込みが許可されています。`,
        recommendation: 'ワイルドカードを削除し、信頼できるドメイン（オリジン）のみを明示的に指定してください。',
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
  } else {
    // script-src も default-src も未定義
    issues.push({
      id: 'CSP-SCRIPT-MISSING',
      policyId,
      directive: 'script-src / default-src',
      severity: mode === 'report-only' ? 'low' : 'high',
      pattern: '未指定',
      description: 'script-src および default-src が定義されていないため、スクリプトの読み込み元が制限されていません。',
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
      description: "object-src (および default-src) が未指定です。Flashやプラグインによるスクリプト実行を制限できません。",
      recommendation: "object-src 'none' を指定してプラグイン実行を完全に無効化してください。",
    });
  } else {
    const rawVals = objectSources.values.map((v) => v.toLowerCase().replace(/['"]/g, ''));
    const isNone = rawVals.includes('none');
    if (!isNone) {
      issues.push({
        id: 'CSP-OBJECT-SRC-NOT-NONE',
        policyId,
        directive: objectSources.effectiveDirective,
        severity: 'medium',
        pattern: objectSources.values.join(' '),
        description: "object-src に 'none' 以外の値が指定されています。不要なプラグイン実行を制限するために 'none' の指定が強く推奨されます。",
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
      description: 'base-uri ディレクティブが未指定です。<base> タグの挿入による相対URL改変攻撃（Base Manipulation）を防止できません。',
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
 * 複数のCSPポリシー（ヘッダー複数、meta CSP等）を統合診断する (IMP-05 / 4.6)
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
  const allIssues: CSPIssue[] = [];
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

  for (const policy of policies) {
    const issues = evaluateSinglePolicy(policy, hasXFrameOptions);
    allIssues.push(...issues);
  }

  const enforcePolicies = policies.filter((p) => p.mode === 'enforce');
  const reportOnlyPolicies = policies.filter((p) => p.mode === 'report-only');

  // Report-Only のみの評価
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

  // 強制適用ポリシーの評価
  if (enforcePolicies.length > 0) {
    const enforceIssues = allIssues.filter((i) => {
      const p = policies.find((pol) => pol.id === i.policyId);
      return !p || p.mode === 'enforce';
    });

    if (enforceIssues.length === 0) {
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
      if (enforceIssues.some((i) => i.severity === 'high')) {
        overallSeverity = 'high';
      } else if (enforceIssues.some((i) => i.severity === 'medium')) {
        overallSeverity = 'medium';
      }

      const issueDescriptions = enforceIssues.map((i) => `・[${i.directive}] ${i.description}`).join('\n');
      const recommendations = Array.from(new Set(enforceIssues.map((i) => i.recommendation))).join(' ');

      const stableId = generateFindingId({
        ruleId: 'SEC-CSP-DIRECTIVE-ISSUE',
        origin,
        resourceKey: 'csp',
        targetKey: enforceIssues.map((i) => i.id).join(','),
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
      });
    }
  }

  return { policies, issues: allIssues, results };
}

/**
 * 単一CSPヘッダーの解析用関数 (後方互換ラッパー)
 */
export function analyzeCSPHeader(
  cspHeaderValue: string,
  url: string,
  hasXFrameOptions: boolean = false
): SecurityCheckResult[] {
  const policy = parseCSPPolicy(cspHeaderValue, 'response-header', 'enforce');
  const { results } = analyzeCSPPolicies([policy], url, hasXFrameOptions);
  return results;
}
