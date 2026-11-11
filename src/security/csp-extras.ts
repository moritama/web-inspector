/**
 * Web Technology & Security Inspector
 * CSP の追加項目診断 (src/security/csp-extras.ts)
 * v1.8.0 T07 / NEW-03b
 */

import type { CSPIssue } from './csp-parser';
import { parseCSPPolicy } from './csp-parser';
import type { CSPPolicy, SecurityCheckResult, CspExtrasContext } from '../shared/types';

export type { CspExtrasContext };

/**
 * 未パースのポリシーオブジェクトを正規化する
 */
function normalizePolicy(policy: CSPPolicy): CSPPolicy {
  if (policy.directives && Object.keys(policy.directives).length > 0) {
    return policy;
  }
  if (!policy.rawValue) {
    return { ...policy, directives: {}, warnings: [] };
  }
  const parsed = parseCSPPolicy(policy.rawValue, policy.source, policy.mode);
  return {
    ...policy,
    directives: parsed.directives,
    warnings: policy.warnings && policy.warnings.length > 0 ? policy.warnings : parsed.warnings,
  };
}

/**
 * ディレクティブ名の存在チェック（大文字小文字を区別しない）
 */
function hasDirective(directives: Record<string, string[]>, name: string): boolean {
  const target = name.toLowerCase();
  for (const key of Object.keys(directives)) {
    if (key.toLowerCase() === target) {
      return true;
    }
  }
  return false;
}

/**
 * ディレクティブ値の取得（大文字小文字を区別しない）
 */
function getDirectiveValues(directives: Record<string, string[]>, name: string): string[] | undefined {
  const target = name.toLowerCase();
  for (const [key, values] of Object.entries(directives)) {
    if (key.toLowerCase() === target) {
      return values;
    }
  }
  return undefined;
}

/**
 * RFC 9651 Dictionary に基づく Reporting-Endpoints ヘッダーの解析
 * 定義されたエンドポイントグループのキー（小文字）を Set として返す
 */
export function parseReportingEndpoints(lines?: string[]): Set<string> {
  const keys = new Set<string>();
  if (!lines || lines.length === 0) return keys;

  const combined = lines.join(',');
  let i = 0;
  const len = combined.length;

  while (i < len) {
    // 空白・カンマをスキップ
    while (i < len && (combined[i] === ' ' || combined[i] === '\t' || combined[i] === ',')) {
      i++;
    }
    if (i >= len) break;

    // キーの抽出 (lcalpha または '*' で始まり、lcalpha / 数字 / '_' / '-' / '.' / '*' が続く)
    const keyStart = i;
    while (i < len && /[a-zA-Z0-9_.*-]/.test(combined[i])) {
      i++;
    }
    const key = combined.slice(keyStart, i).trim();
    if (!key) {
      while (i < len && combined[i] !== ',') i++;
      continue;
    }

    // 空白スキップ
    while (i < len && (combined[i] === ' ' || combined[i] === '\t')) i++;

    // 次が '=' であれば値がある
    if (i < len && combined[i] === '=') {
      i++; // '=' スキップ
      while (i < len && (combined[i] === ' ' || combined[i] === '\t')) i++;
      if (i < len && combined[i] === '"') {
        i++; // 開始引用符
        while (i < len) {
          if (combined[i] === '\\') {
            i += 2;
          } else if (combined[i] === '"') {
            i++;
            break;
          } else {
            i++;
          }
        }
      } else {
        while (i < len && combined[i] !== ',' && combined[i] !== ';') {
          i++;
        }
      }
    }

    // パラメータ ';' のスキップ
    while (i < len && combined[i] !== ',') {
      i++;
    }

    if (key) {
      keys.add(key.toLowerCase());
    }
  }

  return keys;
}

/**
 * 共通の文言定義
 */
const MESSAGES = {
  tt: {
    name: 'CSP (Trusted Types)',
    observed: "require-trusted-types-for 'script' 未指定",
    description: "強制ポリシーに require-trusted-types-for 'script' が指定されていません。",
    recommendation: "require-trusted-types-for 'script' を Report-Only で試してから強制を検討してください。",
  },
  uir: {
    name: 'CSP (upgrade-insecure-requests)',
    observed: '混在コンテンツ検出 / upgrade-insecure-requests 未指定',
    description: '混在コンテンツが検出されていますが、強制ポリシーに upgrade-insecure-requests が指定されていません。',
    recommendation: '混在コンテンツの URL を https に直してください。すぐに直せない場合の補助として upgrade-insecure-requests の指定を検討してください。',
  },
  form: {
    name: 'CSP (form-action)',
    observed: 'form-action 未指定',
    description: '強制ポリシーに form-action が指定されていません（default-src では代替されません）。',
    recommendation: "form-action 'self' などを指定してフォームの送信先を限定してください（default-src にはフォールバックしません）。",
  },
  report: {
    name: 'CSP (report-to のレポート先)',
    observed: (groups: string[]) => `未定義のエンドポイントグループ: ${groups.join(', ')}`,
    description: (groups: string[]) => `Reporting-Endpoints ヘッダーに未定義のエンドポイントグループ "${groups.join(', ')}" が指定されています。`,
    recommendation: 'Reporting-Endpoints ヘッダーに同じ名前のエンドポイントを定義するか、report-to の指定を修正してください。',
  },
} as const;

/**
 * ページ全体の 4 項目（SEC-CSPX-*）を評価する。発火しない項目は返さない
 */
export function checkCspExtras(
  policies: CSPPolicy[],
  url: string,
  context: CspExtrasContext
): SecurityCheckResult[] {
  const results: SecurityCheckResult[] = [];
  const normalizedPolicies = policies.map(normalizePolicy);
  const enforcePolicies = normalizedPolicies.filter((p) => p.mode === 'enforce');

  // 1. SEC-CSPX-TT-01: Trusted Types
  // 強制ポリシーが 1 つ以上あり、どの強制ポリシーにも require-trusted-types-for 'script' がない
  if (enforcePolicies.length > 0) {
    const hasTrustedTypesScript = enforcePolicies.some((p) => {
      const vals = getDirectiveValues(p.directives, 'require-trusted-types-for');
      return vals && vals.some((v) => v.trim().toLowerCase() === "'script'");
    });
    if (!hasTrustedTypesScript) {
      results.push({
        checkId: 'SEC-CSPX-TT-01',
        category: 'http-headers',
        name: MESSAGES.tt.name,
        status: 'info',
        severity: 'info',
        scope: url,
        observed: MESSAGES.tt.observed,
        description: MESSAGES.tt.description,
        recommendation: MESSAGES.tt.recommendation,
        referenceUrls: ['https://w3c.github.io/trusted-types/dist/spec/'],
      });
    }
  }

  // 2. SEC-CSPX-UIR-01: upgrade-insecure-requests
  // 混在コンテンツが検出されていて、どの強制ポリシーにも upgrade-insecure-requests がない（CSP が全くない場合も含む）
  if (context.mixedContentDetected) {
    const hasUir = enforcePolicies.some((p) => hasDirective(p.directives, 'upgrade-insecure-requests'));
    if (!hasUir) {
      results.push({
        checkId: 'SEC-CSPX-UIR-01',
        category: 'http-headers',
        name: MESSAGES.uir.name,
        status: 'info',
        severity: 'info',
        scope: url,
        observed: MESSAGES.uir.observed,
        description: MESSAGES.uir.description,
        recommendation: MESSAGES.uir.recommendation,
        referenceUrls: ['https://w3c.github.io/webappsec-upgrade-insecure-requests/'],
      });
    }
  }

  // 3. SEC-CSPX-FORM-01: form-action
  // 強制ポリシーが 1 つ以上あり、どの強制ポリシーにも form-action がない
  if (enforcePolicies.length > 0) {
    const hasFormAction = enforcePolicies.some((p) => hasDirective(p.directives, 'form-action'));
    if (!hasFormAction) {
      results.push({
        checkId: 'SEC-CSPX-FORM-01',
        category: 'http-headers',
        name: MESSAGES.form.name,
        status: 'warning',
        severity: 'low',
        scope: url,
        observed: MESSAGES.form.observed,
        description: MESSAGES.form.description,
        recommendation: MESSAGES.form.recommendation,
        referenceUrls: ['https://w3c.github.io/webappsec-csp/#directive-form-action'],
      });
    }
  }

  // 4. SEC-CSPX-REPORT-01: レポート先
  // ヘッダーで受け取ったポリシー（強制・Report-Only）のうち、report-to のグループが Reporting-Endpoints に定義されていないもの
  const headerPolicies = normalizedPolicies.filter((p) => p.source === 'response-header');
  const definedEndpoints = parseReportingEndpoints(context.reportingEndpoints);
  const missingGroups: string[] = [];

  for (const p of headerPolicies) {
    const reportToVals = getDirectiveValues(p.directives, 'report-to');
    if (reportToVals && reportToVals.length > 0) {
      const groupToken = reportToVals[0].trim();
      if (groupToken && !definedEndpoints.has(groupToken.toLowerCase())) {
        if (!missingGroups.includes(groupToken)) {
          missingGroups.push(groupToken);
        }
      }
    }
  }

  if (missingGroups.length > 0) {
    results.push({
      checkId: 'SEC-CSPX-REPORT-01',
      category: 'http-headers',
      name: MESSAGES.report.name,
      status: 'info',
      severity: 'info',
      scope: url,
      observed: MESSAGES.report.observed(missingGroups),
      description: MESSAGES.report.description(missingGroups),
      recommendation: MESSAGES.report.recommendation,
      referenceUrls: ['https://w3c.github.io/reporting/#header'],
    });
  }

  return results;
}

/**
 * 1 つのポリシーの「問題点の表」に足す指摘を返す（id は CSP-TRUSTED-TYPES-MISSING など）
 */
export function evaluateCspExtraIssues(
  policy: CSPPolicy,
  allPolicies: CSPPolicy[],
  context: CspExtrasContext
): CSPIssue[] {
  if (!context) return [];

  const issues: CSPIssue[] = [];
  const normalizedTarget = normalizePolicy(policy);
  const normalizedAll = allPolicies.map(normalizePolicy);
  const enforcePolicies = normalizedAll.filter((p) => p.mode === 'enforce');

  // TT, UIR, FORM: 対象ポリシーが強制ポリシーで、かつ全体で指定がないとき
  if (normalizedTarget.mode === 'enforce') {
    // 1. TT
    if (enforcePolicies.length > 0) {
      const hasTrustedTypesScript = enforcePolicies.some((p) => {
        const vals = getDirectiveValues(p.directives, 'require-trusted-types-for');
        return vals && vals.some((v) => v.trim().toLowerCase() === "'script'");
      });
      if (!hasTrustedTypesScript) {
        issues.push({
          id: 'CSP-TRUSTED-TYPES-MISSING',
          directive: 'require-trusted-types-for',
          severity: 'info',
          description: MESSAGES.tt.description,
          recommendation: MESSAGES.tt.recommendation,
          policyId: normalizedTarget.id,
          pattern: '未指定',
        });
      }
    }

    // 2. UIR
    if (context.mixedContentDetected) {
      const hasUir = enforcePolicies.some((p) => hasDirective(p.directives, 'upgrade-insecure-requests'));
      if (!hasUir) {
        issues.push({
          id: 'CSP-UPGRADE-INSECURE-REQUESTS-MISSING',
          directive: 'upgrade-insecure-requests',
          severity: 'info',
          description: MESSAGES.uir.description,
          recommendation: MESSAGES.uir.recommendation,
          policyId: normalizedTarget.id,
          pattern: '未指定',
        });
      }
    }

    // 3. FORM
    if (enforcePolicies.length > 0) {
      const hasFormAction = enforcePolicies.some((p) => hasDirective(p.directives, 'form-action'));
      if (!hasFormAction) {
        issues.push({
          id: 'CSP-FORM-ACTION-MISSING',
          directive: 'form-action',
          severity: 'low',
          description: MESSAGES.form.description,
          recommendation: MESSAGES.form.recommendation,
          policyId: normalizedTarget.id,
          pattern: '未指定',
        });
      }
    }
  }

  // 4. REPORT: 対象ポリシーがヘッダーのポリシーで、未定義の report-to グループを持つとき
  if (normalizedTarget.source === 'response-header') {
    const reportToVals = getDirectiveValues(normalizedTarget.directives, 'report-to');
    if (reportToVals && reportToVals.length > 0) {
      const groupToken = reportToVals[0].trim();
      const definedEndpoints = parseReportingEndpoints(context.reportingEndpoints);
      if (groupToken && !definedEndpoints.has(groupToken.toLowerCase())) {
        issues.push({
          id: 'CSP-REPORT-TO-UNDEFINED-GROUP',
          directive: 'report-to',
          severity: 'info',
          description: MESSAGES.report.description([groupToken]),
          recommendation: MESSAGES.report.recommendation,
          policyId: normalizedTarget.id,
          pattern: groupToken,
        });
      }
    }
  }

  return issues;
}
