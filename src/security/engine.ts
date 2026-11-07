/**
 * Web Technology & Security Inspector
 * 統合セキュリティ診断エンジン (src/security/engine.ts)
 */

import {
  DomSignals,
  InspectedCookieInfo,
  NetworkSignals,
  SecurityCheckResult,
} from '../shared/types';
import { checkCookies } from './cookies';
import { checkLegacyAnalyticsTags } from './domain-analyzer';
import { checkHttpHeaders } from './headers';
import { checkHttpsAndMixedContent } from './https';

/**
 * セキュリティ診断入力パラメータ
 */
export interface SecurityEvaluationInput {
  url: string;
  dom: DomSignals;
  network?: NetworkSignals;
}

/**
 * 統合セキュリティ診断エンジン
 */
export class SecurityEngine {
  /**
   * 観測情報から総合セキュリティ診断を実行する
   */
  public evaluate(input: SecurityEvaluationInput): {
    checks: SecurityCheckResult[];
    cookies: InspectedCookieInfo[];
  } {
    const isHttps = input.url.toLowerCase().startsWith('https://');
    const allChecks: SecurityCheckResult[] = [];

    // 1. HTTPヘッダー診断（meta CSP がある場合はヘッダー CSP と合わせて積集合評価: v1.7.1 T10）
    const headers = input.network?.responseHeaders || {};
    const headerChecks = checkHttpHeaders(headers, input.url, isHttps, {
      metaCsp: input.dom?.metaCsp,
      metaCspReportOnly: input.dom?.metaCspReportOnly,
    });
    allChecks.push(...headerChecks);

    // 2. Cookie診断
    const rawCookies = input.network?.cookies || [];
    const { checks: cookieChecks, inspectedCookies } = checkCookies(rawCookies, input.url, isHttps);
    allChecks.push(...cookieChecks);

    // 3. HTTPS & 混在コンテンツ診断
    const mixedItems = input.dom?.mixedContent || [];
    const httpsChecks = checkHttpsAndMixedContent(input.url, isHttps, mixedItems);
    allChecks.push(...httpsChecks);

    // 4. 旧世代の計測タグ (ga.js / analytics.js) の残存確認 (v1.7.1 T09 / L, E5)
    const legacyTagChecks = checkLegacyAnalyticsTags(input.url, input.dom);
    allChecks.push(...legacyTagChecks);

    // 重大度順（high -> medium -> low -> info -> unknown）にソート
    const severityOrder: Record<string, number> = {
      high: 0,
      medium: 1,
      low: 2,
      info: 3,
      unknown: 4,
    };

    allChecks.sort((a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9));

    return {
      checks: allChecks,
      cookies: inspectedCookies,
    };
  }
}
