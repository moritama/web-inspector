/**
 * Web Technology & Security Inspector
 * 調査完全性・エビデンス品質管理モジュール (src/shared/coverage.ts) - IMP-08
 * 
 * - 調査できた範囲（Coverage）と調査できなかった理由のトラッキング
 * - 調査状態（complete, partial, unavailable）の判定
 * - 機密情報（認証ヘッダー、機密URLパラメータ、Cookie値等）のマスキング
 */

import { InspectionCoverage, InspectionStatus } from './types';

export interface CoverageAssessmentInputs {
  hasDom: boolean;
  hasHeaders: boolean;
  hasCookiesPermission: boolean;
  cookieCount: number;
  hasWebRequestPermission: boolean;
  iframeCount?: number;
  unobservedPreScan?: boolean;
  pageNavigatedDuringScan?: boolean;
  domItemCount?: number;
  headerCount?: number;
}

/**
 * 調査完全性（InspectionCoverage）を評価・算出する (IMP-08 / 7.2 & 7.3)
 */
export function assessInspectionCoverage(inputs: CoverageAssessmentInputs): InspectionCoverage {
  const missingPerms: string[] = [];

  if (!inputs.hasCookiesPermission) {
    missingPerms.push('cookies');
  }
  if (!inputs.hasWebRequestPermission) {
    missingPerms.push('webRequest');
  }

  // DOM解析状態
  const dom: InspectionStatus = inputs.hasDom ? 'complete' : 'unavailable';

  // HTTPヘッダー状態 (拡張機能起動前でwebRequest未観測の場合は partial)
  let headers: InspectionStatus = 'complete';
  if (!inputs.hasHeaders) {
    headers = inputs.unobservedPreScan ? 'partial' : 'unavailable';
  }

  // Cookie解析状態
  let cookies: InspectionStatus = 'complete';
  if (!inputs.hasCookiesPermission) {
    cookies = 'unavailable';
  } else if (inputs.cookieCount === 0) {
    // 0件の場合は未設定か取得漏れか未確定
    cookies = 'complete';
  }

  // iframe状態
  const iframes: InspectionStatus = inputs.iframeCount && inputs.iframeCount > 0 ? 'partial' : 'not-applicable';

  // ネットワーク状態
  const network: InspectionStatus = inputs.hasWebRequestPermission ? 'complete' : 'partial';

  // 全体ステータス判定
  let overallStatus: InspectionStatus = 'complete';
  if (dom === 'unavailable' || headers === 'unavailable' || cookies === 'unavailable') {
    overallStatus = 'partial';
  } else if (inputs.unobservedPreScan || inputs.pageNavigatedDuringScan) {
    overallStatus = 'partial';
  }

  return {
    dom,
    headers,
    cookies,
    iframes,
    network,
    overallStatus,
    details: {
      missingPermissions: missingPerms.length > 0 ? missingPerms : undefined,
      unobservedPreScan: inputs.unobservedPreScan,
      pageNavigatedDuringScan: inputs.pageNavigatedDuringScan,
      domItemCount: inputs.domItemCount,
      headerCount: inputs.headerCount,
      cookieCount: inputs.cookieCount,
    },
  };
}

/**
 * 機密データ（トークン、APIキー、認証ヘッダー等）をマスクする (IMP-08 / 7.4)
 *
 * @param text 対象文字列（URL、ヘッダー、ログ等）
 * @returns マスク後の文字列
 */
export function maskSensitiveData(text: string): string {
  if (!text || typeof text !== 'string') return text;

  let result = text;

  // 1. Authorization ヘッダーのマスク (Bearer, Basic, Digest, etc.)
  result = result.replace(
    /(authorization\s*:\s*(?:bearer|basic|digest|token)\s+)[^\s\r\n,]+/gi,
    '$1[REDACTED]'
  );

  // 2. URLクエリパラメータの機密キー（token, secret, api_key, password 等）のマスク
  const sensitiveKeys = [
    'token',
    'access_token',
    'refresh_token',
    'id_token',
    'api_key',
    'apikey',
    'secret',
    'secret_key',
    'password',
    'passwd',
    'auth',
    'jwt',
    'session_id',
    'sess',
    'signature',
    'sig',
  ];

  for (const key of sensitiveKeys) {
    const regex = new RegExp(`([?&]${key}=)[^&\\s#]+`, 'gi');
    result = result.replace(regex, '$1[REDACTED]');
  }

  return result;
}
