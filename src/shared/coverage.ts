/**
 * Web Technology & Security Inspector
 * 調査完全性・エビデンス品質管理モジュール (src/shared/coverage.ts) - IMP-08
 * 
 * - 調査できた範囲（Coverage）と調査できなかった理由のトラッキング
 * - 調査状態（complete, partial, unavailable）の判定
 * - 機密情報（認証ヘッダー、機密URLパラメータ、Cookie値等）のマスキング
 */

import { DomSignals, InspectionCoverage, InspectionStatus } from './types';

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
  /** Content Script の収集が途中で失敗または中断されたか (v1.7.1 T06) */
  domCollectionPartial?: boolean;
  /** Content Script の収集失敗に関する詳細理由 (v1.7.1 T06) */
  domCollectionReasons?: string[];
  /** Content Script の収集エラー一覧 (v1.7.1 T06) */
  domCollectionErrors?: string[];
  /** DOM にリソースの参照があるか (v1.7.1 T06) */
  hasDomResourceReferences?: boolean;
  /** 観測された通信先ホスト数 (v1.7.1 T06) */
  externalConnectionCount?: number;
}

/**
 * DOMシグナルから収集された要素・シグナルの総件数（domItemCount）を算出する (v1.7.1 T06)
 * - metaTags と scriptUrls だけでなく、収集した DOM の印（domMarkers）・スタイルシート・クラス名（htmlSnippets）の件数も含めて数える
 */
export function countDomItems(
  domSignals?: Partial<
    Pick<
      DomSignals,
      'metaTags' | 'scriptUrls' | 'domMarkers' | 'linkUrls' | 'cssAssets' | 'htmlSnippets'
    >
  > | null
): number {
  if (!domSignals) return 0;
  const metaCount = Array.isArray(domSignals.metaTags) ? domSignals.metaTags.length : 0;
  const scriptCount = Array.isArray(domSignals.scriptUrls) ? domSignals.scriptUrls.length : 0;
  const markerCount = Array.isArray(domSignals.domMarkers) ? domSignals.domMarkers.length : 0;
  const snippetCount = Array.isArray(domSignals.htmlSnippets) ? domSignals.htmlSnippets.length : 0;

  const stylesheetLinksCount = Array.isArray(domSignals.linkUrls)
    ? domSignals.linkUrls.filter((l) => {
        const tokens = String(l?.rel || '')
          .toLowerCase()
          .split(/\s+/)
          .filter(Boolean);
        return tokens.includes('stylesheet');
      }).length
    : 0;
  const cssAssetsCount = Array.isArray(domSignals.cssAssets) ? domSignals.cssAssets.length : 0;
  const stylesheetCount = Math.max(stylesheetLinksCount, cssAssetsCount);

  return metaCount + scriptCount + markerCount + stylesheetCount + snippetCount;
}

/**
 * DOM 内にサブリソースの参照（スクリプト・スタイルシート・画像等のリンク）が存在するか判定する (v1.7.1 T06)
 */
export function hasDomResourceReferences(
  domSignals?: Partial<
    Pick<
      DomSignals,
      'scriptUrls' | 'rawScriptUrls' | 'linkUrls' | 'rawLinkUrls' | 'domResourceUrls' | 'cssAssets'
    >
  > | null
): boolean {
  if (!domSignals) return false;
  if (Array.isArray(domSignals.scriptUrls) && domSignals.scriptUrls.length > 0) return true;
  if (Array.isArray(domSignals.rawScriptUrls) && domSignals.rawScriptUrls.length > 0) return true;
  if (Array.isArray(domSignals.linkUrls) && domSignals.linkUrls.length > 0) return true;
  if (Array.isArray(domSignals.rawLinkUrls) && domSignals.rawLinkUrls.length > 0) return true;
  if (Array.isArray(domSignals.domResourceUrls) && domSignals.domResourceUrls.length > 0) return true;
  if (Array.isArray(domSignals.cssAssets) && domSignals.cssAssets.length > 0) return true;
  return false;
}

/**
 * 調査完全性（InspectionCoverage）を評価・算出する (IMP-08 / 7.2 & 7.3 / v1.7.1 T06)
 */
export function assessInspectionCoverage(inputs: CoverageAssessmentInputs): InspectionCoverage {
  const missingPerms: string[] = [];
  const partialReasons: string[] = [];

  if (!inputs.hasCookiesPermission) {
    missingPerms.push('cookies');
  }
  if (!inputs.hasWebRequestPermission) {
    missingPerms.push('webRequest');
  }

  // DOM解析状態
  let dom: InspectionStatus = inputs.hasDom ? 'complete' : 'unavailable';
  if (inputs.domCollectionPartial) {
    dom = 'partial';
    const reasons = [
      ...(inputs.domCollectionReasons || []),
      ...(inputs.domCollectionErrors || []),
    ].filter(Boolean);
    if (reasons.length > 0) {
      for (const reason of reasons) {
        const formatted = reason.startsWith('Content Script')
          ? reason
          : `Content Script の DOM シグナル収集が途中で失敗しました (${reason})`;
        if (!partialReasons.includes(formatted)) {
          partialReasons.push(formatted);
        }
      }
    } else {
      partialReasons.push(
        'Content Script の収集が途中で失敗したため、一部の DOM シグナルを取得できませんでした'
      );
    }
  } else if (!inputs.hasDom) {
    partialReasons.push('DOM シグナルを取得できませんでした');
  }

  // HTTPヘッダー状態 (拡張機能起動前でwebRequest未観測の場合は partial)
  let headers: InspectionStatus = 'complete';
  if (!inputs.hasHeaders) {
    headers = inputs.unobservedPreScan ? 'partial' : 'unavailable';
    partialReasons.push(
      inputs.unobservedPreScan
        ? '拡張機能起動前の通信のため HTTP レスポンスヘッダーが未観測です'
        : 'HTTP レスポンスヘッダーを取得できませんでした'
    );
  }

  // Cookie解析状態
  let cookies: InspectionStatus = 'complete';
  if (!inputs.hasCookiesPermission) {
    cookies = 'unavailable';
    partialReasons.push('Cookie 読み取り権限 (cookies) が不足しています');
  } else if (inputs.cookieCount === 0) {
    // 0件の場合は未設定か取得漏れか未確定
    cookies = 'complete';
  }

  // iframe状態
  const iframes: InspectionStatus =
    inputs.iframeCount && inputs.iframeCount > 0 ? 'partial' : 'not-applicable';

  // ネットワーク状態
  let network: InspectionStatus = inputs.hasWebRequestPermission ? 'complete' : 'partial';
  if (!inputs.hasWebRequestPermission) {
    partialReasons.push('ネットワーク観測権限 (webRequest) が不足しています');
  }

  // DOM にリソースの参照があるのに通信先が 0 件のとき (v1.7.1 T06)
  const zeroConnectionsWithDomRefs =
    inputs.hasDomResourceReferences === true &&
    typeof inputs.externalConnectionCount === 'number' &&
    inputs.externalConnectionCount === 0;
  if (zeroConnectionsWithDomRefs) {
    network = 'partial';
    partialReasons.push('DOM にリソースの参照がありますが、通信先が 0 件でした');
  }

  if (inputs.pageNavigatedDuringScan) {
    partialReasons.push('調査中にページ遷移が発生しました');
  }

  // 全体ステータス判定
  let overallStatus: InspectionStatus = 'complete';
  if (
    dom === 'unavailable' ||
    dom === 'partial' ||
    headers === 'unavailable' ||
    headers === 'partial' ||
    cookies === 'unavailable' ||
    network === 'partial' ||
    inputs.unobservedPreScan ||
    inputs.pageNavigatedDuringScan
  ) {
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
      partialReasons:
        overallStatus !== 'complete' && partialReasons.length > 0 ? partialReasons : undefined,
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
