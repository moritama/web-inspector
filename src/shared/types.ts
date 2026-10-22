/**
 * Web Technology & Security Inspector
 * 共通型定義 (src/shared/types.ts)
 */

/**
 * 技術カテゴリ種別
 */
export type TechnologyCategory =
  | 'web-server'             // Webサーバー
  | 'programming-language'    // サーバーサイドプログラミング言語
  | 'cms'                     // コンテンツ管理システム (CMS)
  | 'js-framework'            // JavaScriptフレームワーク
  | 'js-css-library'          // JavaScript / CSSライブラリ
  | 'cdn-waf';                // CDN / WAF / リバースプロキシ

/**
 * 確信度レベル (仕様書第5項)
 * - 高: 80〜100 (明確な固有シグナルがある)
 * - 中: 50〜79 (複数の間接的な証拠がある)
 * - 低: 1〜49 (可能性を示す証拠がある)
 * - なし: 0 (判断できる証拠がない)
 */
export type ConfidenceLevel = 'high' | 'medium' | 'low' | 'none';

/**
 * 検出根拠 (エビデンス)
 */
export interface Evidence {
  /** 根拠の種別 */
  type:
    | 'response-header'       // HTTPレスポンスヘッダー
    | 'cookie-name'           // Cookie名
    | 'url-pattern'           // URLパターン / パス
    | 'meta-tag'              // metaタグ (generator等)
    | 'script-src'            // 読み込まれたスクリプトURL
    | 'link-href'             // linkタグのhref
    | 'dom-marker'            // DOM構造 / 特有の属性・ID・クラス
    | 'css-rule';             // CSSシグネチャ
  /** 検出項目名 (ヘッダー名、Cookie名、meta名など) */
  name: string;
  /** 観測された値 (バージョンや文字列、マッチしたパターン) */
  value: string;
  /** 取得元URLまたはスコープ */
  source: string;
  /** 補足説明 */
  detail?: string;
  /** この単体エビデンスが付与する基礎スコア */
  weight?: number;
}

/**
 * 検出されたWeb技術
 */
export interface DetectedTechnology {
  /** 技術名 (例: "PHP", "Apache", "WordPress", "React") */
  technology: string;
  /** 分類カテゴリ */
  category: TechnologyCategory;
  /** 検出フラグ */
  detected: boolean;
  /** 特定されたバージョン (不明な場合は null) */
  version: string | null;
  /** 確信度スコア (0〜100) */
  confidence: number;
  /** 確信度判定ラベル ('high' | 'medium' | 'low' | 'none') */
  confidenceLevel: ConfidenceLevel;
  /** 判定根拠リスト */
  evidence: Evidence[];
  /** 技術の概要 */
  description?: string;
  /** 公式サイトまたはドキュメントURL */
  website?: string;
  /** アイコン識別子 */
  icon?: string;
}

/**
 * セキュリティ診断カテゴリ
 */
export type SecurityCategory =
  | 'http-headers'            // HTTPセキュリティヘッダー
  | 'cookies'                 // Cookie属性・セキュリティ
  | 'https-communication'     // HTTPS・混在コンテンツ
  | 'information-disclosure'  // サーバー・言語等の情報漏洩
  | 'cors';                   // CORS設定

/**
 * セキュリティ診断結果ステータス
 */
export type SecurityStatus = 'pass' | 'warning' | 'fail' | 'info' | 'unknown';

/**
 * セキュリティ診断重大度 (仕様書第5項)
 * - high: 明確な危険な設定
 * - medium: 改善が推奨される設定
 * - low: 軽微な設定上の問題や参考情報
 * - info: 情報提供
 * - unknown: 観測不足で判断できない
 */
export type SecuritySeverity = 'high' | 'medium' | 'low' | 'info' | 'unknown';

/**
 * セキュリティ診断チェック結果
 */
export interface SecurityCheckResult {
  /** チェック項目ID (例: "SEC-HSTS-01", "SEC-CSP-01") */
  checkId: string;
  /** カテゴリ */
  category: SecurityCategory;
  /** チェック項目名 (例: "HSTS (Strict-Transport-Security)") */
  name: string;
  /** 診断ステータス */
  status: SecurityStatus;
  /** 重大度 */
  severity: SecuritySeverity;
  /** 観測された内容 (例: "Header not present", "max-age=31536000; includeSubDomains") */
  observed: string;
  /** 問題点・現状の解説 */
  description: string;
  /** 推奨される改善方法 */
  recommendation: string;
  /** 参考資料URL一覧 */
  referenceUrls: string[];
  /** 対象スコープ (URLなど) */
  scope: string;
}

/**
 * Cookie診断用属性情報 (※値そのものは保存しない)
 */
export interface InspectedCookieInfo {
  name: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: 'no_restriction' | 'lax' | 'strict' | 'unspecified';
  session: boolean;
  expirationDate?: number;
  hostPrefixValid?: boolean;    // __Host- プレフィックスの整合性
  securePrefixValid?: boolean;  // __Secure- プレフィックスの整合性
  issues: string[];             // 検出された属性の問題
}

/**
 * 混在コンテンツ (Mixed Content) 検出アイテム
 */
export interface MixedContentItem {
  resourceType: 'image' | 'script' | 'stylesheet' | 'iframe' | 'fetch' | 'other';
  url: string;
  elementHtml?: string;
}

/**
 * Content ScriptがDOMから収集するシグナル
 */
export interface DomSignals {
  url: string;
  title: string;
  metaTags: Array<{ name?: string; property?: string; content: string }>;
  scriptUrls: string[];
  linkUrls: Array<{ rel: string; href: string }>;
  domMarkers: string[];
  htmlSnippets: string[];
  mixedContent: MixedContentItem[];
  cookiesFromDocument: string[]; // document.cookieから得られる名前のみ
}

/**
 * ネットワークから収集した生シグナル
 */
export interface NetworkSignals {
  url: string;
  statusCode?: number;
  responseHeaders: Record<string, string[]>;
  cookies: InspectedCookieInfo[];
}

/**
 * 総合調査レポート
 */
export interface InspectionReport {
  /** レポートの一意なID (UUID形式) */
  id: string;
  /** 調査対象URL */
  url: string;
  /** ホスト名 */
  hostname: string;
  /** 調査日時 (ISO 8601) */
  inspectedAt: string;
  /** 拡張機能バージョン */
  extensionVersion: string;
  /** ルール定義バージョン */
  rulesVersion: string;
  /** サマリー情報 */
  summary: {
    totalTechnologies: number;
    requiresAttentionCount: number; // warning + fail
    securityFindings: {
      high: number;
      medium: number;
      low: number;
      info: number;
      unknown: number;
    };
    isHttps: boolean;
    mixedContentCount: number;
  };
  /** 検出された技術一覧 */
  technologies: DetectedTechnology[];
  /** セキュリティ診断項目一覧 */
  securityChecks: SecurityCheckResult[];
  /** Cookie属性診断一覧 */
  cookies: InspectedCookieInfo[];
  /** 混在コンテンツ一覧 */
  mixedContent: MixedContentItem[];
}

/**
 * 調査履歴サマリー (リスト表示用)
 */
export interface HistoryEntrySummary {
  id: string;
  url: string;
  hostname: string;
  inspectedAt: string;
  technologyCount: number;
  requiresAttentionCount: number;
  isHttps: boolean;
}

/**
 * 拡張機能の設定
 */
export interface ExtensionSettings {
  maxHistoryEntries: number;       // 保持する最大履歴件数 (デフォルト: 50)
  autoScanOnPageLoad: boolean;     // ページ読み込み時の自動解析 (デフォルト: false, オンデマンド)
  theme: 'system' | 'dark' | 'light';
}

/**
 * Service WorkerとPopup/Dashboard間のメッセージ通信型
 */
export type ExtensionMessage =
  | { type: 'INSPECT_CURRENT_TAB'; tabId?: number }
  | { type: 'INSPECTION_RESULT'; payload: InspectionReport }
  | { type: 'INSPECTION_ERROR'; error: string }
  | { type: 'GET_REPORT_BY_ID'; id: string }
  | { type: 'GET_HISTORY' }
  | { type: 'DELETE_HISTORY_ITEM'; id: string }
  | { type: 'CLEAR_HISTORY' }
  | { type: 'GET_SETTINGS' }
  | { type: 'SAVE_SETTINGS'; payload: Partial<ExtensionSettings> };
