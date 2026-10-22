/**
 * Web Technology & Security Inspector
 * 共通型定義 (src/shared/types.ts) - Version 1.1.0
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
 * - high: 80〜100 (明確な固有シグナルがある)
 * - medium: 50〜79 (複数の間接的な証拠がある)
 * - low: 1〜49 (可能性を示す証拠がある)
 * - none: 0 (判断できる証拠がない)
 */
export type ConfidenceLevel = 'high' | 'medium' | 'low' | 'none';

/**
 * 検出根拠の種別 (Version 1.1 ADD-07)
 */
export type EvidenceType =
  | 'runtime'               // JavaScript実行時情報 (window.jQuery, window.bootstrap等)
  | 'html'                  // HTML要素・属性 (ng-version, data-reactroot等)
  | 'script-url'            // JavaScriptファイルURL
  | 'css-url'               // CSSファイルURL
  | 'css-comment'           // CSSファイル内のコメント
  | 'response-header'       // HTTPレスポンスヘッダー
  | 'cookie-name'           // Cookie名
  | 'url-pattern'           // URLパス・クエリ
  | 'dom-marker'            // DOMマーカー
  | 'pattern';              // その他パターン

/**
 * 検出根拠 (エビデンス)
 */
export interface Evidence {
  type: EvidenceType;
  /** 検出項目名 */
  name: string;
  /** 観測された値 */
  value: string;
  /** 取得元URLまたは実行時オブジェクトパス */
  source: string;
  /** 補足説明 */
  detail?: string;
  /** 確信度 */
  confidence?: 'high' | 'medium' | 'low';
  /** この単体エビデンスが付与する基礎スコア */
  weight?: number;
}

/**
 * EOL・サポート状況 (Version 1.1 ADD-04)
 */
export type SupportStatus =
  | 'Supported'     // サポート中
  | 'Maintenance'   // 限定保守・セキュリティ修正のみ
  | 'EOL'           // サポート終了 (End of Life)
  | 'Unknown';      // 情報不足・判定不可

/**
 * EOL詳細情報
 */
export interface EolInfo {
  status: SupportStatus;
  eolDate: string | null;       // YYYY-MM-DD または YYYY-MM
  releaseDate?: string | null;
  supportedUntil?: string | null;
  source: string;               // 公式ポリシーまたはendoflife.date
  sourceUrl?: string;
  recommendation: string;       // 推奨対応
}

/**
 * 脆弱性照合ステータス (Version 1.1 ADD-05)
 */
export type AdvisoryMatchStatus =
  | 'Potentially Affected'  // 影響バージョン範囲に一致
  | 'Not Affected'          // 対象アドバイザリの影響範囲外
  | 'Needs Review'          // 追加確認が必要
  | 'No Data'               // 該当情報が見つからない
  | 'Lookup Failed';        // 情報取得に失敗

/**
 * 脆弱性 (CVE / GHSA) 詳細アイテム
 */
export interface SecurityAdvisory {
  id: string;               // 例: "CVE-2019-8331", "GHSA-xxxx"
  aliases?: string[];       // 関連CVE/GHSA ID
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  cvssScore?: number | null;
  affectedRange: string;    // 例: "< 4.3.1", ">= 4.0.0, < 4.3.1"
  fixedVersion: string | null; // 例: "4.3.1"
  summary: string;
  publishedDate?: string;
  referenceUrls: string[];
}

/**
 * バージョン整合性判定結果 (Version 1.1 ADD-03)
 */
export type VersionMismatchStatus =
  | 'match'           // 一致 (OK)
  | 'mismatch'        // 要確認 (不一致)
  | 'indeterminate'   // 判定不能 (どちらか一方または両方が不明)
  | 'multiple';       // 複数バージョン検出

/**
 * バージョン整合性詳細
 */
export interface VersionIntegrityInfo {
  jsVersion: string | null;
  cssVersion: string | null;
  status: VersionMismatchStatus;
  detail: string;
  recommendation: string;
}

/**
 * 検出されたWeb技術 (Version 1.1 拡張)
 */
export interface DetectedTechnology {
  /** 技術名 (例: "jQuery", "Bootstrap", "PHP", "Apache") */
  technology: string;
  /** カテゴリ */
  category: TechnologyCategory;
  /** 検出フラグ */
  detected: boolean;
  /** 特定された代表バージョン */
  version: string | null;
  /** バージョン取得元 ('runtime' | 'css-url' | 'css-comment' | 'script-url' | 'header' | 'meta' | 'pattern') */
  versionSource?: string;
  /** 確信度スコア (0〜100) */
  confidence: number;
  /** 確信度判定ラベル */
  confidenceLevel: ConfidenceLevel;
  /** 判定根拠リスト */
  evidence: Evidence[];

  // --- Version 1.1 追加項目 ---
  /** CSS側から検出されたバージョン */
  cssVersion?: string | null;
  /** JavaScript側から検出されたバージョン */
  jsVersion?: string | null;
  /** CSSとJSのバージョン整合性 */
  versionIntegrity?: VersionIntegrityInfo;
  /** EOLサポート状況 */
  supportStatus?: SupportStatus;
  /** EOL日 */
  eolDate?: string | null;
  /** EOL詳細 */
  eolInfo?: EolInfo;
  /** 脆弱性照合ステータス */
  advisoryMatchStatus?: AdvisoryMatchStatus;
  /** 該当する既知脆弱性一覧 */
  advisories?: SecurityAdvisory[];
  /** 最大CVSSスコア */
  maxCvss?: number | null;
  /** 脆弱性データ更新日時 */
  advisoryDataUpdatedAt?: string;

  /** 技術の概要 */
  description?: string;
  /** 公式サイトURL */
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
  | 'cors'                    // CORS設定
  | 'library-security';       // ライブラリEOL・既知脆弱性

/**
 * セキュリティ診断ステータス
 */
export type SecurityStatus = 'pass' | 'warning' | 'fail' | 'info' | 'unknown';

/**
 * セキュリティ診断重大度
 */
export type SecuritySeverity = 'high' | 'medium' | 'low' | 'info' | 'unknown';

/**
 * セキュリティ診断チェック結果
 */
export interface SecurityCheckResult {
  checkId: string;
  category: SecurityCategory;
  name: string;
  status: SecurityStatus;
  severity: SecuritySeverity;
  observed: string;
  description: string;
  recommendation: string;
  referenceUrls: string[];
  scope: string;
}

/**
 * Cookieの用途別カテゴリ (Version 1.2 IMP-01)
 */
export type CookieCategory =
  | 'authentication'  // 認証・セッション
  | 'csrf'            // CSRF保護トークン
  | 'analytics'       // トラッキング・アクセス解析
  | 'preferences'     // UI・表示設定
  | 'general';        // 一般・その他

/**
 * Cookie診断における個別指摘事項
 */
export interface CookieIssue {
  id: string;
  name: string;
  category: CookieCategory;
  severity: SecuritySeverity;
  missingAttributes: ('Secure' | 'HttpOnly' | 'SameSite' | 'Prefix')[];
  description: string;
  recommendation: string;
}

/**
 * Cookie属性診断用サマリー
 */
export interface CookieAnalysisResult {
  totalCount: number;
  secureCount: number;
  issues: CookieIssue[];
}

/**
 * Cookie診断用属性情報 (※値は除外)
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
  hostPrefixValid?: boolean;
  securePrefixValid?: boolean;
  category?: CookieCategory;
  issues: string[];
}

/**
 * 混在コンテンツ (Mixed Content)
 */
export interface MixedContentItem {
  resourceType: 'image' | 'script' | 'stylesheet' | 'iframe' | 'fetch' | 'other';
  url: string;
  elementHtml?: string;
}

/**
 * CSSファイル解析結果 (Version 1.1 ADD-02)
 */
export interface InspectedCssAsset {
  href: string;
  filename: string;
  inferredLibrary?: string;
  inferredVersion?: string | null;
  commentVersion?: string | null;
  evidenceType: 'css-url' | 'css-comment';
  confidence: 'high' | 'medium' | 'low';
}

/**
 * Content ScriptおよびMAIN WorldがDOMから収集するシグナル
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
  cookiesFromDocument: string[];
  // Version 1.1 追加
  cssAssets: InspectedCssAsset[];
  runtimeVersions?: Record<string, string | null>; // window.jQuery, window.bootstrap等
}

/**
 * ネットワーク生シグナル
 */
export interface NetworkSignals {
  url: string;
  statusCode?: number;
  responseHeaders: Record<string, string[]>;
  cookies: InspectedCookieInfo[];
}

/**
 * 総合調査レポート (Version 1.1)
 */
export interface InspectionReport {
  id: string;
  url: string;
  hostname: string;
  inspectedAt: string;
  extensionVersion: string;
  rulesVersion: string;
  advisoryDatabaseVersion?: string;
  summary: {
    totalTechnologies: number;
    requiresAttentionCount: number;
    securityFindings: {
      high: number;
      medium: number;
      low: number;
      info: number;
      unknown: number;
    };
    librarySecurity: {
      eolCount: number;
      vulnerableLibraryCount: number;
      mismatchCount: number;
    };
    isHttps: boolean;
    mixedContentCount: number;
  };
  technologies: DetectedTechnology[];
  securityChecks: SecurityCheckResult[];
  cookies: InspectedCookieInfo[];
  mixedContent: MixedContentItem[];
}

/**
 * 調査履歴サマリー
 */
export interface HistoryEntrySummary {
  id: string;
  url: string;
  hostname: string;
  inspectedAt: string;
  technologyCount: number;
  requiresAttentionCount: number;
  eolCount?: number;
  vulnerableCount?: number;
  isHttps: boolean;
}

/**
 * 拡張機能の設定
 */
export interface ExtensionSettings {
  maxHistoryEntries: number;
  theme: 'system' | 'dark' | 'light';
  enableOnlineAdvisoryLookup: boolean; // オンライン脆弱性照合 (デフォルト: false)
}

/**
 * メッセージ型定義
 */
export type ExtensionMessage =
  | { type: 'INSPECT_CURRENT_TAB'; tabId?: number }
  | { type: 'INSPECTION_RESULT'; payload: InspectionReport }
  | { type: 'INSPECTION_ERROR'; error: string }
  | { type: 'GET_REPORT_BY_ID'; id: string }
  | { type: 'GET_ALL_REPORTS' }
  | { type: 'GET_HISTORY' }
  | { type: 'DELETE_HISTORY_ITEM'; id: string }
  | { type: 'CLEAR_HISTORY' }
  | { type: 'QUERY_ONLINE_ADVISORY'; technology: string; version: string }
  | { type: 'GET_SETTINGS' }
  | { type: 'SAVE_SETTINGS'; payload: Partial<ExtensionSettings> };
