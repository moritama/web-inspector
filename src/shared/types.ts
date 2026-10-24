/**
 * Web Technology & Security Inspector
 * 共通型定義 (src/shared/types.ts) - Version 1.1.0
 */

/**
 * 技術カテゴリ種別
 */
export type TechnologyCategory =
  | 'web-server'             // Webサーバー
  | 'programming-language'    // サーバーサイドプログラミング言語 / フレームワーク
  | 'cms'                     // コンテンツ管理システム (CMS)
  | 'js-framework'            // JavaScriptフレームワーク
  | 'js-css-library'          // JavaScript / CSSライブラリ
  | 'cdn-waf'                 // CDN / WAF / リバースプロキシ
  | 'hosting-cloud'           // ホスティング / クラウド基盤 (Vercel, Netlify, AWS ALB等)
  | 'analytics-tracking'      // アクセス解析・タグ管理 (GA, GTM, Clarity等)
  | 'security-service';       // セキュリティ・監視サービス (Sentry, reCAPTCHA等)

/**
 * 連動・推論関係の種別 (Rev.1.2 IMP-17)
 * - runtime-dependency: 実行時依存（例: Laravel → PHP, Express → Node.js）
 * - framework-dependency: フレームワーク基盤依存（例: Next.js → React, Nuxt → Vue）
 * - possible-runtime: 実行環境の候補（例: Next.js → Node.js [静的配信の可能性あり]）
 * - technology-association: 関連技術（例: 特定ホスティングとの親和性）
 */
export type ImplicationType =
  | 'runtime-dependency'
  | 'framework-dependency'
  | 'possible-runtime'
  | 'technology-association';

/**
 * 検出方式の区分 (Rev.1.2 IMP-18)
 * - direct: 直接検出（固有の観測情報あり）
 * - inferred: 連動検知（技術的依存関係から推定）
 * - associated: 関連技術（使用を裏付ける直接証拠なし）
 */
export type DetectionMethod =
  | 'direct'
  | 'inferred'
  | 'associated';

/**
 * ランタイム実行状態 (Rev.1.2 IMP-17)
 * - confirmed: 稼働確認済み（直接シグナルや必須実行環境）
 * - possible: 稼働可能性あり（静的配信等の代替構成があり得る）
 * - unknown: 稼働状態未確認（外部から実行状態を観測できない）
 * - not-applicable: 該当なし（フロントエンドライブラリ等、サーバーランタイムを持たない）
 */
export type RuntimeStatus =
  | 'confirmed'
  | 'possible'
  | 'unknown'
  | 'not-applicable';

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
 * オフライン脆弱性DB照合ステータス (Rev.2.1 IMP-06 / 5.5)
 * - Matched: 収録済み脆弱性の影響バージョン範囲に一致
 * - No Match: 収録済み技術だが該当する脆弱性なし (安全を保証するものではない)
 * - Not Covered: DB収録対象外の技術
 * - Unknown Version: バージョンが不明・パース不能
 * - Lookup Error: 照合処理エラー
 */
export type OfflineMatchStatus =
  | 'Matched'
  | 'No Match'
  | 'Not Covered'
  | 'Unknown Version'
  | 'Lookup Error';

/**
 * DB鮮度レベル (Rev.2.1 IMP-06 / 5.8)
 * - fresh: 0〜7日 (最新に近い)
 * - moderate: 8〜30日 (更新確認推奨)
 * - stale: 31日以上 (古い)
 * - unknown: 更新日不明
 */
export type DbFreshnessLevel = 'fresh' | 'moderate' | 'stale' | 'unknown';

/**
 * 脆弱性DBスナップショットメタデータ (Rev.2.1 IMP-06 / 5.4)
 */
export interface AdvisoryDbMetadata {
  schemaVersion: string;
  dataVersion: string;
  generatedAt: string;
  sources: string[];
  coverage: {
    technologies: string[];
  };
  advisoryCount: number;
  productCount: number;
  syncStatus: 'success' | 'partial' | 'failed';
}

/**
 * 脆弱性照合ステータス (Version 1.1 ADD-05 / 後方互換保持)
 */
export type AdvisoryMatchStatus =
  | 'Potentially Affected'  // 影響バージョン範囲に一致 (Matched)
  | 'Not Affected'          // 対象アドバイザリの影響範囲外 (No Match)
  | 'Needs Review'          // 追加確認が必要 (Unknown Version)
  | 'No Data'               // 該当情報が見つからない (Not Covered)
  | 'Lookup Failed';        // 情報取得に失敗 (Lookup Error)

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
  /** オフライン照合ステータス (Rev.2.1 IMP-06) */
  offlineMatchStatus?: OfflineMatchStatus;
  /** DB鮮度ステータス (Rev.2.1 IMP-06) */
  isStale?: boolean;
  dbFreshness?: DbFreshnessLevel;
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

  /** 複数技術の推定候補グループであるフラグ (例: XSRF-TOKEN による複数バックエンド候補) */
  isCandidateGroup?: boolean;
  /** 候補に含まれる個別技術名リスト */
  candidateTechnologies?: string[];

  // --- Version 1.6 追加項目 (IMP-17 / IMP-18 / IMP-19) ---
  /** 検出方式区分 ('direct': 直接検出, 'inferred': 連動検知, 'associated': 関連技術) */
  detectionMethod?: DetectionMethod;
  /** 連動・推論関係の種別 */
  implicationType?: ImplicationType;
  /** 推論元の技術名 */
  inferredFrom?: string;
  /** ランタイム実行状態 ('confirmed', 'possible', 'unknown', 'not-applicable') */
  runtimeStatus?: RuntimeStatus;
  /** 推論経路 */
  inferencePath?: string[];
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
  /** 安定ID (Rev.2.1 IMP-07 / IMP-10) */
  findingId?: string;
  /** 例外・許容ステータス (Rev.2.1 IMP-10) */
  exceptionStatus?: ExceptionStatus;
  /** 許容設定の理由 (Rev.2.1 IMP-10) */
  exceptionReason?: string;
  /** 許容設定ID (Rev.2.1 IMP-10) */
  exceptionId?: string;
}

/**
 * 差分種別 (Rev.2.1 IMP-09 / 8.2)
 */
export type DiffType =
  | 'Added'      // 新規検出
  | 'Removed'    // 未検出化
  | 'Changed'    // 値や設定の変化
  | 'Resolved'   // 問題の解消を観測
  | 'Regressed'  // 新たな問題を検出
  | 'Unchanged'  // 変化なし
  | 'Unknown';   // 比較不能

/**
 * 差分原因分類 (Rev.2.1 IMP-09 / 8.3)
 */
export type DiffCause =
  | 'site-change'            // サイト側の構成・設定変更
  | 'advisory-update'        // CVE/EOL情報の更新
  | 'rule-update'            // Web Inspectorの診断ルール変更
  | 'inspection-difference'  // 調査権限・対象範囲の違い
  | 'unknown';               // 原因不明・複数候補

/**
 * 詳細差分項目 (Rev.2.1 IMP-09)
 */
export interface DetailedDiffItem {
  id: string;
  category: 'technology' | 'security' | 'cookie' | 'coverage';
  target: string;
  diffType: DiffType;
  diffCause: DiffCause;
  causeExplanation: string;
  before: string | null;
  after: string | null;
}

/**
 * 拡張レポート比較結果 (Rev.2.1 IMP-09)
 */
export interface EnhancedReportComparison {
  reportA: InspectionReport;
  reportB: InspectionReport;
  diffItems: DetailedDiffItem[];
  summary: {
    addedCount: number;
    removedCount: number;
    changedCount: number;
    resolvedCount: number;
    regressedCount: number;
    causes: Record<DiffCause, number>;
  };
  addedTechnologies: string[];
  removedTechnologies: string[];
  versionChanges: Array<{ technology: string; before: string | null; after: string | null }>;
  newSecurityIssues: string[];
  resolvedSecurityIssues: string[];
}

/**
 * 診断項目の例外状態 (Rev.2.1 IMP-10 / 9.2)
 */
export type ExceptionStatus =
  | 'active'          // 通常表示 (例外未設定)
  | 'accepted'        // リスク許容
  | 'false-positive'  // 誤検知
  | 'muted'           // 通知抑制
  | 'expired';        // 許容期限切れ

/**
 * 診断項目の許容・除外設定エンティティ (Rev.2.1 IMP-10 / 9.3)
 */
export interface FindingException {
  id: string;               // UUID
  findingId: string;        // 安定ID (FindingIdentity / checkId / checkId:resource)
  targetUrl?: string;       // 適用対象URL (空ならホスト全体または全サイト)
  targetHost?: string;      // 適用対象ホスト名
  status: 'accepted' | 'false-positive' | 'muted';
  reason: string;           // 許容理由
  createdAt: string;        // ISO日時
  expiresAt?: string;       // 有効期限 (任意)
  ruleVersion?: string;     // 設定時のルールバージョン
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
 * Chrome API SameSiteStatus の内部正規化表現 (Rev.2.1 IMP-04)
 */
export type NormalizedSameSite =
  | 'none'
  | 'lax'
  | 'strict'
  | 'unspecified'
  | 'unknown';

/**
 * Cookie分類のあいまい性と確信度 (Rev.2.1 IMP-04)
 */
export interface CookieClassification {
  category: CookieCategory;
  confidence: 'high' | 'medium' | 'low' | 'unknown';
  matchedRules: string[];
  ambiguous: boolean;
  overridden: boolean;
}

/**
 * Cookie診断用属性情報 (※値は除外)
 */
export interface InspectedCookieInfo {
  name: string;
  value?: string;
  domain?: string;
  path?: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'no_restriction' | 'lax' | 'strict' | 'unspecified';
  normalizedSameSite?: NormalizedSameSite;
  session?: boolean;
  hostOnly?: boolean;
  partitioned?: boolean;
  partitionKey?: string | null;
  expirationDate?: number;
  hostPrefixValid?: boolean;
  securePrefixValid?: boolean;
  prefixType?: '__Secure-' | '__Host-' | '__Http-' | '__Host-Http-' | null;
  category?: CookieCategory;
  classification?: CookieClassification;
  issues?: string[];
}

/**
 * 安定ID生成用識別子 (Rev.2.1 IMP-07)
 */
export interface FindingIdentity {
  ruleId: string;
  origin: string;
  resourceKey: string;
  targetKey: string;
  scopeKey?: string;
}

/**
 * CSP取得元種別 (Rev.2.1 IMP-05)
 */
export type CSPSource = 'response-header' | 'meta';

/**
 * 独立したCSPポリシー情報 (Rev.2.1 IMP-05)
 */
export interface CSPPolicy {
  id: string;
  source: CSPSource;
  mode: 'enforce' | 'report-only';
  directives: Record<string, string[]>;
  rawValue: string;
  warnings: string[];
  observedAt: string;
}

/**
 * CSP診断指摘事項 (Rev.2.1 IMP-05)
 */
export interface CSPFinding {
  id: string;
  policyId: string;
  directive: string;
  effectiveDirective: string;
  severity: SecuritySeverity;
  confidence: ConfidenceLevel;
  description: string;
  recommendation: string;
  evidence: DetectionEvidence[];
}

/**
 * 調査状態種別 (Rev.2.1 IMP-08)
 */
export type InspectionStatus =
  | 'complete'
  | 'partial'
  | 'unavailable'
  | 'not-applicable';

/**
 * 調査範囲・完全性 (Rev.2.1 IMP-08)
 */
export interface InspectionCoverage {
  dom: InspectionStatus;
  headers: InspectionStatus;
  cookies: InspectionStatus;
  iframes: InspectionStatus;
  network: InspectionStatus;
  overallStatus: InspectionStatus;
  details?: {
    missingPermissions?: string[];
    unobservedPreScan?: boolean;
    pageNavigatedDuringScan?: boolean;
    domItemCount?: number;
    headerCount?: number;
    cookieCount?: number;
  };
}

/**
 * 検出エビデンス詳細 (Rev.2.1 IMP-08)
 */
export interface DetectionEvidence {
  id: string;
  type: string;
  source: string;
  observedValue: string;
  confidence: ConfidenceLevel;
  observedAt: string;
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
  // Rev.2.1 追加
  metaCsp?: string[];
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
 * 通信先ドメインの所属種別 (Rev.2.1 IMP-11 / 10.2)
 */
export type DomainPartyType = 'first-party' | 'third-party' | 'local';

/**
 * 外部サービスの推定カテゴリ (Rev.2.1 IMP-11 / 10.5)
 */
export type ExternalServiceCategory =
  | 'cdn'           // コンテンツ配信・静的アセット (cdnjs, unpkg, jsdelivr等)
  | 'analytics'     // アクセス解析・トラッキング (GA, GTM, Clarity, Hotjar等)
  | 'advertising'   // 広告・マーケティング配信 (DoubleClick, Ads等)
  | 'fonts'         // Webフォント (Google Fonts, Adobe Typekit等)
  | 'social'        // SNSウィジェット・埋め込み (X/Twitter, Facebook等)
  | 'api'           // 外部API・バックエンドサービス
  | 'other';        // その他

/**
 * 接続先ドメイン情報 (Rev.2.1 IMP-11)
 */
export interface ExternalConnectionItem {
  hostname: string;
  registrableDomain: string; // eTLD+1
  publicSuffix: string;
  partyType: DomainPartyType;
  category: ExternalServiceCategory;
  resourceCount: number;
  sampleUrls: string[];
}

/**
 * 外部通信先・サードパーティ総合分析 (Rev.2.1 IMP-11)
 */
export interface ExternalConnectionsAnalysis {
  totalConnections: number;
  firstPartyCount: number;
  thirdPartyCount: number;
  categoryBreakdown: Record<ExternalServiceCategory, number>;
  connections: ExternalConnectionItem[];
}

/**
 * 総合調査レポート (Version 1.2 / Rev.2.1)
 */
export interface InspectionReport {
  id: string;
  url: string;
  hostname: string;
  inspectedAt: string;
  extensionVersion: string;
  rulesVersion: string;
  advisoryDatabaseVersion?: string;
  coverage?: InspectionCoverage;
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
  cspPolicies?: CSPPolicy[];
  mixedContent: MixedContentItem[];
  /** 外部通信先・サードパーティ分析結果 (Rev.2.1 IMP-11) */
  externalConnections?: ExternalConnectionsAnalysis;
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
