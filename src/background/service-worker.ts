/**
 * Web Technology & Security Inspector
 * Service Worker (src/background/service-worker.ts) - Version 1.1.0
 * HTTPレスポンスヘッダー傍受、Cookie取得、MAIN World実行時バージョン取得、診断の統括
 */

import { getAdvisoryDbMetadata } from '../detection/advisory';
import { ALL_TECHNOLOGY_RULES, RULES_VERSION, SSR_INFERENCE_HEADER_NAMES } from '../detection/rules';
import { isValidXFrameOptions, SECURITY_HEADER_NAMES } from '../security/headers';
import { DetectionEngine } from '../detection/engine';
import { SecurityEngine } from '../security/engine';
import {
  deleteReportById,
  getAllHistoryReports,
  getHistorySummaries,
  getReportById,
  saveReportToHistory,
  clearAllHistory,
  enforceReportStorageLimits,
  sanitizeReportUrls,
} from '../storage/history';
import {
  getAllFindingExceptions,
  saveFindingException,
  deleteFindingException,
  matchFindingException,
} from '../storage/exceptions';
import { generateFindingIdFromCheck } from '../shared/identity';
import { analyzeCSPPolicies, parseCSPHeaderValues } from '../security/csp-parser';
import { analyzeExternalConnections } from '../security/domain-analyzer';
import { assessInspectionCoverage } from '../shared/coverage';
import {
  CSPPolicy,
  DomSignals,
  FindingException,
  InspectedCookieInfo,
  InspectionReport,
  NetworkSignals,
  SecurityCheckResult,
  TechnologyInstance,
} from '../shared/types';
import { formatAdvisoryRecommendation } from '../detection/advisory';

const EXTENSION_VERSION = (typeof chrome !== 'undefined' && chrome.runtime?.getManifest?.()?.version) || '1.7.0';

/**
 * キャッシュに保持するヘッダーエントリ構造
 */
export interface HeaderCacheEntry {
  url: string;
  headers: Record<string, string[]>;
  updatedAt: number;
  observed: boolean;
}

/**
 * 許可されたレスポンスヘッダー名（小文字）のホワイトリストセット
 * 検出ルール (type: 'header') の target、セキュリティ診断、および検出エンジン直接参照ヘッダーから動的に生成
 */
export const ALLOWED_RESPONSE_HEADERS: ReadonlySet<string> = new Set<string>([
  ...SECURITY_HEADER_NAMES.map((h) => h.toLowerCase()),
  ...SSR_INFERENCE_HEADER_NAMES.map((h) => h.toLowerCase()),
  ...ALL_TECHNOLOGY_RULES.flatMap((rule) =>
    rule.signals
      .filter((s) => s.type === 'header' && s.target)
      .map((s) => s.target.toLowerCase())
  ),
]);

/**
 * HTTPレスポンスヘッダーに依存するセキュリティ診断項目のプレフィックス (SPEC-01)
 */
export const HEADER_DEPENDENT_CHECK_PREFIXES = [
  'SEC-HSTS-',
  'SEC-CSP-',
  'SEC-XFO-',
  'SEC-XCTO-',
  'SEC-REF-',
  'SEC-PERM-',
  'SEC-CORS-',
  'SEC-DISC-',
] as const;

/**
 * キャッシュ保存用にURLをサニタイズ（クエリおよびフラグメントを除去し origin + pathname のみにする）
 * file:, about:, data:, blob: 等で origin が "null" になる場合や不正なURL文字列でも安全に処理
 */
export function sanitizeUrlForCache(rawUrl: string): string {
  if (!rawUrl || typeof rawUrl !== 'string') return '';
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return `${parsed.origin}${parsed.pathname}`;
    }
    // file:, about:, data:, blob: 等はクエリとハッシュを除去した href または rawUrl の先頭部を返す
    parsed.search = '';
    parsed.hash = '';
    const clean = parsed.href;
    if (clean.startsWith('null')) {
      return rawUrl.split(/[?#]/)[0] || '';
    }
    return clean;
  } catch {
    return rawUrl.split(/[?#]/)[0] || rawUrl;
  }
}

/**
 * レスポンスヘッダーから許可リストに含まれるヘッダーのみを抽出し、小文字キーで正規化する
 * 許可されないヘッダー（Set-Cookie, Authorization, Location 等）はキーごと破棄する
 */
export function filterAndSanitizeHeaders(
  headers: Record<string, string[]> | chrome.webRequest.HttpHeader[]
): Record<string, string[]> {
  const result: Record<string, string[]> = {};

  if (Array.isArray(headers)) {
    for (const h of headers) {
      if (!h.name) continue;
      const lowerName = h.name.toLowerCase();
      if (ALLOWED_RESPONSE_HEADERS.has(lowerName)) {
        if (!result[lowerName]) {
          result[lowerName] = [];
        }
        if (h.value) {
          result[lowerName].push(h.value);
        }
      }
    }
  } else if (headers && typeof headers === 'object') {
    for (const [key, value] of Object.entries(headers)) {
      const lowerName = key.toLowerCase();
      if (ALLOWED_RESPONSE_HEADERS.has(lowerName)) {
        const valArr = Array.isArray(value) ? value : [String(value)];
        result[lowerName] = valArr;
      }
    }
  }

  return result;
}

/**
 * sessionストレージ等から復元したキャッシュエントリを再検証・サニタイズする
 */
export function sanitizeRestoredHeaderEntry(entry: any): HeaderCacheEntry {
  const safeUrl = sanitizeUrlForCache(entry?.url || '');
  const safeHeaders = filterAndSanitizeHeaders(entry?.headers || {});
  return {
    url: safeUrl,
    headers: safeHeaders,
    updatedAt: typeof entry?.updatedAt === 'number' ? entry.updatedAt : Date.now(),
    observed: true,
  };
}

// タブIDごとのレスポンスヘッダーキャッシュ (インメモリ + chrome.storage.session によるSWスリープ永続化)
// 容量上限対策: 最大保持タブ数
const MAX_HEADER_CACHE_TABS = 100;
const headersCache = new Map<number, HeaderCacheEntry>();

// Service Worker起動時のセッションストレージ復元Promise（初期化競合防止）
let restoreHeadersPromise: Promise<void> | null = null;

async function ensureHeadersRestored(): Promise<void> {
  if (!restoreHeadersPromise) {
    restoreHeadersPromise = (async () => {
      try {
        if (chrome.storage?.session) {
          const allData = await chrome.storage.session.get(null);
          const restoredTabIds: number[] = [];

          for (const [key, value] of Object.entries(allData)) {
            if (key.startsWith('tab_headers_')) {
              const tabId = parseInt(key.replace('tab_headers_', ''), 10);
              if (!isNaN(tabId) && value && (value as any).headers) {
                const sanitized = sanitizeRestoredHeaderEntry(value);
                headersCache.set(tabId, sanitized);
                restoredTabIds.push(tabId);
              }
            }
          }

          // 生存タブの確認と孤立セッションデータの掃除
          if (chrome.tabs?.query && restoredTabIds.length > 0) {
            try {
              const activeTabs = await chrome.tabs.query({});
              const activeTabIdSet = new Set(activeTabs.map((t) => t.id).filter(Boolean));
              const staleKeys: string[] = [];

              for (const tabId of restoredTabIds) {
                if (!activeTabIdSet.has(tabId)) {
                  headersCache.delete(tabId);
                  staleKeys.push(`tab_headers_${tabId}`);
                }
              }

              if (staleKeys.length > 0) {
                await chrome.storage.session.remove(staleKeys);
              }
            } catch {
              // tabs.query 権限/タイミング例外の安全なフォールバック
            }
          }
        }
      } catch (e) {
        console.warn('Failed to restore headers from session storage:', e);
      }
    })();
  }
  return restoreHeadersPromise;
}

// SWロード時に即座に復元を開始
if (typeof chrome !== 'undefined') {
  ensureHeadersRestored().catch(() => {});
}

async function saveHeadersCache(
  tabId: number,
  data: { url: string; headers: Record<string, string[]>; observed?: boolean }
): Promise<void> {
  const entry: HeaderCacheEntry = {
    url: sanitizeUrlForCache(data.url),
    headers: filterAndSanitizeHeaders(data.headers),
    updatedAt: Date.now(),
    observed: data.observed ?? true,
  };

  // 既に存在する場合は再登録（Map末尾に移動してLRU順序を維持）
  headersCache.delete(tabId);
  headersCache.set(tabId, entry);

  // 容量上限（LRU）の適用
  if (headersCache.size > MAX_HEADER_CACHE_TABS) {
    const oldestTabId = headersCache.keys().next().value;
    if (oldestTabId !== undefined) {
      headersCache.delete(oldestTabId);
      if (chrome.storage?.session) {
        chrome.storage.session.remove(`tab_headers_${oldestTabId}`).catch(() => {});
      }
    }
  }

  try {
    if (chrome.storage?.session) {
      await chrome.storage.session.set({ [`tab_headers_${tabId}`]: entry });
    }
  } catch {
    // セッションストレージ例外防止
  }
}

async function getCachedHeaders(tabId: number): Promise<HeaderCacheEntry | undefined> {
  // 初期化復元を待機
  await ensureHeadersRestored();

  if (headersCache.has(tabId)) {
    return headersCache.get(tabId);
  }
  try {
    if (chrome.storage?.session) {
      const key = `tab_headers_${tabId}`;
      const res = await chrome.storage.session.get(key);
      if (res && res[key]) {
        const sanitized = sanitizeRestoredHeaderEntry(res[key]);
        headersCache.set(tabId, sanitized);
        return sanitized;
      }
    }
  } catch {
    // セッションストレージ例外防止
  }
  return undefined;
}

// 1. webRequest API によるHTTPレスポンスヘッダーの収集とナビゲーション時クリーンアップ
try {
  if (typeof chrome !== 'undefined' && chrome.webRequest) {
    // ナビゲーション開始時に前ページの古いヘッダーをリセット
    if (chrome.webRequest.onBeforeRequest) {
      chrome.webRequest.onBeforeRequest.addListener(
        (details) => {
          if (details.tabId > 0 && details.type === 'main_frame') {
            headersCache.delete(details.tabId);
            if (chrome.storage?.session) {
              chrome.storage.session.remove(`tab_headers_${details.tabId}`).catch(() => {});
            }
          }
        },
        { urls: ['<all_urls>'] }
      );
    }

    // レスポンスヘッダー受信時の保存（extraHeadersを外し、許可リスト方式で取り込み）
    if (chrome.webRequest.onHeadersReceived) {
      chrome.webRequest.onHeadersReceived.addListener(
        (details) => {
          if (details.tabId > 0 && details.type === 'main_frame') {
            const headerMap = filterAndSanitizeHeaders(details.responseHeaders || []);
            saveHeadersCache(details.tabId, {
              url: details.url,
              headers: headerMap,
              observed: true,
            });
          }
        },
        { urls: ['<all_urls>'] },
        ['responseHeaders']
      );
    }
  }
} catch (e) {
  console.warn('webRequest registration warning:', e);
}

if (typeof chrome !== 'undefined' && chrome.tabs?.onRemoved) {
  chrome.tabs.onRemoved.addListener((tabId) => {
    headersCache.delete(tabId);
    try {
      if (chrome.storage?.session) {
        chrome.storage.session.remove(`tab_headers_${tabId}`).catch(() => {});
      }
    } catch {
      // 例外防止
    }
  });
}

// プリレンダリング対応: removedTabId のキャッシュを addedTabId へ移行 (SPEC-16)
if (typeof chrome !== 'undefined' && chrome.tabs?.onReplaced) {
  chrome.tabs.onReplaced.addListener(async (addedTabId, removedTabId) => {
    try {
      await ensureHeadersRestored();
      const entry = headersCache.get(removedTabId);
      if (entry) {
        headersCache.delete(removedTabId);
        headersCache.set(addedTabId, entry);
      }
      if (chrome.storage?.session) {
        const removedKey = `tab_headers_${removedTabId}`;
        const addedKey = `tab_headers_${addedTabId}`;
        const sessionData = await chrome.storage.session.get(removedKey);
        const savedEntry = sessionData?.[removedKey] || entry;
        if (savedEntry) {
          await chrome.storage.session.set({ [addedKey]: savedEntry });
          await chrome.storage.session.remove(removedKey);
        }
      }
    } catch (e) {
      console.warn('tabs.onReplaced header cache migration warning:', e);
    }
  });
}

/**
 * Cookie属性の取得 (値は除外)
 */
async function getInspectedCookies(url: string): Promise<InspectedCookieInfo[]> {
  try {
    const rawCookies = await chrome.cookies.getAll({ url });
    return rawCookies.map((c: any) => ({
      name: c.name,
      domain: c.domain,
      path: c.path,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite as 'no_restriction' | 'lax' | 'strict' | 'unspecified',
      session: c.session,
      hostOnly: c.hostOnly,
      partitioned: Boolean(c.partitionKey),
      partitionKey: c.partitionKey?.topLevelSite || (typeof c.partitionKey === 'string' ? c.partitionKey : null),
      expirationDate: c.expirationDate,
      issues: [],
    }));
  } catch (error) {
    console.warn('Cookie retrieval warning:', error);
    return [];
  }
}

/**
 * Content ScriptからDOM・CSSシグナルを取得する
 */
async function fetchDomSignals(tabId: number, url: string): Promise<DomSignals> {
  try {
    const response = await chrome.tabs.sendMessage(tabId, { type: 'EXTRACT_DOM_SIGNALS' });
    if (response) return response as DomSignals;
  } catch {
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId },
        files: ['content/content-script.js'],
      });
      if (results && results.length > 0) {
        const response = await chrome.tabs.sendMessage(tabId, { type: 'EXTRACT_DOM_SIGNALS' });
        if (response) return response as DomSignals;
      }
    } catch (e) {
      console.warn('Content script injection failed:', e);
    }
  }

  return {
    url,
    title: '',
    metaTags: [],
    scriptUrls: [],
    linkUrls: [],
    domMarkers: [],
    htmlSnippets: [],
    mixedContent: [],
    cookiesFromDocument: [],
    cssAssets: [],
  };
}

/**
 * MAIN World（ページの実行コンテキスト）からJavaScriptライブラリの実行時バージョンおよびフレームワーク内部プロパティを安全に取得する (ADD-01)
 */
async function fetchRuntimeVersions(tabId: number): Promise<{
  versions: Record<string, string | null>;
  frameworkMarkers: string[];
}> {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      world: 'MAIN',
      func: () => {
        const w = window as any;
        const versions: Record<string, string | null> = {
          jquery: w.jQuery?.fn?.jquery ?? null,
          bootstrap4: w.jQuery?.fn?.modal?.Constructor?.VERSION ?? null,
          bootstrap5: w.bootstrap?.Modal?.VERSION ?? null,
          vue: w.Vue?.version ?? null,
          // Underscore.js との誤認防止: window._.VERSION は Underscore にも存在するため、cloneDeep 関数の有無で判別 (T07 / DOC-02)
          lodash:
            typeof w._?.cloneDeep === 'function' && typeof w._?.VERSION === 'string'
              ? w._.VERSION
              : null,
          moment: w.moment?.version ?? null,
          angularjs: w.angular?.version?.full ?? null,
        };

        const frameworkMarkers: string[] = [];

        // React 18/19: ルート要素の __reactContainer$ または __reactFiber$ を探査
        try {
          const candidateNodes = [
            document.getElementById('root'),
            document.getElementById('app'),
            document.getElementById('__next'),
            document.body,
            ...Array.from(document.querySelectorAll('div[id], main, #root > *, body > *')).slice(0, 200),
          ];
          for (const node of candidateNodes) {
            if (!node) continue;
            const keys = Object.keys(node);
            if (keys.some((k) => k.startsWith('__reactContainer$') || k.startsWith('__reactFiber$'))) {
              frameworkMarkers.push('__reactContainer$');
              break;
            }
          }
        } catch {
          // 例外防止
        }

        // Vue 3: ルート要素の __vue_app__ を探査
        try {
          const candidateNodes = [
            document.getElementById('app'),
            document.getElementById('root'),
            document.getElementById('__nuxt'),
            document.body,
            ...Array.from(document.querySelectorAll('div[id], main, [data-v-app]')).slice(0, 200),
          ];
          for (const node of candidateNodes) {
            if (!node) continue;
            if ((node as any).__vue_app__) {
              frameworkMarkers.push('__vue_app__');
              break;
            }
          }
        } catch {
          // 例外防止
        }

        return { versions, frameworkMarkers };
      },
    });

    if (results && results[0]?.result) {
      return results[0].result as {
        versions: Record<string, string | null>;
        frameworkMarkers: string[];
      };
    }
  } catch (e) {
    console.warn('Runtime version extraction skipped (chrome:// or restricted page):', e);
  }

  return { versions: {}, frameworkMarkers: [] };
}

/**
 * 調査処理の依存関係インターフェース (テスト容易性とモック注入用)
 */
export interface InspectionDependencies {
  tab: { id: number; url: string };
  fetchDomSignals: (tabId: number, url: string) => Promise<DomSignals>;
  fetchRuntimeVersions: (tabId: number) => Promise<{ versions: Record<string, string | null>; frameworkMarkers: string[] }>;
  getCachedHeaders: (tabId: number) => Promise<{ url: string; headers: Record<string, string[]>; observed?: boolean } | undefined>;
  getInspectedCookies: (url: string) => Promise<InspectedCookieInfo[]>;
  getAllFindingExceptions: () => Promise<FindingException[]>;
  saveReport?: (report: InspectionReport) => Promise<void>;
  updateBadge?: (count: number, isWarning: boolean, tabId: number) => void;
  hasWebRequestPermission?: boolean;
}

/**
 * 調査処理のコアロジック (外部chrome.*依存を注入可能)
 */
export async function executeInspection(deps: InspectionDependencies): Promise<InspectionReport> {
  const url = deps.tab.url;
  const currentTabId = deps.tab.id;

  if (url.startsWith('chrome://') || url.startsWith('edge://') || url.startsWith('about:')) {
    throw new Error('ブラウザの内部管理ページは調査対象外です。一般のWebページで実行してください。');
  }

  let hostname = '';
  try {
    hostname = new URL(url).hostname;
  } catch {
    hostname = url;
  }

  // 1. DOM・CSS情報の取得
  const domSignals = await deps.fetchDomSignals(currentTabId, url);

  // 2. JavaScript実行時バージョンおよび内部フレームワークマーカーの取得 (MAIN World)
  const runtimeInfo = await deps.fetchRuntimeVersions(currentTabId);

  // IMPL-04: MAIN world から取得した実行時バージョンの検証（ページによる偽装や肥大化を防止）
  const runtimeVersionPattern = /^\d+(\.\d+){0,3}([-+.][0-9A-Za-z.-]{1,16})?$/;
  const validatedVersions: Record<string, string | null> = {};
  if (runtimeInfo && runtimeInfo.versions && typeof runtimeInfo.versions === 'object') {
    for (const [key, val] of Object.entries(runtimeInfo.versions)) {
      if (
        typeof val === 'string' &&
        val.length >= 1 &&
        val.length <= 32 &&
        runtimeVersionPattern.test(val)
      ) {
        validatedVersions[key] = val;
      } else {
        validatedVersions[key] = null;
      }
    }
  }
  domSignals.runtimeVersions = validatedVersions;

  // IMPL-04: 既知のフレームワークマーカーのみ許可
  const ALLOWED_FRAMEWORK_MARKERS = new Set(['__reactContainer$', '__vue_app__']);
  const validatedMarkers = Array.isArray(runtimeInfo?.frameworkMarkers)
    ? runtimeInfo.frameworkMarkers.filter(
        (m): m is string => typeof m === 'string' && ALLOWED_FRAMEWORK_MARKERS.has(m)
      )
    : [];
  if (validatedMarkers.length > 0) {
    domSignals.domMarkers = [...(domSignals.domMarkers || []), ...validatedMarkers];
  }

  // 3. HTTPヘッダー・Cookieの取得 (IMPL-02: URL照合)
  const cachedData = await deps.getCachedHeaders(currentTabId);
  let isOriginMatch = false;
  if (cachedData?.url) {
    try {
      const cachedOrigin = new URL(cachedData.url).origin;
      const tabOrigin = new URL(url).origin;
      isOriginMatch = cachedOrigin === tabOrigin;
    } catch {
      isOriginMatch = false;
    }
  }

  const rawHeadersObserved = Boolean(cachedData?.observed ?? cachedData);
  const headersObserved = rawHeadersObserved && isOriginMatch;
  const responseHeaders = headersObserved ? (cachedData?.headers || {}) : {};
  const cookies = await deps.getInspectedCookies(url);

  const networkSignals: NetworkSignals = {
    url,
    responseHeaders,
    cookies,
  };

  // 4. 拡張技術検出エンジンの実行 (EOL & CVE照合含む)
  const detectionEngine = new DetectionEngine();
  const technologies = detectionEngine.detect({
    url,
    dom: domSignals,
    network: networkSignals,
    runtimeVersions: runtimeInfo.versions,
  });

  // 5. セキュリティ診断エンジンの実行
  const securityEngine = new SecurityEngine();
  const { checks: baseSecurityChecks, cookies: evaluatedCookies } = securityEngine.evaluate({
    url,
    dom: domSignals,
    network: networkSignals,
  });

  // 5.1 複数CSPポリシーの独立保持と詳細評価 (Rev.2.1 IMP-05 / v1.7.0 T06: 配列要素・カンマ区切り・meta Report-Only 分離)
  const cspPolicies: CSPPolicy[] = [
    ...parseCSPHeaderValues(responseHeaders['content-security-policy'], 'response-header', 'enforce'),
    ...parseCSPHeaderValues(
      responseHeaders['content-security-policy-report-only'],
      'response-header',
      'report-only'
    ),
    ...parseCSPHeaderValues(domSignals.metaCsp, 'meta', 'enforce'),
    ...parseCSPHeaderValues(domSignals.metaCspReportOnly, 'meta', 'report-only'),
  ];

  if (cspPolicies.length > 0) {
    const hasXfo = isValidXFrameOptions(responseHeaders['x-frame-options']?.join(', '));
    const { results: advancedCspChecks } = analyzeCSPPolicies(cspPolicies, url, hasXfo);
    // 既存のCSP項目 (SEC-CSP-*) を詳細解析結果に置き換え
    const nonCspChecks = baseSecurityChecks.filter((c) => !c.checkId.startsWith('SEC-CSP-'));
    baseSecurityChecks.length = 0;
    baseSecurityChecks.push(...nonCspChecks, ...advancedCspChecks);
  }

  // SPEC-01: ヘッダー未観測時はヘッダー依存の診断を「未観測」とする
  if (!headersObserved) {
    const hasMetaCsp = Boolean(domSignals.metaCsp && domSignals.metaCsp.length > 0);
    for (const c of baseSecurityChecks) {
      const isHeaderDependent = HEADER_DEPENDENT_CHECK_PREFIXES.some((prefix) =>
        c.checkId.startsWith(prefix)
      );
      if (isHeaderDependent) {
        // meta CSP が存在する場合の CSP 解析結果、または meta Report-Only の info 注記は meta 由来として維持
        if (c.checkId.startsWith('SEC-CSP-') && (hasMetaCsp || c.checkId === 'SEC-CSP-META-RO')) {
          continue;
        }
        c.status = 'unknown';
        c.severity = 'info';
        c.observed = 'HTTPレスポンスヘッダー未観測';
        c.description =
          '拡張機能がこのページのレスポンスヘッダーを観測できませんでした。ページを再読み込みしてから再調査してください。';
        c.recommendation = 'ページを再読み込み（リロード）してから再調査してください。';
      }
    }
  }

  // 6. ライブラリセキュリティ診断項目の生成 (EOL, CVE, バージョン不一致) (v1.7.0 T08 / SPEC-10: インスタンス単位)
  const librarySecurityChecks: SecurityCheckResult[] = [];
  let eolCount = 0;
  let vulnerableLibraryCount = 0;
  let mismatchCount = 0;

  for (const tech of technologies) {
    const instances: TechnologyInstance[] =
      tech.instances && tech.instances.length > 0
        ? tech.instances
        : [
            {
              version: tech.version,
              evidence: tech.evidence,
              advisories: tech.advisories || [],
              eol: tech.eolInfo || {
                status: tech.supportStatus || 'Unknown',
                eolDate: tech.eolDate ?? null,
                source: 'Internal Policy',
                recommendation: '現行のサポート対象バージョンへの移行を検討してください。',
              },
              eolInfo: tech.eolInfo,
              supportStatus: tech.supportStatus,
              eolDate: tech.eolDate,
              advisoryMatchStatus: tech.advisoryMatchStatus,
              maxCvss: tech.maxCvss,
            },
          ];

    let techEolCheckIdx = 0;
    let techCveCheckIdx = 0;

    for (const inst of instances) {
      const instSupportStatus = inst.supportStatus ?? inst.eol?.status ?? tech.supportStatus;
      const instEolInfo = inst.eol ?? inst.eolInfo ?? tech.eolInfo;
      const instEolDate = inst.eolDate ?? instEolInfo?.eolDate ?? tech.eolDate;
      const instVersion = inst.version;

      // EOL判定のセキュリティチェック追加 (インスタンスごと)
      if (instSupportStatus === 'EOL') {
        eolCount++;
        const eolCheckId =
          techEolCheckIdx === 0
            ? `SEC-EOL-${tech.technology.toUpperCase()}`
            : `SEC-EOL-${tech.technology.toUpperCase()}-${instVersion || techEolCheckIdx + 1}`;
        techEolCheckIdx++;

        const eolName =
          instances.length > 1 && instVersion
            ? `${tech.technology} (${instVersion}) サポート終了 (EOL)`
            : `${tech.technology} サポート終了 (EOL)`;
        const eolFindingId = `${generateFindingIdFromCheck(
          eolCheckId,
          url,
          `${tech.technology}:${instVersion || 'unknown'}:eol`
        )}${instVersion ? `_${instVersion}` : ''}`;

        librarySecurityChecks.push({
          checkId: eolCheckId,
          category: 'library-security',
          name: eolName,
          status: 'warning',
          severity: 'medium',
          observed: `検出バージョン: ${instVersion || '不明'} (EOL日: ${instEolDate || '過去'})`,
          description: `${tech.technology}${instVersion ? ` (${instVersion})` : ''} は公式サポートが終了しています。新たな脆弱性が発見されてもセキュリティパッチが提供されません。`,
          recommendation: instEolInfo?.recommendation || '現行のサポート対象バージョンへの移行を検討してください。',
          referenceUrls: instEolInfo?.sourceUrl ? [instEolInfo.sourceUrl] : [],
          scope: url,
          findingId: eolFindingId,
        });
      }

      // CVE該当判定のセキュリティチェック追加 (v1.7.0 T03 / SPEC-13 & T08 / SPEC-10: インスタンスごと)
      const instAdvisories = inst.advisories || [];
      const instMatchStatus =
        inst.advisoryMatchStatus ??
        (instAdvisories.length > 0 ? 'Potentially Affected' : tech.advisoryMatchStatus);

      if (instMatchStatus === 'Potentially Affected' && instAdvisories.length > 0) {
        vulnerableLibraryCount++;
        const topAdvisory = instAdvisories[0];
        const severityRank: Record<string, number> = {
          critical: 4,
          high: 3,
          medium: 2,
          low: 1,
        };
        let highestSeverity: 'critical' | 'high' | 'medium' | 'low' = 'medium';
        let highestRank = 0;
        const hasKev = instAdvisories.some((a) => a.kev === true);

        for (const adv of instAdvisories) {
          const s = String(adv.severity || '').toLowerCase();
          const r = severityRank[s] ?? 0;
          if (r > highestRank) {
            highestRank = r;
            highestSeverity = s as 'critical' | 'high' | 'medium' | 'low';
          }
        }

        const instMaxCvss = inst.maxCvss ?? tech.maxCvss;
        if (highestRank === 0 && typeof instMaxCvss === 'number') {
          if (instMaxCvss >= 9.0) highestSeverity = 'critical';
          else if (instMaxCvss >= 7.0) highestSeverity = 'high';
          else if (instMaxCvss >= 4.0) highestSeverity = 'medium';
          else highestSeverity = 'low';
        }

        const severity: 'critical' | 'high' | 'medium' | 'low' = hasKev
          ? 'critical'
          : highestSeverity;

        const isEol = instSupportStatus === 'EOL';

        const cveRecommendation = formatAdvisoryRecommendation(instVersion, instAdvisories, {
          isEol,
          technologyName: tech.technology,
        });

        const kevNote = hasKev ? ' / 悪用確認済み（CISA KEV）' : '';
        const kevDescSuffix = hasKev ? '（悪用確認済み（CISA KEV）の脆弱性を含みます）' : '';

        const cveCheckId =
          techCveCheckIdx === 0
            ? `SEC-CVE-${tech.technology.toUpperCase()}`
            : `SEC-CVE-${tech.technology.toUpperCase()}-${instVersion || techCveCheckIdx + 1}`;
        techCveCheckIdx++;

        const cveName =
          instances.length > 1 && instVersion
            ? `${tech.technology} (${instVersion}) 既知脆弱性 (${instAdvisories.map((a) => a.id).join(', ')})`
            : `${tech.technology} 既知脆弱性 (${instAdvisories.map((a) => a.id).join(', ')})`;
        const cveFindingId = `${generateFindingIdFromCheck(
          cveCheckId,
          url,
          `${tech.technology}:${instVersion || 'unknown'}:cve`
        )}${instVersion ? `_${instVersion}` : ''}`;

        librarySecurityChecks.push({
          checkId: cveCheckId,
          category: 'library-security',
          name: cveName,
          status: 'fail',
          severity,
          observed: `バージョン ${instVersion} に該当する既知脆弱性 ${instAdvisories.length} 件 (重大度: ${severity.toUpperCase()}${kevNote})`,
          description: `${topAdvisory.summary}${kevDescSuffix}`,
          recommendation: cveRecommendation,
          referenceUrls: topAdvisory.referenceUrls,
          scope: url,
          findingId: cveFindingId,
        });
      }
    }

    // バージョン不一致判定のセキュリティチェック追加
    if (tech.versionIntegrity && tech.versionIntegrity.status === 'mismatch') {
      mismatchCount++;
      librarySecurityChecks.push({
        checkId: `SEC-MISMATCH-${tech.technology.toUpperCase()}`,
        category: 'library-security',
        name: `${tech.technology} CSS/JSバージョン不一致`,
        status: 'warning',
        severity: 'low',
        observed: `CSS: ${tech.versionIntegrity.cssVersion} / JS: ${tech.versionIntegrity.jsVersion}`,
        description: tech.versionIntegrity.detail,
        recommendation: tech.versionIntegrity.recommendation,
        referenceUrls: [],
        scope: url,
      });
    }
  }

  const allSecurityChecks = [...librarySecurityChecks, ...baseSecurityChecks];

  // 6.1 安定ID (FindingId) の付与と許容・除外設定 (FindingException) の照合 (Rev.2.1 IMP-10 / v1.7.0 T10 IMPL-09)
  const exceptions = await deps.getAllFindingExceptions();
  for (const c of allSecurityChecks) {
    if (!c.findingId) {
      c.findingId = generateFindingIdFromCheck(c.checkId, url);
    }
    const exMatch = matchFindingException(c.findingId, url, exceptions, {
      checkId: c.checkId,
      name: c.name,
    });
    c.exceptionStatus = exMatch.status;
    if (exMatch.exception) {
      c.exceptionReason = exMatch.exception.reason;
      c.exceptionId = exMatch.exception.id;
    }
  }

  // 7. 統計集計 (許容・除外設定された項目は要確認カウントから除外)
  const requiresAttentionCount = allSecurityChecks.filter((c) => {
    const isIssue = c.status === 'warning' || c.status === 'fail';
    if (!isIssue) return false;
    const isAccepted =
      c.exceptionStatus === 'accepted' ||
      c.exceptionStatus === 'false-positive' ||
      c.exceptionStatus === 'muted';
    return !isAccepted;
  }).length;

  const securityFindings = {
    critical: allSecurityChecks.filter((c) => c.severity === 'critical').length,
    high: allSecurityChecks.filter((c) => c.severity === 'high').length,
    medium: allSecurityChecks.filter((c) => c.severity === 'medium').length,
    low: allSecurityChecks.filter((c) => c.severity === 'low').length,
    info: allSecurityChecks.filter((c) => c.severity === 'info').length,
    unknown: allSecurityChecks.filter((c) => c.severity === 'unknown').length,
  };

  const isHttps = url.toLowerCase().startsWith('https://');

  // 8. 調査完全性評価 (Rev.2.1 IMP-08)
  const coverage = assessInspectionCoverage({
    hasDom: Boolean(domSignals.title || domSignals.metaTags.length > 0 || domSignals.scriptUrls.length > 0),
    hasHeaders: headersObserved,
    hasCookiesPermission: true,
    cookieCount: cookies.length,
    hasWebRequestPermission: deps.hasWebRequestPermission ?? true,
    unobservedPreScan: !headersObserved,
    domItemCount: domSignals.metaTags.length + domSignals.scriptUrls.length,
    headerCount: Object.keys(responseHeaders).length,
  });

  // 8.1 外部通信先・サードパーティドメイン分析 (Rev.2.1 IMP-11)
  const resourceUrls = [
    ...domSignals.scriptUrls,
    ...domSignals.linkUrls.map((l) => l.href),
    ...domSignals.mixedContent.map((m) => m.url),
    ...domSignals.cssAssets.map((c) => c.href),
  ];
  const externalConnections = analyzeExternalConnections(url, resourceUrls);

  const advMeta = getAdvisoryDbMetadata();
  let advDbVersion = advMeta.dataVersion || '2026.10';
  if (/^\d{8}$/.test(advDbVersion)) {
    advDbVersion = `${advDbVersion.slice(0, 4)}-${advDbVersion.slice(4, 6)}-${advDbVersion.slice(6, 8)}`;
  } else if (advMeta.generatedAt) {
    advDbVersion = advMeta.generatedAt.slice(0, 10);
  }

  const rawReport: InspectionReport = {
    id: `rep_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
    url,
    hostname,
    inspectedAt: new Date().toISOString(),
    extensionVersion: EXTENSION_VERSION,
    rulesVersion: RULES_VERSION,
    advisoryDatabaseVersion: advDbVersion,
    coverage,
    summary: {
      totalTechnologies: technologies.length,
      requiresAttentionCount,
      securityFindings,
      librarySecurity: {
        eolCount,
        vulnerableLibraryCount,
        mismatchCount,
      },
      isHttps,
      mixedContentCount: domSignals.mixedContent.length,
    },
    technologies,
    securityChecks: allSecurityChecks,
    cookies: evaluatedCookies,
    cspPolicies,
    mixedContent: domSignals.mixedContent,
    externalConnections,
  };

  // URLマスク（クエリ・フラグメント除去）および単一レポートサイズ・evidence上限の適用 (IMPL-06, IMPL-07)
  const report = enforceReportStorageLimits(sanitizeReportUrls(rawReport));

  // 8. 履歴保存（失敗しても調査自体は失敗させず、画面への通知情報を付与する: IMPL-06）
  if (deps.saveReport) {
    try {
      await deps.saveReport(report);
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      report.historySaveFailed = true;
      report.storageWarning = `履歴の保存に失敗しました（${errMsg || 'ストレージ書き込みエラー'}）。今回の調査結果は表示されていますが、履歴には残っていません。`;
    }
  }

  // 9. バッジ更新
  if (deps.updateBadge) {
    deps.updateBadge(
      requiresAttentionCount > 0 ? requiresAttentionCount : technologies.length,
      requiresAttentionCount > 0,
      currentTabId
    );
  }

  return report;
}

/**
 * 総合調査を実行するメインコントローラー (Version 1.1)
 */
async function runInspection(tabId?: number): Promise<InspectionReport> {
  let targetTab: chrome.tabs.Tab | undefined;

  if (tabId) {
    targetTab = await chrome.tabs.get(tabId);
  } else {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    targetTab = tabs[0];
  }

  if (!targetTab || !targetTab.url || !targetTab.id) {
    throw new Error('調査対象のアクティブなタブが見つかりませんでした。');
  }

  return executeInspection({
    tab: { id: targetTab.id, url: targetTab.url },
    fetchDomSignals,
    fetchRuntimeVersions,
    getCachedHeaders,
    getInspectedCookies,
    getAllFindingExceptions,
    saveReport: saveReportToHistory,
    updateBadge: (count, isWarning, currentTabId) => {
      if (typeof chrome !== 'undefined' && chrome.action) {
        chrome.action.setBadgeText({ text: String(count), tabId: currentTabId });
        chrome.action.setBadgeBackgroundColor({
          color: isWarning ? '#E53E3E' : '#3182CE',
          tabId: currentTabId,
        });
      }
    },
    hasWebRequestPermission: typeof chrome !== 'undefined' && Boolean(chrome.webRequest),
  });
}

// E2Eテストおよび内部検証用グローバル公開
if (typeof globalThis !== 'undefined') {
  (globalThis as any).runInspection = runInspection;
}

const PRIVILEGED_MESSAGE_TYPES = new Set([
  'INSPECT_CURRENT_TAB',
  'GET_HISTORY',
  'GET_ALL_REPORTS',
  'GET_REPORT_BY_ID',
  'DELETE_HISTORY_ITEM',
  'CLEAR_HISTORY',
  'GET_FINDING_EXCEPTIONS',
  'SAVE_FINDING_EXCEPTION',
  'DELETE_FINDING_EXCEPTION',
]);

/**
 * メッセージ送信元が拡張機能自身の特権ページ（popup / dashboard 等）であるか検証する (v1.7.0 T10 / IMPL-05)
 * - sender.id === chrome.runtime.id かつ sender.url が拡張機能のページ (chrome-extension://<id>/...) のときのみ許可
 * - content script (sender.url が https:// 等) からの特権メッセージを拒否する
 */
export function isPrivilegedExtensionSender(
  sender?: chrome.runtime.MessageSender
): boolean {
  if (!sender || typeof sender !== 'object') {
    return false;
  }
  const runtimeId =
    typeof chrome !== 'undefined' && typeof chrome.runtime?.id === 'string' && chrome.runtime.id
      ? chrome.runtime.id
      : undefined;

  if (runtimeId) {
    if (sender.id !== runtimeId) {
      return false;
    }
  } else if (typeof sender.id !== 'string' || !sender.id) {
    return false;
  }

  if (typeof sender.url !== 'string' || !sender.url) {
    return false;
  }

  const expectedId = runtimeId || sender.id;
  const expectedPrefix = `chrome-extension://${expectedId}/`;
  const runtimeBaseUrl =
    typeof chrome !== 'undefined' && typeof chrome.runtime?.getURL === 'function'
      ? chrome.runtime.getURL('')
      : expectedPrefix;

  if (!sender.url.startsWith(expectedPrefix) && !sender.url.startsWith(runtimeBaseUrl)) {
    return false;
  }

  return true;
}

/**
 * 受信したメッセージの型と必須フィールドの形式を検証する (v1.7.0 T10 / IMPL-05)
 */
export function validateRuntimeMessage(
  message: unknown
): { valid: boolean; knownType: boolean; error?: string } {
  if (!message || typeof message !== 'object') {
    return { valid: false, knownType: false, error: 'Message must be an object' };
  }

  const msg = message as Record<string, unknown>;
  if (typeof msg.type !== 'string' || !PRIVILEGED_MESSAGE_TYPES.has(msg.type)) {
    return { valid: false, knownType: false, error: 'Unknown message type' };
  }

  switch (msg.type) {
    case 'INSPECT_CURRENT_TAB': {
      if (
        msg.tabId !== undefined &&
        (typeof msg.tabId !== 'number' || !Number.isInteger(msg.tabId) || msg.tabId < 0)
      ) {
        return { valid: false, knownType: true, error: 'Invalid tabId' };
      }
      return { valid: true, knownType: true };
    }
    case 'GET_HISTORY':
    case 'GET_ALL_REPORTS':
    case 'CLEAR_HISTORY':
    case 'GET_FINDING_EXCEPTIONS':
      return { valid: true, knownType: true };
    case 'GET_REPORT_BY_ID':
    case 'DELETE_HISTORY_ITEM':
    case 'DELETE_FINDING_EXCEPTION': {
      if (typeof msg.id !== 'string' || msg.id.trim().length === 0 || msg.id.length > 256) {
        return { valid: false, knownType: true, error: 'Invalid id' };
      }
      return { valid: true, knownType: true };
    }
    case 'SAVE_FINDING_EXCEPTION': {
      if (!msg.exception || typeof msg.exception !== 'object') {
        return { valid: false, knownType: true, error: 'Missing exception object' };
      }
      const ex = msg.exception as Record<string, unknown>;
      const validStatuses = new Set(['accepted', 'false-positive', 'muted']);
      if (
        typeof ex.id !== 'string' ||
        ex.id.trim().length === 0 ||
        ex.id.length > 128 ||
        typeof ex.findingId !== 'string' ||
        ex.findingId.trim().length === 0 ||
        ex.findingId.length > 256 ||
        typeof ex.status !== 'string' ||
        !validStatuses.has(ex.status) ||
        typeof ex.reason !== 'string' ||
        ex.reason.length > 2000 ||
        typeof ex.createdAt !== 'string' ||
        ex.createdAt.trim().length === 0
      ) {
        return { valid: false, knownType: true, error: 'Invalid exception fields' };
      }
      if (ex.targetUrl !== undefined && (typeof ex.targetUrl !== 'string' || ex.targetUrl.length > 2048)) {
        return { valid: false, knownType: true, error: 'Invalid exception targetUrl' };
      }
      if (ex.checkId !== undefined && (typeof ex.checkId !== 'string' || ex.checkId.length > 128)) {
        return { valid: false, knownType: true, error: 'Invalid exception checkId' };
      }
      return { valid: true, knownType: true };
    }
    default:
      return { valid: false, knownType: false, error: 'Unknown message type' };
  }
}

/**
 * chrome.runtime.onMessage リスナー本体 (v1.7.0 T10 / IMPL-05)
 * - 未知のメッセージには同期的に false を返す
 * - 特権メッセージは sender 検証およびペイロード検証を通過したときのみ実行する
 */
export function handleRuntimeMessage(
  message: unknown,
  sender: chrome.runtime.MessageSender,
  sendResponse: (response?: any) => void
): boolean {
  const validation = validateRuntimeMessage(message);
  if (!validation.knownType) {
    return false;
  }

  if (!isPrivilegedExtensionSender(sender)) {
    sendResponse({
      success: false,
      error: '権限エラー: 拡張機能ページ以外からの特権メッセージは拒否されました。',
    });
    return false;
  }

  if (!validation.valid) {
    sendResponse({
      success: false,
      error: `不正なメッセージ形式です: ${validation.error || 'validation failed'}`,
    });
    return false;
  }

  const msg = message as Record<string, any>;

  if (msg.type === 'INSPECT_CURRENT_TAB') {
    runInspection(msg.tabId)
      .then((report) => sendResponse({ success: true, report }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (msg.type === 'GET_HISTORY') {
    getHistorySummaries()
      .then((history) => sendResponse({ success: true, history }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (msg.type === 'GET_ALL_REPORTS') {
    getAllHistoryReports()
      .then((reports) => sendResponse({ success: true, reports }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (msg.type === 'GET_REPORT_BY_ID') {
    getReportById(msg.id)
      .then((report) => sendResponse({ success: true, report }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (msg.type === 'DELETE_HISTORY_ITEM') {
    deleteReportById(msg.id)
      .then(() => sendResponse({ success: true }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (msg.type === 'CLEAR_HISTORY') {
    clearAllHistory()
      .then(() => sendResponse({ success: true }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  // --- Rev.2.1 IMP-10: 許容・除外設定メッセージハンドラ ---
  if (msg.type === 'GET_FINDING_EXCEPTIONS') {
    getAllFindingExceptions()
      .then((exceptions) => sendResponse({ success: true, exceptions }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (msg.type === 'SAVE_FINDING_EXCEPTION') {
    saveFindingException(msg.exception as FindingException)
      .then(() => sendResponse({ success: true }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (msg.type === 'DELETE_FINDING_EXCEPTION') {
    deleteFindingException(msg.id)
      .then(() => sendResponse({ success: true }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  return false;
}

// メッセージリスナー
if (typeof chrome !== 'undefined' && chrome.runtime?.onMessage) {
  chrome.runtime.onMessage.addListener(handleRuntimeMessage);
}
