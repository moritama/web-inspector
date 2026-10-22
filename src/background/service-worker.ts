/**
 * Web Technology & Security Inspector
 * Service Worker (src/background/service-worker.ts) - Version 1.1.0
 * HTTPレスポンスヘッダー傍受、Cookie取得、MAIN World実行時バージョン取得、診断の統括
 */

import { CVE_DATABASE_VERSION } from '../security/cve/cve-engine';
import { RULES_VERSION } from '../detection/rules';
import { DetectionEngine } from '../detection/engine';
import { SecurityEngine } from '../security/engine';
import {
  deleteReportById,
  getAllHistoryReports,
  getHistorySummaries,
  getReportById,
  saveReportToHistory,
  clearAllHistory,
} from '../storage/history';
import {
  DomSignals,
  InspectedCookieInfo,
  InspectionReport,
  NetworkSignals,
  SecurityCheckResult,
} from '../shared/types';

const EXTENSION_VERSION = '1.1.0';

// タブIDごとのレスポンスヘッダーキャッシュ
const headersCache = new Map<number, { url: string; headers: Record<string, string[]> }>();

// 1. webRequest API によるHTTPレスポンスヘッダーの収集
try {
  if (chrome.webRequest && chrome.webRequest.onHeadersReceived) {
    chrome.webRequest.onHeadersReceived.addListener(
      (details) => {
        if (details.tabId > 0 && details.type === 'main_frame') {
          const headerMap: Record<string, string[]> = {};
          if (details.responseHeaders) {
            for (const h of details.responseHeaders) {
              const name = h.name.toLowerCase();
              if (!headerMap[name]) {
                headerMap[name] = [];
              }
              if (h.value) {
                headerMap[name].push(h.value);
              }
            }
          }
          headersCache.set(details.tabId, {
            url: details.url,
            headers: headerMap,
          });
        }
      },
      { urls: ['<all_urls>'] },
      ['responseHeaders', 'extraHeaders']
    );
  }
} catch (e) {
  console.warn('webRequest registration warning:', e);
}

chrome.tabs.onRemoved.addListener((tabId) => {
  headersCache.delete(tabId);
});

/**
 * Cookie属性の取得 (値は除外)
 */
async function getInspectedCookies(url: string): Promise<InspectedCookieInfo[]> {
  try {
    const rawCookies = await chrome.cookies.getAll({ url });
    return rawCookies.map((c) => ({
      name: c.name,
      domain: c.domain,
      path: c.path,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite as 'no_restriction' | 'lax' | 'strict' | 'unspecified',
      session: c.session,
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
 * MAIN World（ページの実行コンテキスト）からJavaScriptライブラリの実行時バージョンを安全に取得する (ADD-01)
 */
async function fetchRuntimeVersions(tabId: number): Promise<Record<string, string | null>> {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      world: 'MAIN',
      func: () => {
        const w = window as any;
        return {
          jquery: w.jQuery?.fn?.jquery ?? null,
          bootstrap4: w.jQuery?.fn?.modal?.Constructor?.VERSION ?? null,
          bootstrap5: w.bootstrap?.Modal?.VERSION ?? null,
          vue: w.Vue?.version ?? null,
          lodash: w._?.VERSION ?? null,
          moment: w.moment?.version ?? null,
        };
      },
    });

    if (results && results[0]?.result) {
      return results[0].result as Record<string, string | null>;
    }
  } catch (e) {
    console.warn('Runtime version extraction skipped (chrome:// or restricted page):', e);
  }

  return {};
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

  const url = targetTab.url;
  const currentTabId = targetTab.id;

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
  const domSignals = await fetchDomSignals(currentTabId, url);

  // 2. JavaScript実行時バージョンの取得 (MAIN World)
  const runtimeVersions = await fetchRuntimeVersions(currentTabId);
  domSignals.runtimeVersions = runtimeVersions;

  // 3. HTTPヘッダー・Cookieの取得
  const cachedData = headersCache.get(currentTabId);
  const responseHeaders = cachedData?.headers || {};
  const cookies = await getInspectedCookies(url);

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
    runtimeVersions,
  });

  // 5. セキュリティ診断エンジンの実行
  const securityEngine = new SecurityEngine();
  const { checks: baseSecurityChecks, cookies: evaluatedCookies } = securityEngine.evaluate({
    url,
    dom: domSignals,
    network: networkSignals,
  });

  // 6. ライブラリセキュリティ診断項目の生成 (EOL, CVE, バージョン不一致)
  const librarySecurityChecks: SecurityCheckResult[] = [];
  let eolCount = 0;
  let vulnerableLibraryCount = 0;
  let mismatchCount = 0;

  for (const tech of technologies) {
    // EOL判定のセキュリティチェック追加
    if (tech.supportStatus === 'EOL') {
      eolCount++;
      librarySecurityChecks.push({
        checkId: `SEC-EOL-${tech.technology.toUpperCase()}`,
        category: 'library-security',
        name: `${tech.technology} サポート終了 (EOL)`,
        status: 'warning',
        severity: 'medium',
        observed: `検出バージョン: ${tech.version || '不明'} (EOL日: ${tech.eolDate || '過去'})`,
        description: `${tech.technology} は公式サポートが終了しています。新たな脆弱性が発見されてもセキュリティパッチが提供されません。`,
        recommendation: tech.eolInfo?.recommendation || '現行のサポート対象バージョンへの移行を検討してください。',
        referenceUrls: tech.eolInfo?.sourceUrl ? [tech.eolInfo.sourceUrl] : [],
        scope: url,
      });
    }

    // CVE該当判定のセキュリティチェック追加
    if (tech.advisoryMatchStatus === 'Potentially Affected' && tech.advisories && tech.advisories.length > 0) {
      vulnerableLibraryCount++;
      const topAdvisory = tech.advisories[0];
      const maxScore = tech.maxCvss ?? 6.1;
      const severity = maxScore >= 7.0 ? 'high' : 'medium';

      librarySecurityChecks.push({
        checkId: `SEC-CVE-${tech.technology.toUpperCase()}`,
        category: 'library-security',
        name: `${tech.technology} 既知脆弱性 (${tech.advisories.map((a) => a.id).join(', ')})`,
        status: 'fail',
        severity,
        observed: `バージョン ${tech.version} に該当する既知脆弱性 ${tech.advisories.length} 件 (最大CVSS: ${maxScore})`,
        description: topAdvisory.summary,
        recommendation: topAdvisory.fixedVersion
          ? `修正済みバージョン（${topAdvisory.fixedVersion} 以上）への速やかなアップデートを推奨します。`
          : '修正済みバージョンへの更新または緩和策の適用を検討してください。',
        referenceUrls: topAdvisory.referenceUrls,
        scope: url,
      });
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

  // 7. 統計集計
  const requiresAttentionCount = allSecurityChecks.filter(
    (c) => c.status === 'warning' || c.status === 'fail'
  ).length;

  const securityFindings = {
    high: allSecurityChecks.filter((c) => c.severity === 'high').length,
    medium: allSecurityChecks.filter((c) => c.severity === 'medium').length,
    low: allSecurityChecks.filter((c) => c.severity === 'low').length,
    info: allSecurityChecks.filter((c) => c.severity === 'info').length,
    unknown: allSecurityChecks.filter((c) => c.severity === 'unknown').length,
  };

  const isHttps = url.toLowerCase().startsWith('https://');

  const report: InspectionReport = {
    id: `rep_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
    url,
    hostname,
    inspectedAt: new Date().toISOString(),
    extensionVersion: EXTENSION_VERSION,
    rulesVersion: RULES_VERSION,
    advisoryDatabaseVersion: CVE_DATABASE_VERSION,
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
    mixedContent: domSignals.mixedContent,
  };

  // 8. 履歴保存
  await saveReportToHistory(report);

  // 9. バッジ更新
  if (requiresAttentionCount > 0) {
    chrome.action.setBadgeText({ text: String(requiresAttentionCount), tabId: currentTabId });
    chrome.action.setBadgeBackgroundColor({ color: '#E53E3E', tabId: currentTabId });
  } else {
    chrome.action.setBadgeText({ text: String(technologies.length), tabId: currentTabId });
    chrome.action.setBadgeBackgroundColor({ color: '#3182CE', tabId: currentTabId });
  }

  return report;
}

// メッセージリスナー
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'INSPECT_CURRENT_TAB') {
    runInspection(message.tabId)
      .then((report) => sendResponse({ success: true, report }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (message.type === 'GET_HISTORY') {
    getHistorySummaries()
      .then((history) => sendResponse({ success: true, history }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (message.type === 'GET_ALL_REPORTS') {
    getAllHistoryReports()
      .then((reports) => sendResponse({ success: true, reports }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (message.type === 'GET_REPORT_BY_ID') {
    getReportById(message.id)
      .then((report) => sendResponse({ success: true, report }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (message.type === 'DELETE_HISTORY_ITEM') {
    deleteReportById(message.id)
      .then(() => sendResponse({ success: true }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (message.type === 'CLEAR_HISTORY') {
    clearAllHistory()
      .then(() => sendResponse({ success: true }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  return true;
});
