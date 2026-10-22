/**
 * Web Technology & Security Inspector
 * Service Worker (src/background/service-worker.ts)
 * HTTPレスポンスヘッダーの傍受、Cookie属性の収集、診断の統括
 */

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
} from '../shared/types';

const EXTENSION_VERSION = '1.0.0';

// タブID / URLごとのHTTPレスポンスヘッダーキャッシュ
// Map<tabId, { url: string, headers: Record<string, string[]> }>
const headersCache = new Map<number, { url: string; headers: Record<string, string[]> }>();

// 1. webRequest API によるHTTPレスポンスヘッダーの収集
// (Manifest V3のライフサイクルに合わせトップレベルで登録)
try {
  if (chrome.webRequest && chrome.webRequest.onHeadersReceived) {
    chrome.webRequest.onHeadersReceived.addListener(
      (details) => {
        // メインフレームのリクエストのみ、または主要リソースのヘッダーを記録
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
  console.warn('webRequest listener registration warning:', e);
}

// タブが閉じられたらキャッシュを破棄
chrome.tabs.onRemoved.addListener((tabId) => {
  headersCache.delete(tabId);
});

/**
 * 対象URLのCookie属性を取得する (※値は一切取得・保存しない)
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
 * Content ScriptからDOMシグナルを取得する
 */
async function fetchDomSignals(tabId: number, url: string): Promise<DomSignals> {
  try {
    const response = await chrome.tabs.sendMessage(tabId, { type: 'EXTRACT_DOM_SIGNALS' });
    if (response) return response as DomSignals;
  } catch {
    // Content Scriptがまだ動いていない、または再読み込みされていない場合は注入を試みる
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

  // フォールバック用の最小DOM情報
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
  };
}

/**
 * 総合調査を実行するメインコントローラー
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

  // 内部ブラウザページ (chrome:// など) の除外
  if (url.startsWith('chrome://') || url.startsWith('edge://') || url.startsWith('about:')) {
    throw new Error('ブラウザの内部管理ページは調査対象外です。一般のWebページで実行してください。');
  }

  let hostname = '';
  try {
    hostname = new URL(url).hostname;
  } catch {
    hostname = url;
  }

  // 1. DOM情報の取得
  const domSignals = await fetchDomSignals(currentTabId, url);

  // 2. HTTPヘッダーの取得
  const cachedData = headersCache.get(currentTabId);
  const responseHeaders = cachedData?.headers || {};

  // 3. Cookie属性の収集 (値は除外)
  const cookies = await getInspectedCookies(url);

  const networkSignals: NetworkSignals = {
    url,
    responseHeaders,
    cookies,
  };

  // 4. 技術検出エンジンの実行
  const detectionEngine = new DetectionEngine();
  const technologies = detectionEngine.detect({
    url,
    dom: domSignals,
    network: networkSignals,
  });

  // 5. セキュリティ診断エンジンの実行
  const securityEngine = new SecurityEngine();
  const { checks: securityChecks, cookies: evaluatedCookies } = securityEngine.evaluate({
    url,
    dom: domSignals,
    network: networkSignals,
  });

  // 6. 統計集計
  const requiresAttentionCount = securityChecks.filter(
    (c) => c.status === 'warning' || c.status === 'fail'
  ).length;

  const securityFindings = {
    high: securityChecks.filter((c) => c.severity === 'high').length,
    medium: securityChecks.filter((c) => c.severity === 'medium').length,
    low: securityChecks.filter((c) => c.severity === 'low').length,
    info: securityChecks.filter((c) => c.severity === 'info').length,
    unknown: securityChecks.filter((c) => c.severity === 'unknown').length,
  };

  const isHttps = url.toLowerCase().startsWith('https://');

  const report: InspectionReport = {
    id: `rep_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
    url,
    hostname,
    inspectedAt: new Date().toISOString(),
    extensionVersion: EXTENSION_VERSION,
    rulesVersion: RULES_VERSION,
    summary: {
      totalTechnologies: technologies.length,
      requiresAttentionCount,
      securityFindings,
      isHttps,
      mixedContentCount: domSignals.mixedContent.length,
    },
    technologies,
    securityChecks,
    cookies: evaluatedCookies,
    mixedContent: domSignals.mixedContent,
  };

  // 7. 履歴への自動保存
  await saveReportToHistory(report);

  // 8. アイコンバッジの更新（要確認件数を表示）
  if (requiresAttentionCount > 0) {
    chrome.action.setBadgeText({ text: String(requiresAttentionCount), tabId: currentTabId });
    chrome.action.setBadgeBackgroundColor({ color: '#E53E3E', tabId: currentTabId });
  } else {
    chrome.action.setBadgeText({ text: String(technologies.length), tabId: currentTabId });
    chrome.action.setBadgeBackgroundColor({ color: '#3182CE', tabId: currentTabId });
  }

  return report;
}

// メッセージハンドラー
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'INSPECT_CURRENT_TAB') {
    runInspection(message.tabId)
      .then((report) => sendResponse({ success: true, report }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true; // 非同期レスポンス
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
