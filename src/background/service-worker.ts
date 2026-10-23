/**
 * Web Technology & Security Inspector
 * Service Worker (src/background/service-worker.ts) - Version 1.1.0
 * HTTPレスポンスヘッダー傍受、Cookie取得、MAIN World実行時バージョン取得、診断の統括
 */

import { getAdvisoryDbMetadata } from '../detection/advisory';
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
  getAllFindingExceptions,
  saveFindingException,
  deleteFindingException,
  matchFindingException,
} from '../storage/exceptions';
import { generateFindingIdFromCheck } from '../shared/identity';
import { analyzeCSPPolicies, parseCSPPolicy } from '../security/csp-parser';
import { analyzeExternalConnections } from '../security/domain-analyzer';
import { assessInspectionCoverage } from '../shared/coverage';
import {
  CSPPolicy,
  DomSignals,
  InspectedCookieInfo,
  InspectionReport,
  NetworkSignals,
  SecurityCheckResult,
} from '../shared/types';

const EXTENSION_VERSION = chrome.runtime?.getManifest?.()?.version || '1.5.0';

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

  // 5.1 複数CSPポリシーの独立保持と詳細評価 (Rev.2.1 IMP-05)
  const cspPolicies: CSPPolicy[] = [];
  const rawCspHeader = responseHeaders['content-security-policy']?.[0];
  const rawCspReportOnly = responseHeaders['content-security-policy-report-only']?.[0];

  if (rawCspHeader) {
    cspPolicies.push(parseCSPPolicy(rawCspHeader, 'response-header', 'enforce'));
  }
  if (rawCspReportOnly) {
    cspPolicies.push(parseCSPPolicy(rawCspReportOnly, 'response-header', 'report-only'));
  }
  if (domSignals.metaCsp && domSignals.metaCsp.length > 0) {
    for (const metaVal of domSignals.metaCsp) {
      cspPolicies.push(parseCSPPolicy(metaVal, 'meta', 'enforce'));
    }
  }

  if (cspPolicies.length > 0) {
    const hasXfo = Boolean(responseHeaders['x-frame-options']);
    const { results: advancedCspChecks } = analyzeCSPPolicies(cspPolicies, url, hasXfo);
    // 既存のCSP項目 (SEC-CSP-*) を詳細解析結果に置き換え
    const nonCspChecks = baseSecurityChecks.filter((c) => !c.checkId.startsWith('SEC-CSP-'));
    baseSecurityChecks.length = 0;
    baseSecurityChecks.push(...nonCspChecks, ...advancedCspChecks);
  }

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

  // 6.1 安定ID (FindingId) の付与と許容・除外設定 (FindingException) の照合 (Rev.2.1 IMP-10)
  const exceptions = await getAllFindingExceptions();
  for (const c of allSecurityChecks) {
    c.findingId = generateFindingIdFromCheck(c.checkId, url, c.name);
    const exMatch = matchFindingException(c.findingId, url, exceptions);
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
    hasHeaders: Object.keys(responseHeaders).length > 0,
    hasCookiesPermission: true,
    cookieCount: cookies.length,
    hasWebRequestPermission: Boolean(chrome.webRequest),
    unobservedPreScan: Object.keys(responseHeaders).length === 0,
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

  const report: InspectionReport = {
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

  // --- Rev.2.1 IMP-10: 許容・除外設定メッセージハンドラ ---
  if (message.type === 'GET_FINDING_EXCEPTIONS') {
    getAllFindingExceptions()
      .then((exceptions) => sendResponse({ success: true, exceptions }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (message.type === 'SAVE_FINDING_EXCEPTION') {
    saveFindingException(message.exception)
      .then(() => sendResponse({ success: true }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (message.type === 'DELETE_FINDING_EXCEPTION') {
    deleteFindingException(message.id)
      .then(() => sendResponse({ success: true }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  return true;
});
