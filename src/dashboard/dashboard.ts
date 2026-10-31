/**
 * Web Technology & Security Inspector
 * 詳細ダッシュボードコントローラー (src/dashboard/dashboard.ts) - Version 1.1.0
 */

import { downloadCsvFile } from '../export/csv';
import { downloadJsonFile } from '../export/json';
import { downloadMarkdownReport } from '../export/markdown';
import { compareReportsEnhanced } from '../storage/diff';
import {
  DetectedTechnology,
  ExternalConnectionsAnalysis,
  ExternalServiceCategory,
  FindingException,
  InspectionReport,
  SecurityCheckResult,
} from '../shared/types';
import {
  escapeHtml,
  renderCookiesTableHtml,
  renderFullSecurityHtml,
  renderFullTechnologiesHtml,
  renderHistoryListHtml,
  renderLibrarySecurityTableHtml,
  renderOverviewLibrarySecHtml,
  renderOverviewSecurityHtml,
} from './render';

let currentReport: InspectionReport | null = null;
let allReportsList: InspectionReport[] = [];

// DOM要素参照
let currentHostnameEl = document.getElementById('currentHostname') as HTMLElement;
let inspectedAtTimeEl = document.getElementById('inspectedAtTime') as HTMLElement;
let dashAdvisoryDbDateEl = document.getElementById('dashAdvisoryDbDate') as HTMLElement;
let dashTotalTechsEl = document.getElementById('dashTotalTechs') as HTMLElement;
let dashAttentionCountEl = document.getElementById('dashAttentionCount') as HTMLElement;
let dashEolCountEl = document.getElementById('dashEolCount') as HTMLElement;
let dashVulnCountEl = document.getElementById('dashVulnCount') as HTMLElement;
let dashHttpsStatusEl = document.getElementById('dashHttpsStatus') as HTMLElement;
let dashMixedStatusEl = document.getElementById('dashMixedStatus') as HTMLElement;

let overviewLibrarySecListEl = document.getElementById('overviewLibrarySecList') as HTMLElement;
let overviewSecurityListEl = document.getElementById('overviewSecurityList') as HTMLElement;
let librarySecurityTableContainerEl = document.getElementById('librarySecurityTableContainer') as HTMLElement;
let fullTechsContainerEl = document.getElementById('fullTechsContainer') as HTMLElement;
let fullSecurityContainerEl = document.getElementById('fullSecurityContainer') as HTMLElement;
let cookiesTableBodyEl = document.getElementById('cookiesTableBody') as HTMLElement;
let historyListContainerEl = document.getElementById('historyListContainer') as HTMLElement;
let exceptionsTableContainerEl = document.getElementById('exceptionsTableContainer') as HTMLElement;

let compareSelectA = document.getElementById('compareSelectA') as HTMLSelectElement;
let compareSelectB = document.getElementById('compareSelectB') as HTMLSelectElement;
let executeCompareBtn = document.getElementById('executeCompareBtn') as HTMLButtonElement;
let compareResultContainer = document.getElementById('compareResultContainer') as HTMLElement;
let domainsContainerEl = document.getElementById('domainsContainer') as HTMLElement;

let themeToggleBtn = document.getElementById('themeToggleBtn') as HTMLButtonElement;
let exportMdBtn = document.getElementById('exportMdBtn') as HTMLButtonElement;
let exportJsonBtn = document.getElementById('exportJsonBtn') as HTMLButtonElement;
let exportCsvBtn = document.getElementById('exportCsvBtn') as HTMLButtonElement;
let refreshBtn = document.getElementById('refreshBtn') as HTMLButtonElement;
let clearHistoryBtn = document.getElementById('clearHistoryBtn') as HTMLButtonElement;

function initDomElements(): void {
  currentHostnameEl = document.getElementById('currentHostname') as HTMLElement;
  inspectedAtTimeEl = document.getElementById('inspectedAtTime') as HTMLElement;
  dashAdvisoryDbDateEl = document.getElementById('dashAdvisoryDbDate') as HTMLElement;
  dashTotalTechsEl = document.getElementById('dashTotalTechs') as HTMLElement;
  dashAttentionCountEl = document.getElementById('dashAttentionCount') as HTMLElement;
  dashEolCountEl = document.getElementById('dashEolCount') as HTMLElement;
  dashVulnCountEl = document.getElementById('dashVulnCount') as HTMLElement;
  dashHttpsStatusEl = document.getElementById('dashHttpsStatus') as HTMLElement;
  dashMixedStatusEl = document.getElementById('dashMixedStatus') as HTMLElement;

  overviewLibrarySecListEl = document.getElementById('overviewLibrarySecList') as HTMLElement;
  overviewSecurityListEl = document.getElementById('overviewSecurityList') as HTMLElement;
  librarySecurityTableContainerEl = document.getElementById('librarySecurityTableContainer') as HTMLElement;
  fullTechsContainerEl = document.getElementById('fullTechsContainer') as HTMLElement;
  fullSecurityContainerEl = document.getElementById('fullSecurityContainer') as HTMLElement;
  cookiesTableBodyEl = document.getElementById('cookiesTableBody') as HTMLElement;
  historyListContainerEl = document.getElementById('historyListContainer') as HTMLElement;
  exceptionsTableContainerEl = document.getElementById('exceptionsTableContainer') as HTMLElement;

  compareSelectA = document.getElementById('compareSelectA') as HTMLSelectElement;
  compareSelectB = document.getElementById('compareSelectB') as HTMLSelectElement;
  executeCompareBtn = document.getElementById('executeCompareBtn') as HTMLButtonElement;
  compareResultContainer = document.getElementById('compareResultContainer') as HTMLElement;
  domainsContainerEl = document.getElementById('domainsContainer') as HTMLElement;

  themeToggleBtn = document.getElementById('themeToggleBtn') as HTMLButtonElement;
  exportMdBtn = document.getElementById('exportMdBtn') as HTMLButtonElement;
  exportJsonBtn = document.getElementById('exportJsonBtn') as HTMLButtonElement;
  exportCsvBtn = document.getElementById('exportCsvBtn') as HTMLButtonElement;
  refreshBtn = document.getElementById('refreshBtn') as HTMLButtonElement;
  clearHistoryBtn = document.getElementById('clearHistoryBtn') as HTMLButtonElement;
}

/**
 * ダッシュボードの初期化処理
 */
export async function initDashboard(): Promise<void> {
  initDomElements();
  initTheme();
  setupVersionBadge();
  setupNav();
  setupActions();
  await loadDashboardData();
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      void initDashboard();
    });
  } else {
    void initDashboard();
  }
}

function setupVersionBadge(): void {
  const badgeEl = document.getElementById('dashboardVersion');
  if (badgeEl) {
    const ver = chrome.runtime?.getManifest?.()?.version || '1.6.5';
    badgeEl.textContent = `v${ver}`;
  }
}

function initTheme(): void {
  const saved = localStorage.getItem('web_inspector_theme') || 'dark';
  document.body.className = saved === 'light' ? 'theme-light' : 'theme-dark';
}

function toggleTheme(): void {
  const isDark = document.body.classList.contains('theme-dark');
  const next = isDark ? 'theme-light' : 'theme-dark';
  document.body.className = next;
  localStorage.setItem('web_inspector_theme', isDark ? 'light' : 'dark');
}

function setupNav(): void {
  document.querySelectorAll('.nav-item').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.nav-item').forEach((b) => b.classList.remove('active'));
      document.querySelectorAll('.view-panel').forEach((p) => p.classList.remove('active'));

      btn.classList.add('active');
      const targetId = btn.getAttribute('data-view');
      if (targetId) {
        document.getElementById(targetId)?.classList.add('active');
        if (targetId === 'exceptionsView') {
          loadExceptionsData();
        } else if (targetId === 'domainsView') {
          renderExternalConnectionsView(currentReport?.externalConnections);
        }
      }
    });
  });
}

function setupActions(): void {
  if (themeToggleBtn) themeToggleBtn.addEventListener('click', toggleTheme);
  if (refreshBtn) refreshBtn.addEventListener('click', loadDashboardData);

  if (exportMdBtn) {
    exportMdBtn.addEventListener('click', () => {
      if (currentReport) downloadMarkdownReport(currentReport);
    });
  }

  if (exportJsonBtn) {
    exportJsonBtn.addEventListener('click', () => {
      if (currentReport) downloadJsonFile(currentReport);
    });
  }

  if (exportCsvBtn) {
    exportCsvBtn.addEventListener('click', () => {
      if (currentReport) downloadCsvFile(currentReport);
    });
  }

  if (clearHistoryBtn) {
    clearHistoryBtn.addEventListener('click', async () => {
      if (confirm('すべての調査履歴を完全に削除しますか？')) {
        await chrome.runtime.sendMessage({ type: 'CLEAR_HISTORY' });
        await loadDashboardData();
      }
    });
  }

  if (executeCompareBtn) {
    executeCompareBtn.addEventListener('click', handleCompare);
  }

  const historyContainer = historyListContainerEl || document.getElementById('historyListContainer');
  if (historyContainer && !historyContainer.dataset.listenerAttached) {
    historyContainer.addEventListener('click', handleHistoryClick);
    historyContainer.dataset.listenerAttached = 'true';
  }
}

async function loadDashboardData(): Promise<void> {
  try {
    const response = await chrome.runtime.sendMessage({ type: 'GET_ALL_REPORTS' });
    if (response && response.success && response.reports.length > 0) {
      allReportsList = response.reports as InspectionReport[];
      currentReport = allReportsList[0];
    } else {
      const scanRes = await chrome.runtime.sendMessage({ type: 'INSPECT_CURRENT_TAB' });
      if (scanRes && scanRes.success) {
        currentReport = scanRes.report as InspectionReport;
        allReportsList = [currentReport];
      }
    }

    if (currentReport) {
      renderDashboard(currentReport);
      populateCompareSelects(allReportsList);
      renderHistoryList(allReportsList);
    }
  } catch (err) {
    console.error('Failed to load dashboard data:', err);
  }
}

function renderDashboard(report: InspectionReport): void {
  if (currentHostnameEl) currentHostnameEl.textContent = report.hostname;
  if (inspectedAtTimeEl) inspectedAtTimeEl.textContent = `調査日時: ${new Date(report.inspectedAt).toLocaleString('ja-JP')}`;
  if (dashAdvisoryDbDateEl) {
    dashAdvisoryDbDateEl.textContent = `🛡️ 脆弱性DB: ${report.advisoryDatabaseVersion || '2026-10-23'}`;
  }

  // サマリーカード
  if (dashTotalTechsEl) dashTotalTechsEl.textContent = String(report.technologies.length);
  if (dashAttentionCountEl) dashAttentionCountEl.textContent = String(report.summary.requiresAttentionCount);

  const eolCount = report.summary.librarySecurity?.eolCount ?? 0;
  const vulnCount = report.summary.librarySecurity?.vulnerableLibraryCount ?? 0;
  if (dashEolCountEl) dashEolCountEl.textContent = String(eolCount);
  if (dashVulnCountEl) dashVulnCountEl.textContent = `既知脆弱性: ${vulnCount}件 / 不一致: ${report.summary.librarySecurity?.mismatchCount ?? 0}件`;

  if (dashHttpsStatusEl) dashHttpsStatusEl.textContent = report.summary.isHttps ? 'HTTPS (暗号化)' : 'HTTP (非暗号化)';
  if (dashMixedStatusEl) dashMixedStatusEl.textContent = `混在コンテンツ: ${report.summary.mixedContentCount}件`;

  // 1. 概要ビュー
  renderOverviewLibrarySec(report.technologies);
  renderOverviewSecurity(report.securityChecks);

  // 2. ライブラリセキュリティビュー (Version 1.1 ADD-06)
  renderLibrarySecurityView(report.technologies);

  // 3. 検出技術 & エビデンス
  renderFullTechnologies(report.technologies, report.coverage);

  // 4. HTTPセキュリティ診断
  renderFullSecurity(report.securityChecks);

  // 5. Cookieテーブル
  renderCookiesTable(report.cookies);

  // 6. 外部通信先分析 (Rev.2.1 IMP-11)
  renderExternalConnectionsView(report.externalConnections);
}

function renderOverviewLibrarySec(techs: DetectedTechnology[]): void {
  overviewLibrarySecListEl.innerHTML = renderOverviewLibrarySecHtml(techs);
}

function renderOverviewSecurity(checks: SecurityCheckResult[]): void {
  overviewSecurityListEl.innerHTML = renderOverviewSecurityHtml(checks);
}

/**
 * ライブラリセキュリティビューの描画 (Version 1.1 ADD-06)
 */
function renderLibrarySecurityView(techs: DetectedTechnology[]): void {
  librarySecurityTableContainerEl.innerHTML = renderLibrarySecurityTableHtml(techs);
}

function renderFullTechnologies(techs: DetectedTechnology[], coverage?: any): void {
  fullTechsContainerEl.innerHTML = renderFullTechnologiesHtml(techs, coverage);
}

function renderFullSecurity(checks: SecurityCheckResult[]): void {
  fullSecurityContainerEl.innerHTML = renderFullSecurityHtml(checks);
}

function renderCookiesTable(cookies: any[]): void {
  cookiesTableBodyEl.innerHTML = renderCookiesTableHtml(cookies);
}

function handleHistoryClick(event: MouseEvent): void {
  const target = (event.target as HTMLElement | null)?.closest('button[data-id]') as HTMLButtonElement | null;
  if (!target) return;

  const id = target.getAttribute('data-id');
  if (!id) return;

  if (target.classList.contains('history-view-btn')) {
    viewReport(id);
  } else if (target.classList.contains('history-delete-btn')) {
    void deleteReport(id);
  }
}

function renderHistoryList(reports: InspectionReport[]): void {
  const container = historyListContainerEl || document.getElementById('historyListContainer');
  if (!container) return;
  container.innerHTML = renderHistoryListHtml(reports);
}

function viewReport(id: string): void {
  const target = allReportsList.find((r) => r.id === id);
  if (target) {
    currentReport = target;
    renderDashboard(target);
    document.querySelector('.nav-item[data-view="overviewView"]')?.dispatchEvent(new Event('click'));
  }
}

async function deleteReport(id: string): Promise<void> {
  if (confirm('この調査レポートを削除しますか？')) {
    await chrome.runtime.sendMessage({ type: 'DELETE_HISTORY_ITEM', id });
    await loadDashboardData();
  }
}

function populateCompareSelects(reports: InspectionReport[]): void {
  if (!compareSelectA || !compareSelectB) return;
  compareSelectA.innerHTML = '';
  compareSelectB.innerHTML = '';

  reports.forEach((r, idx) => {
    const optA = document.createElement('option');
    optA.value = r.id;
    optA.textContent = `${r.hostname} (${new Date(r.inspectedAt).toLocaleString('ja-JP')})`;
    compareSelectA?.appendChild(optA);

    const optB = document.createElement('option');
    optB.value = r.id;
    optB.textContent = `${r.hostname} (${new Date(r.inspectedAt).toLocaleString('ja-JP')})`;
    if (idx === 1 || (idx === 0 && reports.length === 1)) optB.selected = true;
    compareSelectB?.appendChild(optB);
  });
}

function handleCompare(): void {
  if (!compareSelectA || !compareSelectB) return;
  const idA = compareSelectA.value;
  const idB = compareSelectB.value;

  const repA = allReportsList.find((r) => r.id === idA);
  const repB = allReportsList.find((r) => r.id === idB);

  if (!repA || !repB) return;

  const diff = compareReportsEnhanced(repA, repB);

  // 原因集計バッジの生成 (Rev.2.1 IMP-09)
  const causeBadges = Object.entries(diff.summary.causes)
    .filter(([_, count]) => count > 0)
    .map(([cause, count]) => {
      let label = cause;
      if (cause === 'site-change') label = 'Site Change (サイト側変更)';
      else if (cause === 'advisory-update') label = 'Advisory Update (脆弱性DB更新)';
      else if (cause === 'inspection-difference') label = 'Inspection Diff (調査権限差)';
      else if (cause === 'rule-update') label = 'Rule Update (診断ルール更新)';
      else if (cause === 'unknown') label = 'Unknown (複数/不明)';
      return `<span class="badge badge-medium" style="margin-right:6px;display:inline-block;margin-top:4px;">${escapeHtml(label)}: ${count}件</span>`;
    })
    .join('');

  compareResultContainer.innerHTML = `
    <div class="diff-box">
      <div class="diff-title">差分分析サマリー (Rev.2.1 IMP-09)</div>
      <div style="margin-bottom:8px;">
        検出された変化: <strong>${diff.diffItems.length} 件</strong>
        (新規: ${diff.summary.addedCount}, 消失: ${diff.summary.removedCount}, 変更: ${diff.summary.changedCount}, 解消: ${diff.summary.resolvedCount}, 新規警告: ${diff.summary.regressedCount})
      </div>
      <div>推定要因: ${causeBadges || '<span style="color:var(--text-muted);">差分なし</span>'}</div>
    </div>

    <div class="diff-box">
      <div class="diff-title">詳細な変化と原因分析</div>
      ${
        diff.diffItems.length === 0
          ? '<div style="color:var(--text-muted);padding:8px 0;">2つの調査結果に変化はありませんでした。</div>'
          : `
        <div class="table-responsive">
          <table class="data-table">
            <thead>
              <tr>
                <th>種別</th>
                <th>対象</th>
                <th>推定原因</th>
                <th>Before &rarr; After</th>
                <th>解説</th>
              </tr>
            </thead>
            <tbody>
              ${diff.diffItems
                .map((item) => {
                  let badgeClass = 'badge-medium';
                  if (item.diffType === 'Resolved' || item.diffType === 'Added') badgeClass = 'badge-high';
                  if (item.diffType === 'Regressed') badgeClass = 'badge-eol';

                  return `
                    <tr>
                      <td><span class="badge ${badgeClass}">${item.diffType}</span></td>
                      <td><strong>${escapeHtml(item.target)}</strong></td>
                      <td><span class="badge" style="background:var(--bg-hover);">${escapeHtml(item.diffCause)}</span></td>
                      <td>${escapeHtml(item.before || '-')} &rarr; <strong>${escapeHtml(item.after || '-')}</strong></td>
                      <td style="font-size:12px;color:var(--text-sub);">${escapeHtml(item.causeExplanation)}</td>
                    </tr>
                  `;
                })
                .join('')}
            </tbody>
          </table>
        </div>
      `
      }
    </div>
  `;
}

async function loadExceptionsData(): Promise<void> {
  if (!exceptionsTableContainerEl) return;
  try {
    const res = await chrome.runtime.sendMessage({ type: 'GET_FINDING_EXCEPTIONS' });
    const exceptions: FindingException[] = res?.exceptions || [];
    if (exceptions.length === 0) {
      exceptionsTableContainerEl.innerHTML = '<div class="empty-state">登録されている許容・除外設定はありません。</div>';
      return;
    }

    exceptionsTableContainerEl.innerHTML = `
      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>状態</th>
              <th>対象安定ID (FindingId)</th>
              <th>対象URL</th>
              <th>許容理由</th>
              <th>登録日</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            ${exceptions
              .map(
                (ex) => `
              <tr>
                <td><span class="badge ${ex.status === 'accepted' ? 'badge-high' : 'badge-medium'}">${ex.status === 'accepted' ? 'リスク許容' : ex.status === 'false-positive' ? '誤検知' : '通知抑制'}</span></td>
                <td><code>${escapeHtml(ex.findingId)}</code></td>
                <td>${escapeHtml(ex.targetUrl || '全体適用')}</td>
                <td>${escapeHtml(ex.reason)}</td>
                <td>${ex.createdAt ? new Date(ex.createdAt).toLocaleString('ja-JP') : '-'}</td>
                <td><button class="btn btn-secondary revoke-ex-btn" data-id="${escapeHtml(ex.id)}" style="font-size:11px;padding:3px 8px;">解除</button></td>
              </tr>
            `
              )
              .join('')}
          </tbody>
        </table>
      </div>
    `;

    document.querySelectorAll('.revoke-ex-btn').forEach((btn) => {
      btn.addEventListener('click', async (e) => {
        const id = (e.currentTarget as HTMLElement).getAttribute('data-id');
        if (id && confirm('この許容設定を解除しますか？')) {
          await chrome.runtime.sendMessage({ type: 'DELETE_FINDING_EXCEPTION', id });
          await loadExceptionsData();
          await loadDashboardData();
        }
      });
    });
  } catch (err) {
    const errMessage = err instanceof Error ? err.message : String(err);
    exceptionsTableContainerEl.innerHTML = `<div class="empty-state" style="color:var(--danger-color);">許容設定の取得に失敗しました: ${escapeHtml(errMessage)}</div>`;
  }
}

/**
 * 外部通信先・サードパーティドメイン分析ビューの描画 (Rev.2.1 IMP-11)
 */
function renderExternalConnectionsView(analysis?: ExternalConnectionsAnalysis): void {
  if (!domainsContainerEl) return;
  if (!analysis || !analysis.connections || analysis.connections.length === 0) {
    domainsContainerEl.innerHTML = '<div class="empty-state">外部通信先情報はまだ解析されていません。</div>';
    return;
  }

  const catLabels: Record<ExternalServiceCategory, string> = {
    cdn: 'CDN・静的配信',
    analytics: 'アクセス解析',
    advertising: '広告・マーケティング',
    fonts: 'Webフォント',
    social: 'SNSウィジェット',
    api: '外部API',
    other: 'その他',
  };

  const categoryChips = (Object.entries(analysis.categoryBreakdown) as [ExternalServiceCategory, number][])
    .filter(([_, count]) => count > 0)
    .map(([cat, count]) => `<span class="badge badge-medium" style="margin-right:6px;display:inline-block;margin-top:4px;">${escapeHtml(catLabels[cat] || cat)}: ${count}件</span>`)
    .join('');

  domainsContainerEl.innerHTML = `
    <div class="diff-box">
      <div class="diff-title">通信先ドメイン集計 (eTLD+1 / Public Suffix List 判定)</div>
      <div style="margin-bottom:8px;">
        検出ホスト数: <strong>${analysis.totalConnections} 件</strong>
        (自社/First-Party: <strong>${analysis.firstPartyCount}</strong>, 外部/Third-Party: <strong>${analysis.thirdPartyCount}</strong>)
      </div>
      <div>推定用途別内訳: ${categoryChips || '<span style="color:var(--text-muted);">-</span>'}</div>
    </div>

    <div class="diff-box">
      <div class="diff-title">通信先ホスト一覧</div>
      <div class="table-responsive">
        <table class="data-table">
          <thead>
            <tr>
              <th>ホスト名</th>
              <th>eTLD+1 (組織ドメイン)</th>
              <th>分類</th>
              <th>用途カテゴリ</th>
              <th>リソース数</th>
              <th>サンプルURL</th>
            </tr>
          </thead>
          <tbody>
            ${analysis.connections
              .map((item) => {
                let badgeClass = 'badge-medium';
                let partyLabel = 'Third-Party';
                if (item.partyType === 'first-party') {
                  badgeClass = 'badge-high';
                  partyLabel = 'First-Party (自社)';
                } else if (item.partyType === 'local') {
                  badgeClass = 'badge-low';
                  partyLabel = 'Local (内部)';
                } else {
                  badgeClass = 'badge-medium';
                  partyLabel = 'Third-Party (外部)';
                }

                const sampleUrl = item.sampleUrls.length > 0 ? item.sampleUrls[0] : '';

                return `
                  <tr>
                    <td><strong>${escapeHtml(item.hostname)}</strong></td>
                    <td><code>${escapeHtml(item.registrableDomain || '-')}</code></td>
                    <td><span class="badge ${badgeClass}">${partyLabel}</span></td>
                    <td><span class="badge" style="background:var(--bg-hover);">${escapeHtml(catLabels[item.category] || item.category)}</span></td>
                    <td>${item.resourceCount}</td>
                    <td style="font-size:11px;color:var(--text-sub);max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(sampleUrl)}">${escapeHtml(sampleUrl || '-')}</td>
                  </tr>
                `;
              })
              .join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}


