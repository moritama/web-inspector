/**
 * Web Technology & Security Inspector
 * ポップアップ画面コントローラー (src/popup/popup.ts) - Version 1.1.0
 */

import { downloadCsvFile } from '../export/csv';
import { downloadJsonFile } from '../export/json';
import {
  DetectedTechnology,
  InspectedCookieInfo,
  InspectionReport,
  SecurityCheckResult,
} from '../shared/types';
import {
  escapeHtml,
  renderTechRowHtml,
  renderCookieModalHtml,
  renderInterstitialNoticeHtml,
  renderSecurityCheckRowHtml,
  renderSecurityModalHtml,
  renderTechModalHtml,
} from './render';
import { DATA_SOURCES_VIEW_ID } from '../shared/data-sources';

let currentReport: InspectionReport | null = null;

// DOM要素参照
const siteHostnameEl = document.getElementById('siteHostname') as HTMLElement;
const statusIndicatorEl = document.getElementById('statusIndicator') as HTMLElement;
const techCountEl = document.getElementById('techCount') as HTMLElement;
const attentionCountEl = document.getElementById('attentionCount') as HTMLElement;
const eolCountEl = document.getElementById('eolCount') as HTMLElement;
const tabTechCountEl = document.getElementById('tabTechCount') as HTMLElement;
const tabSecCountEl = document.getElementById('tabSecCount') as HTMLElement;
const tabCookieCountEl = document.getElementById('tabCookieCount') as HTMLElement;

const techsListEl = document.getElementById('techsList') as HTMLElement;
const securityListEl = document.getElementById('securityList') as HTMLElement;
const cookiesListEl = document.getElementById('cookiesList') as HTMLElement;

const rescanBtn = document.getElementById('rescanBtn') as HTMLButtonElement;
const themeToggleBtn = document.getElementById('themeToggleBtn') as HTMLButtonElement;
const openDashboardBtn = document.getElementById('openDashboardBtn') as HTMLButtonElement;
const fullReportBtn = document.getElementById('fullReportBtn') as HTMLButtonElement;
const exportJsonBtn = document.getElementById('exportJsonBtn') as HTMLButtonElement;
const exportCsvBtn = document.getElementById('exportCsvBtn') as HTMLButtonElement;

const detailModal = document.getElementById('detailModal') as HTMLElement;
const modalTitle = document.getElementById('modalTitle') as HTMLElement;
const modalBody = document.getElementById('modalBody') as HTMLElement;
const closeModalBtn = document.getElementById('closeModalBtn') as HTMLButtonElement;

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  setupVersionBadge();
  setupEventListeners();
  runScan();
});

function setupVersionBadge(): void {
  const versionEl = document.getElementById('brandVersion');
  if (versionEl) {
    const ver = chrome.runtime?.getManifest?.()?.version || '1.8.1';
    versionEl.textContent = `v${ver}`;
  }
}

function initTheme(): void {
  const savedTheme = localStorage.getItem('web_inspector_theme') || 'dark';
  document.body.className = savedTheme === 'light' ? 'theme-light' : 'theme-dark';
}

function toggleTheme(): void {
  const isDark = document.body.classList.contains('theme-dark');
  const newTheme = isDark ? 'theme-light' : 'theme-dark';
  document.body.className = newTheme;
  localStorage.setItem('web_inspector_theme', isDark ? 'light' : 'dark');
}

function setupEventListeners(): void {
  themeToggleBtn.addEventListener('click', toggleTheme);
  rescanBtn.addEventListener('click', () => runScan());
  openDashboardBtn.addEventListener('click', openDashboard);
  fullReportBtn.addEventListener('click', openDashboard);

  const dataSourcesLinkEl = document.getElementById('dataSourcesLink') as HTMLButtonElement | null;
  if (dataSourcesLinkEl) {
    dataSourcesLinkEl.addEventListener('click', () => {
      const dashboardUrl = `${chrome.runtime.getURL('dashboard.html')}#${DATA_SOURCES_VIEW_ID}`;
      chrome.tabs.create({ url: dashboardUrl });
    });
  }

  exportJsonBtn.addEventListener('click', () => {
    if (currentReport) downloadJsonFile(currentReport);
  });
  exportCsvBtn.addEventListener('click', () => {
    if (currentReport) downloadCsvFile(currentReport);
  });

  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach((p) => p.classList.remove('active'));

      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      if (targetId) {
        document.getElementById(targetId)?.classList.add('active');
      }
    });
  });

  closeModalBtn.addEventListener('click', () => {
    detailModal.classList.add('hidden');
  });

  detailModal.addEventListener('click', (e) => {
    if (e.target === detailModal) {
      detailModal.classList.add('hidden');
    }
  });
}

function openDashboard(): void {
  const dashboardUrl = chrome.runtime.getURL('dashboard.html');
  chrome.tabs.create({ url: dashboardUrl });
}

async function runScan(): Promise<void> {
  statusIndicatorEl.className = 'status-indicator';
  siteHostnameEl.textContent = '調査中...';
  techsListEl.innerHTML = '<div class="empty-state">技術情報を解析中...</div>';
  securityListEl.innerHTML = '<div class="empty-state">セキュリティ設定を診断中...</div>';
  cookiesListEl.innerHTML = '<div class="empty-state">Cookie属性を取得中...</div>';

  try {
    const response = await chrome.runtime.sendMessage({ type: 'INSPECT_CURRENT_TAB' });
    if (!response || !response.success) {
      throw new Error(response?.error || '調査に失敗しました。');
    }

    currentReport = response.report as InspectionReport;
    renderReport(currentReport);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    siteHostnameEl.textContent = '調査エラー';
    statusIndicatorEl.className = 'status-indicator';
    statusIndicatorEl.style.backgroundColor = '#EF4444';
    techsListEl.innerHTML = `<div class="empty-state" style="color: #EF4444;">${escapeHtml(message)}</div>`;
  }
}

function renderReport(report: InspectionReport): void {
  statusIndicatorEl.className = 'status-indicator ready';
  siteHostnameEl.textContent = report.hostname;

  // サマリー数値
  techCountEl.textContent = String(report.technologies.length);
  attentionCountEl.textContent = String(report.summary.requiresAttentionCount);

  // EOL / CVE 合計数
  const totalEolAndCve =
    (report.summary.librarySecurity?.eolCount ?? 0) +
    (report.summary.librarySecurity?.vulnerableLibraryCount ?? 0);
  if (eolCountEl) {
    eolCountEl.textContent = String(totalEolAndCve);
  }

  tabTechCountEl.textContent = String(report.technologies.length);
  tabSecCountEl.textContent = String(report.securityChecks.length);
  tabCookieCountEl.textContent = String(report.cookies.length);

  // 1. 使用技術一覧
  renderTechnologies(
    report.technologies,
    report.coverage,
    report.storageWarning,
    report.interstitial
  );

  // 2. セキュリティ診断一覧
  renderSecurityChecks(report.securityChecks);

  // 3. Cookie診断一覧
  renderCookies(report.cookies);

  // 4. 脆弱性DB更新日表示
  const advisoryDbBarEl = document.getElementById('advisoryDbBar');
  if (advisoryDbBarEl) {
    const dbVer = report.advisoryDatabaseVersion || '2026-10-23';
    advisoryDbBarEl.textContent = `🛡️ 脆弱性DB更新日: ${dbVer}`;
  }
}

function renderTechnologies(
  techs: DetectedTechnology[],
  coverage?: any,
  storageWarning?: string,
  interstitial?: any
): void {
  techsListEl.innerHTML = '';

  const interstitialHtml = renderInterstitialNoticeHtml(interstitial);
  if (interstitialHtml) {
    const banner = document.createElement('div');
    banner.innerHTML = interstitialHtml;
    techsListEl.appendChild(banner.firstElementChild || banner);
  }

  if (storageWarning) {
    const storageBanner = document.createElement('div');
    storageBanner.className = 'notice-banner storage-warning-banner';
    storageBanner.style.cssText = 'background: rgba(239, 68, 68, 0.15); border: 1px solid var(--danger-color, #ef4444); border-radius: 6px; padding: 8px 10px; margin-bottom: 8px; font-size: 11px; color: var(--danger-color, #ef4444); line-height: 1.4;';
    storageBanner.innerHTML = `⚠️ <strong>履歴保存通知</strong>: ${escapeHtml(storageWarning)}`;
    techsListEl.appendChild(storageBanner);
  }

  if (coverage && coverage.networkHeadersObserved === false) {
    const banner = document.createElement('div');
    banner.className = 'notice-banner';
    banner.style.cssText = 'background: rgba(245, 158, 11, 0.15); border: 1px solid var(--warning-color); border-radius: 6px; padding: 8px 10px; margin-bottom: 8px; font-size: 11px; color: var(--warning-color); line-height: 1.4;';
    banner.innerHTML = '⚠️ <strong>HTTPヘッダー未取得</strong>: 拡張機能起動前またはスリープ中に開かれたタブです。サーバーや言語ヘッダーを診断するには、ページを再読み込み（リロード）して再調査してください。';
    techsListEl.appendChild(banner);
  }

  if (techs.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.textContent = '明確な固有技術シグナルは検出されませんでした';
    techsListEl.appendChild(empty);
    return;
  }
  techs.forEach((t) => {
    const row = document.createElement('div');
    row.className = 'item-row';
    row.innerHTML = renderTechRowHtml(t);
    row.addEventListener('click', () => showTechModal(t));
    techsListEl.appendChild(row);
  });
}

function renderSecurityChecks(checks: SecurityCheckResult[]): void {
  if (checks.length === 0) {
    securityListEl.innerHTML = '<div class="empty-state">診断項目がありません</div>';
    return;
  }

  securityListEl.innerHTML = '';
  checks.forEach((c) => {
    const row = document.createElement('div');
    row.className = 'item-row';
    row.innerHTML = renderSecurityCheckRowHtml(c);

    row.addEventListener('click', () => showSecurityModal(c));
    securityListEl.appendChild(row);
  });
}

function renderCookies(cookies: InspectedCookieInfo[]): void {
  if (cookies.length === 0) {
    cookiesListEl.innerHTML = '<div class="empty-state">観測されたCookieはありません</div>';
    return;
  }

  cookiesListEl.innerHTML = '';
  cookies.forEach((c) => {
    const row = document.createElement('div');
    row.className = 'item-row';

    const hasIssues = c.issues && c.issues.length > 0;
    const badgeClass = hasIssues ? 'sev-medium' : 'sev-pass';
    const badgeLabel = hasIssues ? '要確認' : '安全';

    row.innerHTML = `
      <div class="item-main">
        <div class="item-texts">
          <span class="item-name">${escapeHtml(c.name)}</span>
          <div class="item-meta">
            <span>${c.secure ? '🔒 Secure' : '⚠️ 不保護'}</span>
            <span>${c.httpOnly ? '🛡️ HttpOnly' : 'スクリプト可'}</span>
            <span>SameSite: ${escapeHtml(c.sameSite || '-')}</span>
          </div>
        </div>
      </div>
      <div class="item-side">
        <span class="badge ${badgeClass}">${badgeLabel}</span>
      </div>
    `;

    row.addEventListener('click', () => showCookieModal(c));
    cookiesListEl.appendChild(row);
  });
}

/**
 * 技術詳細モーダル (Version 1.1)
 */
function showTechModal(tech: DetectedTechnology): void {
  modalTitle.textContent = `${tech.technology} 検出 & セキュリティ詳細`;
  modalBody.innerHTML = renderTechModalHtml(tech);
  detailModal.classList.remove('hidden');
}

function showSecurityModal(check: SecurityCheckResult): void {
  modalTitle.textContent = check.name;
  modalBody.innerHTML = renderSecurityModalHtml(check);

  // イベントリスナー設定
  const acceptBtn = document.getElementById('modalAcceptFindingBtn');
  if (acceptBtn && check.findingId) {
    acceptBtn.addEventListener('click', async () => {
      const reason = prompt('許容する理由（社内合意、暫定運用等）を入力してください:', '運用要件に基づくリスク受容') || '運用上のリスク受容';
      await chrome.runtime.sendMessage({
        type: 'SAVE_FINDING_EXCEPTION',
        exception: {
          id: `ex_${Date.now()}`,
          findingId: check.findingId,
          checkId: check.checkId,
          targetUrl: currentReport?.url,
          status: 'accepted',
          reason,
          createdAt: new Date().toISOString(),
        },
      });
      detailModal.classList.add('hidden');
      runScan();
    });
  }

  const fpBtn = document.getElementById('modalFalsePositiveBtn');
  if (fpBtn && check.findingId) {
    fpBtn.addEventListener('click', async () => {
      const reason = prompt('誤検知の理由を入力してください:', '対象環境における仕様上不要') || '誤検知';
      await chrome.runtime.sendMessage({
        type: 'SAVE_FINDING_EXCEPTION',
        exception: {
          id: `ex_${Date.now()}`,
          findingId: check.findingId,
          checkId: check.checkId,
          targetUrl: currentReport?.url,
          status: 'false-positive',
          reason,
          createdAt: new Date().toISOString(),
        },
      });
      detailModal.classList.add('hidden');
      runScan();
    });
  }

  const revokeBtn = document.getElementById('modalRevokeExceptionBtn');
  if (revokeBtn && (check.exceptionId || check.findingId)) {
    revokeBtn.addEventListener('click', async () => {
      await chrome.runtime.sendMessage({
        type: 'DELETE_FINDING_EXCEPTION',
        id: check.exceptionId || check.findingId,
      });
      detailModal.classList.add('hidden');
      runScan();
    });
  }

  detailModal.classList.remove('hidden');
}

function showCookieModal(cookie: InspectedCookieInfo): void {
  modalTitle.textContent = `Cookie: ${cookie.name}`;
  modalBody.innerHTML = renderCookieModalHtml(cookie);
  detailModal.classList.remove('hidden');
}
