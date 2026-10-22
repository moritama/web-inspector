/**
 * Web Technology & Security Inspector
 * ポップアップ画面コントローラー (src/popup/popup.ts)
 */

import { downloadCsvFile } from '../export/csv';
import { downloadJsonFile } from '../export/json';
import {
  DetectedTechnology,
  InspectedCookieInfo,
  InspectionReport,
  SecurityCheckResult,
} from '../shared/types';

// 現在表示中のレポート
let currentReport: InspectionReport | null = null;

// DOM要素参照
const siteHostnameEl = document.getElementById('siteHostname') as HTMLElement;
const statusIndicatorEl = document.getElementById('statusIndicator') as HTMLElement;
const techCountEl = document.getElementById('techCount') as HTMLElement;
const attentionCountEl = document.getElementById('attentionCount') as HTMLElement;
const checkCountEl = document.getElementById('checkCount') as HTMLElement;
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

/**
 * 初期化処理
 */
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  setupEventListeners();
  runScan();
});

/**
 * テーマの復元と切り替え設定
 */
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

/**
 * イベントリスナーの登録
 */
function setupEventListeners(): void {
  // テーマ切り替え
  themeToggleBtn.addEventListener('click', toggleTheme);

  // 再調査
  rescanBtn.addEventListener('click', () => {
    runScan();
  });

  // ダッシュボードを開く
  openDashboardBtn.addEventListener('click', openDashboard);
  fullReportBtn.addEventListener('click', openDashboard);

  // エクスポート
  exportJsonBtn.addEventListener('click', () => {
    if (currentReport) downloadJsonFile(currentReport);
  });
  exportCsvBtn.addEventListener('click', () => {
    if (currentReport) downloadCsvFile(currentReport);
  });

  // タブ切り替え
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

  // モーダル閉じる
  closeModalBtn.addEventListener('click', () => {
    detailModal.classList.add('hidden');
  });

  detailModal.addEventListener('click', (e) => {
    if (e.target === detailModal) {
      detailModal.classList.add('hidden');
    }
  });
}

/**
 * ダッシュボード（詳細画面）を新しいタブで開く
 */
function openDashboard(): void {
  const dashboardUrl = chrome.runtime.getURL('dashboard.html');
  chrome.tabs.create({ url: dashboardUrl });
}

/**
 * 調査を実行
 */
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
    techsListEl.innerHTML = `<div class="empty-state" style="color: #EF4444;">${message}</div>`;
  }
}

/**
 * 調査結果をUIに反映
 */
function renderReport(report: InspectionReport): void {
  statusIndicatorEl.className = 'status-indicator ready';
  siteHostnameEl.textContent = report.hostname;

  // サマリー数値の更新
  techCountEl.textContent = String(report.technologies.length);
  attentionCountEl.textContent = String(report.summary.requiresAttentionCount);
  checkCountEl.textContent = String(report.securityChecks.length);

  tabTechCountEl.textContent = String(report.technologies.length);
  tabSecCountEl.textContent = String(report.securityChecks.length);
  tabCookieCountEl.textContent = String(report.cookies.length);

  // 1. 使用技術リスト
  renderTechnologies(report.technologies);

  // 2. セキュリティ診断リスト
  renderSecurityChecks(report.securityChecks);

  // 3. Cookie診断リスト
  renderCookies(report.cookies);
}

/**
 * 使用技術の描画
 */
function renderTechnologies(techs: DetectedTechnology[]): void {
  if (techs.length === 0) {
    techsListEl.innerHTML = '<div class="empty-state">明確な固有技術シグナルは検出されませんでした</div>';
    return;
  }

  techsListEl.innerHTML = '';
  techs.forEach((t) => {
    const row = document.createElement('div');
    row.className = 'item-row';

    const confClass = t.confidenceLevel === 'high' ? 'badge-high' : t.confidenceLevel === 'medium' ? 'badge-medium' : 'badge-low';
    const confLabel = t.confidenceLevel === 'high' ? '高' : t.confidenceLevel === 'medium' ? '中' : '低';

    row.innerHTML = `
      <div class="item-main">
        <div class="tech-icon-badge">${t.technology.slice(0, 2).toUpperCase()}</div>
        <div class="item-texts">
          <span class="item-name">${escapeHtml(t.technology)}</span>
          <div class="item-meta">
            ${t.version ? `<span class="item-version-badge">v${escapeHtml(t.version)}</span>` : '<span class="item-version-badge">バージョン不明</span>'}
            <span>${escapeHtml(formatCategory(t.category))}</span>
          </div>
        </div>
      </div>
      <div class="item-side">
        <span class="badge ${confClass}">${confLabel} · ${t.confidence}</span>
      </div>
    `;

    row.addEventListener('click', () => showTechModal(t));
    techsListEl.appendChild(row);
  });
}

/**
 * セキュリティ診断結果の描画
 */
function renderSecurityChecks(checks: SecurityCheckResult[]): void {
  if (checks.length === 0) {
    securityListEl.innerHTML = '<div class="empty-state">診断項目がありません</div>';
    return;
  }

  securityListEl.innerHTML = '';
  checks.forEach((c) => {
    const row = document.createElement('div');
    row.className = 'item-row';

    let sevClass = 'sev-info';
    let sevLabel = '情報';
    if (c.status === 'pass') {
      sevClass = 'sev-pass';
      sevLabel = '適正';
    } else if (c.severity === 'high') {
      sevClass = 'sev-high';
      sevLabel = '危険';
    } else if (c.severity === 'medium') {
      sevClass = 'sev-medium';
      sevLabel = '警告';
    } else if (c.severity === 'low') {
      sevClass = 'sev-low';
      sevLabel = '注意';
    }

    row.innerHTML = `
      <div class="item-main">
        <div class="item-texts">
          <span class="item-name">${escapeHtml(c.name)}</span>
          <span class="item-meta">${escapeHtml(c.observed.substring(0, 40))}</span>
        </div>
      </div>
      <div class="item-side">
        <span class="badge ${sevClass}">${sevLabel}</span>
      </div>
    `;

    row.addEventListener('click', () => showSecurityModal(c));
    securityListEl.appendChild(row);
  });
}

/**
 * Cookie診断リストの描画
 */
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
            <span>SameSite: ${escapeHtml(c.sameSite)}</span>
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
 * 技術詳細モーダルの表示
 */
function showTechModal(tech: DetectedTechnology): void {
  modalTitle.textContent = `${tech.technology} 検出詳細`;
  modalBody.innerHTML = `
    <div>
      <div class="detail-section-title">判定情報</div>
      <div>確信度スコア: <strong>${tech.confidence}</strong> (${tech.confidenceLevel === 'high' ? '高' : tech.confidenceLevel === 'medium' ? '中' : '低'})</div>
      <div>検出バージョン: <strong>${tech.version || '不明（明示的なシグナルなし）'}</strong></div>
      <div>カテゴリ: ${escapeHtml(formatCategory(tech.category))}</div>
      ${tech.website ? `<div>公式サイト: <a href="${tech.website}" target="_blank" class="ref-link">${tech.website}</a></div>` : ''}
    </div>

    <div>
      <div class="detail-section-title">判定根拠 (エビデンス)</div>
      ${tech.evidence
        .map(
          (e) => `
        <div class="evidence-item">
          <div><strong>[${e.type}]</strong> ${escapeHtml(e.name)}</div>
          <div class="detail-box">${escapeHtml(e.value)}</div>
          ${e.detail ? `<div style="font-size:11px;color:var(--text-muted);">${escapeHtml(e.detail)}</div>` : ''}
        </div>
      `
        )
        .join('')}
    </div>
  `;
  detailModal.classList.remove('hidden');
}

/**
 * セキュリティ診断詳細モーダルの表示
 */
function showSecurityModal(check: SecurityCheckResult): void {
  modalTitle.textContent = check.name;
  modalBody.innerHTML = `
    <div>
      <div class="detail-section-title">観測された値</div>
      <div class="detail-box">${escapeHtml(check.observed)}</div>
    </div>

    <div>
      <div class="detail-section-title">現状・セキュリティ上の意味</div>
      <div>${escapeHtml(check.description)}</div>
    </div>

    <div>
      <div class="detail-section-title">推奨される対応方法</div>
      <div style="color:var(--accent-color);">${escapeHtml(check.recommendation)}</div>
    </div>

    ${
      check.referenceUrls && check.referenceUrls.length > 0
        ? `
      <div>
        <div class="detail-section-title">参考資料</div>
        ${check.referenceUrls
          .map((url) => `<a href="${url}" target="_blank" class="ref-link">${url}</a>`)
          .join('')}
      </div>
    `
        : ''
    }
  `;
  detailModal.classList.remove('hidden');
}

/**
 * Cookie詳細モーダルの表示
 */
function showCookieModal(cookie: InspectedCookieInfo): void {
  modalTitle.textContent = `Cookie: ${cookie.name}`;
  modalBody.innerHTML = `
    <div>
      <div class="detail-section-title">属性詳細 (※値は取得・保存しません)</div>
      <div>ドメイン: <strong>${escapeHtml(cookie.domain)}</strong></div>
      <div>パス: <strong>${escapeHtml(cookie.path)}</strong></div>
      <div>Secure: <strong>${cookie.secure ? '有効' : '無効'}</strong></div>
      <div>HttpOnly: <strong>${cookie.httpOnly ? '有効' : '無効'}</strong></div>
      <div>SameSite: <strong>${escapeHtml(cookie.sameSite)}</strong></div>
      <div>有効期間: <strong>${cookie.session ? 'セッションCookie' : '永続Cookie'}</strong></div>
    </div>

    ${
      cookie.issues && cookie.issues.length > 0
        ? `
      <div>
        <div class="detail-section-title" style="color:var(--warning-color);">検出された課題</div>
        <ul style="padding-left:16px;">
          ${cookie.issues.map((iss) => `<li>${escapeHtml(iss)}</li>`).join('')}
        </ul>
      </div>
    `
        : '<div style="color:var(--success-color);">重大な属性設定の不備は検出されませんでした。</div>'
    }
  `;
  detailModal.classList.remove('hidden');
}

function formatCategory(cat: string): string {
  const map: Record<string, string> = {
    'web-server': 'Webサーバー',
    'programming-language': '開発言語・フレームワーク',
    'cms': 'CMS',
    'js-framework': 'JSフレームワーク',
    'js-css-library': 'JS / CSSライブラリ',
    'cdn-waf': 'CDN / WAF',
  };
  return map[cat] || cat;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
