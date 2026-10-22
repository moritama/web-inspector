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
    const ver = chrome.runtime?.getManifest?.()?.version || '1.3.3';
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
    techsListEl.innerHTML = `<div class="empty-state" style="color: #EF4444;">${message}</div>`;
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
  renderTechnologies(report.technologies);

  // 2. セキュリティ診断一覧
  renderSecurityChecks(report.securityChecks);

  // 3. Cookie診断一覧
  renderCookies(report.cookies);
}

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

    // EOLバッジ
    let eolBadgeHtml = '';
    if (t.supportStatus === 'EOL') {
      eolBadgeHtml = '<span class="badge badge-eol">EOL</span>';
    } else if (t.supportStatus === 'Maintenance') {
      eolBadgeHtml = '<span class="badge badge-medium">保守</span>';
    }

    // CVEバッジ
    let cveBadgeHtml = '';
    if (t.advisories && t.advisories.length > 0) {
      cveBadgeHtml = `<span class="badge badge-cve">CVE ${t.maxCvss ? `CVSS ${t.maxCvss}` : `${t.advisories.length}件`}</span>`;
    }

    // 不一致バッジ
    let mismatchBadgeHtml = '';
    if (t.versionIntegrity?.status === 'mismatch') {
      mismatchBadgeHtml = '<span class="badge badge-mismatch">不一致</span>';
    }

    // バージョン表示
    let verLabel = t.version ? `v${escapeHtml(t.version)}` : 'バージョン不明';
    if (t.versionSource === 'runtime') {
      verLabel += ' (実行時)';
    }

    row.innerHTML = `
      <div class="item-main">
        <div class="tech-icon-badge">${t.technology.slice(0, 2).toUpperCase()}</div>
        <div class="item-texts">
          <span class="item-name">${escapeHtml(t.technology)}</span>
          <div class="item-meta">
            <span class="item-version-badge">${escapeHtml(verLabel)}</span>
            <span>${escapeHtml(formatCategory(t.category))}</span>
          </div>
        </div>
      </div>
      <div class="item-side">
        ${mismatchBadgeHtml}
        ${eolBadgeHtml}
        ${cveBadgeHtml}
        <span class="badge ${confClass}">${confLabel} · ${t.confidence}</span>
      </div>
    `;

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

    const isAccepted =
      c.exceptionStatus === 'accepted' ||
      c.exceptionStatus === 'false-positive' ||
      c.exceptionStatus === 'muted';
    const exceptionBadge = isAccepted
      ? '<span class="badge" style="background:#4B5563;color:#E5E7EB;margin-right:4px;">許容済</span>'
      : '';

    row.innerHTML = `
      <div class="item-main">
        <div class="item-texts">
          <span class="item-name">${escapeHtml(c.name)}</span>
          <span class="item-meta">${escapeHtml(c.observed.substring(0, 42))}</span>
        </div>
      </div>
      <div class="item-side">
        ${exceptionBadge}
        <span class="badge ${sevClass}">${sevLabel}</span>
      </div>
    `;

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
 * 技術詳細モーダル (Version 1.1)
 */
function showTechModal(tech: DetectedTechnology): void {
  modalTitle.textContent = `${tech.technology} 検出 & セキュリティ詳細`;

  // バージョン整合性ブロック
  let integrityHtml = '';
  if (tech.versionIntegrity) {
    const int = tech.versionIntegrity;
    const statusColor = int.status === 'match' ? 'var(--success-color)' : int.status === 'mismatch' ? 'var(--warning-color)' : 'var(--text-muted)';
    integrityHtml = `
      <div>
        <div class="detail-section-title">CSS / JavaScript バージョン整合性</div>
        <div>JavaScript: <strong>${escapeHtml(int.jsVersion || '未検出')}</strong> / CSS: <strong>${escapeHtml(int.cssVersion || '未検出')}</strong></div>
        <div style="color:${statusColor};font-weight:600;margin-top:2px;">判定: ${int.status === 'match' ? '一致 (OK)' : int.status === 'mismatch' ? '要確認 (バージョン不一致)' : '判定不能'}</div>
        <div style="font-size:11px;color:var(--text-muted);">${escapeHtml(int.detail)}</div>
      </div>
    `;
  }

  // EOLサポート状況ブロック
  let eolHtml = '';
  if (tech.eolInfo) {
    const eol = tech.eolInfo;
    const statusColor = eol.status === 'EOL' ? 'var(--danger-color)' : eol.status === 'Maintenance' ? 'var(--warning-color)' : 'var(--success-color)';
    eolHtml = `
      <div>
        <div class="detail-section-title">サポート状況 (EOL)</div>
        <div>ステータス: <strong style="color:${statusColor};">${eol.status}</strong> ${eol.eolDate ? `(EOL日: ${eol.eolDate})` : ''}</div>
        <div style="font-size:11px;color:var(--accent-color);">${escapeHtml(eol.recommendation)}</div>
        ${eol.sourceUrl ? `<div>出典: <a href="${eol.sourceUrl}" target="_blank" class="ref-link">${eol.sourceUrl}</a></div>` : ''}
      </div>
    `;
  }

  // 既知脆弱性 (CVE) ブロック
  let cveHtml = '';
  const statusLabel = tech.offlineMatchStatus || 'Not Covered';
  const staleNotice = tech.isStale ? '<span style="color:var(--warning-color);margin-left:6px;font-size:11px;">⚠️ DB鮮度: 31日以上経過</span>' : '';

  if (tech.advisories && tech.advisories.length > 0) {
    cveHtml = `
      <div>
        <div class="detail-section-title" style="color:var(--danger-color);">該当する既知脆弱性 (${tech.advisories.length} 件) ${staleNotice}</div>
        <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px;">照合ステータス: <strong>${statusLabel}</strong></div>
        ${tech.advisories
          .map(
            (adv) => `
          <div class="advisory-card">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <strong>${escapeHtml(adv.id)}</strong>
              ${adv.cvssScore ? `<span class="badge sev-high">CVSS ${adv.cvssScore}</span>` : ''}
            </div>
            <div style="font-weight:600;margin-top:2px;">${escapeHtml(adv.title)}</div>
            <div style="font-size:11px;color:var(--text-secondary);margin-top:4px;">${escapeHtml(adv.summary)}</div>
            <div style="font-size:11px;margin-top:4px;">
              <span>影響範囲: <code>${escapeHtml(adv.affectedRange)}</code></span>
              ${adv.fixedVersion ? `<span style="margin-left:8px;color:var(--success-color);">修正版: <strong>v${escapeHtml(adv.fixedVersion)}</strong></span>` : ''}
            </div>
            ${adv.referenceUrls.length > 0 ? `<div style="margin-top:4px;"><a href="${adv.referenceUrls[0]}" target="_blank" class="ref-link">詳細情報 (NVD / GitHub)</a></div>` : ''}
          </div>
        `
          )
          .join('')}
      </div>
    `;
  } else {
    let statusText = 'この技術のオフライン脆弱性データは未収録です。';
    if (statusLabel === 'No Match') {
      statusText = 'オフラインDBに収録されていますが、検出されたバージョンには該当する既知脆弱性はありません。';
    } else if (statusLabel === 'Unknown Version') {
      statusText = 'バージョン不明、またはLinuxディストリビューション固有パッケージのため脆弱性断定を保留しています。';
    }
    cveHtml = `
      <div>
        <div class="detail-section-title">脆弱性照合状況 (オフラインDB) ${staleNotice}</div>
        <div style="font-size:12px;">ステータス: <strong>${statusLabel}</strong></div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">${escapeHtml(statusText)}</div>
      </div>
    `;
  }

  modalBody.innerHTML = `
    <div>
      <div class="detail-section-title">基本情報</div>
      <div>確信度スコア: <strong>${tech.confidence}</strong> (${tech.confidenceLevel.toUpperCase()})</div>
      <div>代表バージョン: <strong>${tech.version || '不明'}</strong> ${tech.versionSource ? `[取得元: ${escapeHtml(tech.versionSource)}]` : ''}</div>
      <div>カテゴリ: ${escapeHtml(formatCategory(tech.category))}</div>
      ${tech.website ? `<div>公式サイト: <a href="${tech.website}" target="_blank" class="ref-link">${tech.website}</a></div>` : ''}
    </div>

    ${integrityHtml}
    ${eolHtml}
    ${cveHtml}

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

function showSecurityModal(check: SecurityCheckResult): void {
  modalTitle.textContent = check.name;

  const isAccepted =
    check.exceptionStatus === 'accepted' ||
    check.exceptionStatus === 'false-positive' ||
    check.exceptionStatus === 'muted';

  let exceptionSectionHtml = '';
  if (isAccepted) {
    exceptionSectionHtml = `
      <div style="background:rgba(59,130,246,0.1);border:1px solid rgba(59,130,246,0.3);border-radius:6px;padding:8px 12px;margin-top:12px;">
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <div>
            <strong style="color:var(--accent-color);">🛡️ この指摘は許容設定済みです</strong>
            <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">理由: ${escapeHtml(check.exceptionReason || '未指定')}</div>
          </div>
          <button id="modalRevokeExceptionBtn" class="action-btn" style="font-size:11px;padding:3px 8px;">許容を解除</button>
        </div>
      </div>
    `;
  } else if (check.status === 'warning' || check.status === 'fail') {
    exceptionSectionHtml = `
      <div style="margin-top:12px;display:flex;gap:8px;">
        <button id="modalAcceptFindingBtn" class="action-btn" style="flex:1;font-size:11px;padding:6px 10px;">
          🛡️ この指摘を許容する (リスク受容)
        </button>
        <button id="modalFalsePositiveBtn" class="action-btn" style="flex:1;font-size:11px;padding:6px 10px;">
          ❌ 誤検知として除外
        </button>
      </div>
    `;
  }

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

    ${exceptionSectionHtml}
  `;

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
  modalBody.innerHTML = `
    <div>
      <div class="detail-section-title">属性詳細 (※値は除外)</div>
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
