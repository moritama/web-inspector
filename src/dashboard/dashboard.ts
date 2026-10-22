/**
 * Web Technology & Security Inspector
 * 詳細ダッシュボードコントローラー (src/dashboard/dashboard.ts) - Version 1.1.0
 */

import { downloadCsvFile } from '../export/csv';
import { downloadJsonFile } from '../export/json';
import { compareReports } from '../storage/history';
import {
  DetectedTechnology,
  InspectionReport,
  SecurityCheckResult,
} from '../shared/types';

let currentReport: InspectionReport | null = null;
let allReportsList: InspectionReport[] = [];

// DOM要素参照
const currentHostnameEl = document.getElementById('currentHostname') as HTMLElement;
const inspectedAtTimeEl = document.getElementById('inspectedAtTime') as HTMLElement;
const dashTotalTechsEl = document.getElementById('dashTotalTechs') as HTMLElement;
const dashAttentionCountEl = document.getElementById('dashAttentionCount') as HTMLElement;
const dashEolCountEl = document.getElementById('dashEolCount') as HTMLElement;
const dashVulnCountEl = document.getElementById('dashVulnCount') as HTMLElement;
const dashHttpsStatusEl = document.getElementById('dashHttpsStatus') as HTMLElement;
const dashMixedStatusEl = document.getElementById('dashMixedStatus') as HTMLElement;

const overviewLibrarySecListEl = document.getElementById('overviewLibrarySecList') as HTMLElement;
const overviewSecurityListEl = document.getElementById('overviewSecurityList') as HTMLElement;
const librarySecurityTableContainerEl = document.getElementById('librarySecurityTableContainer') as HTMLElement;
const fullTechsContainerEl = document.getElementById('fullTechsContainer') as HTMLElement;
const fullSecurityContainerEl = document.getElementById('fullSecurityContainer') as HTMLElement;
const cookiesTableBodyEl = document.getElementById('cookiesTableBody') as HTMLElement;
const historyListContainerEl = document.getElementById('historyListContainer') as HTMLElement;

const compareSelectA = document.getElementById('compareSelectA') as HTMLSelectElement;
const compareSelectB = document.getElementById('compareSelectB') as HTMLSelectElement;
const executeCompareBtn = document.getElementById('executeCompareBtn') as HTMLButtonElement;
const compareResultContainer = document.getElementById('compareResultContainer') as HTMLElement;

const themeToggleBtn = document.getElementById('themeToggleBtn') as HTMLButtonElement;
const exportJsonBtn = document.getElementById('exportJsonBtn') as HTMLButtonElement;
const exportCsvBtn = document.getElementById('exportCsvBtn') as HTMLButtonElement;
const refreshBtn = document.getElementById('refreshBtn') as HTMLButtonElement;
const clearHistoryBtn = document.getElementById('clearHistoryBtn') as HTMLButtonElement;

document.addEventListener('DOMContentLoaded', async () => {
  initTheme();
  setupVersionBadge();
  setupNav();
  setupActions();
  await loadDashboardData();
});

function setupVersionBadge(): void {
  const badgeEl = document.getElementById('dashboardVersion');
  if (badgeEl) {
    const ver = chrome.runtime?.getManifest?.()?.version;
    if (ver) {
      badgeEl.textContent = `v${ver}`;
    }
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
      }
    });
  });
}

function setupActions(): void {
  themeToggleBtn.addEventListener('click', toggleTheme);
  refreshBtn.addEventListener('click', loadDashboardData);

  exportJsonBtn.addEventListener('click', () => {
    if (currentReport) downloadJsonFile(currentReport);
  });

  exportCsvBtn.addEventListener('click', () => {
    if (currentReport) downloadCsvFile(currentReport);
  });

  clearHistoryBtn.addEventListener('click', async () => {
    if (confirm('すべての調査履歴を完全に削除しますか？')) {
      await chrome.runtime.sendMessage({ type: 'CLEAR_HISTORY' });
      await loadDashboardData();
    }
  });

  executeCompareBtn.addEventListener('click', handleCompare);
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
  currentHostnameEl.textContent = report.hostname;
  inspectedAtTimeEl.textContent = `調査日時: ${new Date(report.inspectedAt).toLocaleString('ja-JP')}`;

  // サマリーカード
  dashTotalTechsEl.textContent = String(report.technologies.length);
  dashAttentionCountEl.textContent = String(report.summary.requiresAttentionCount);

  const eolCount = report.summary.librarySecurity?.eolCount ?? 0;
  const vulnCount = report.summary.librarySecurity?.vulnerableLibraryCount ?? 0;
  dashEolCountEl.textContent = String(eolCount);
  dashVulnCountEl.textContent = `既知脆弱性: ${vulnCount}件 / 不一致: ${report.summary.librarySecurity?.mismatchCount ?? 0}件`;

  dashHttpsStatusEl.textContent = report.summary.isHttps ? 'HTTPS (暗号化)' : 'HTTP (非暗号化)';
  dashMixedStatusEl.textContent = `混在コンテンツ: ${report.summary.mixedContentCount}件`;

  // 1. 概要ビュー
  renderOverviewLibrarySec(report.technologies);
  renderOverviewSecurity(report.securityChecks);

  // 2. ライブラリセキュリティビュー (Version 1.1 ADD-06)
  renderLibrarySecurityView(report.technologies);

  // 3. 検出技術 & エビデンス
  renderFullTechnologies(report.technologies);

  // 4. HTTPセキュリティ診断
  renderFullSecurity(report.securityChecks);

  // 5. Cookieテーブル
  renderCookiesTable(report.cookies);
}

function renderOverviewLibrarySec(techs: DetectedTechnology[]): void {
  const alerted = techs.filter(
    (t) =>
      t.supportStatus === 'EOL' ||
      (t.advisories && t.advisories.length > 0) ||
      t.versionIntegrity?.status === 'mismatch'
  );

  if (alerted.length === 0) {
    overviewLibrarySecListEl.innerHTML = '<div style="color:var(--success-color);padding:12px 0;">ライブラリのサポート終了や既知脆弱性は検出されませんでした。</div>';
    return;
  }

  overviewLibrarySecListEl.innerHTML = alerted
    .map((t) => {
      let issues: string[] = [];
      if (t.supportStatus === 'EOL') issues.push(`EOL (${t.eolDate || 'サポート終了'})`);
      if (t.advisories && t.advisories.length > 0) issues.push(`CVE ${t.advisories.length}件`);
      if (t.versionIntegrity?.status === 'mismatch') issues.push('CSS/JS不一致');

      return `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border-color);">
          <div>
            <strong>${escapeHtml(t.technology)}</strong>
            <span style="color:var(--text-muted);font-size:12px;margin-left:6px;">${t.version ? `v${escapeHtml(t.version)}` : ''}</span>
            <div style="font-size:11px;color:var(--text-sub);">${escapeHtml(issues.join(' / '))}</div>
          </div>
          <span class="badge ${t.supportStatus === 'EOL' ? 'badge-eol' : 'badge-cve'}">要確認</span>
        </div>
      `;
    })
    .join('');
}

function renderOverviewSecurity(checks: SecurityCheckResult[]): void {
  const issues = checks.filter((c) => c.status === 'warning' || c.status === 'fail');
  if (issues.length === 0) {
    overviewSecurityListEl.innerHTML = '<div style="color:var(--success-color);padding:12px 0;">重大なセキュリティ設定不備は検出されませんでした。</div>';
    return;
  }

  overviewSecurityListEl.innerHTML = issues
    .slice(0, 5)
    .map(
      (c) => `
    <div style="padding:8px 0;border-bottom:1px solid var(--border-color);">
      <div style="display:flex;justify-content:space-between;">
        <strong>${escapeHtml(c.name)}</strong>
        <span class="badge ${c.severity === 'high' ? 'sev-high' : 'sev-medium'}">${c.severity.toUpperCase()}</span>
      </div>
      <div style="font-size:12px;color:var(--text-sub);margin-top:2px;">${escapeHtml(c.description)}</div>
    </div>
  `
    )
    .join('');
}

/**
 * ライブラリセキュリティビューの描画 (Version 1.1 ADD-06)
 */
function renderLibrarySecurityView(techs: DetectedTechnology[]): void {
  if (techs.length === 0) {
    librarySecurityTableContainerEl.innerHTML = '<div class="empty-state">技術情報がありません</div>';
    return;
  }

  const rows = techs
    .map((t) => {
      const eolBadge =
        t.supportStatus === 'EOL'
          ? '<span class="badge badge-eol">EOL</span>'
          : t.supportStatus === 'Maintenance'
          ? '<span class="badge badge-medium">保守</span>'
          : t.supportStatus === 'Supported'
          ? '<span class="badge badge-high">Supported</span>'
          : '<span class="badge" style="background:var(--bg-hover);">Unknown</span>';

      let cveBadge = '<span class="badge sev-pass">該当なし</span>';
      if (t.offlineMatchStatus === 'Matched' || (t.advisories && t.advisories.length > 0)) {
        cveBadge = `<span class="badge badge-cve">該当 ${t.advisories?.length ?? 0}件 (CVSS ${t.maxCvss || '6.1'})</span>`;
      } else if (t.offlineMatchStatus === 'Not Covered') {
        cveBadge = '<span style="color:var(--text-muted);font-size:11px;">未登録</span>';
      } else if (t.offlineMatchStatus === 'Unknown Version') {
        cveBadge = '<span class="badge badge-medium">要確認</span>';
      }

      if (t.isStale) {
        cveBadge += ' <span style="font-size:10px;color:var(--warning-color);">[DB古]</span>';
      }

      const integrityBadge = t.versionIntegrity
        ? t.versionIntegrity.status === 'match'
          ? '<span class="badge badge-high">一致</span>'
          : t.versionIntegrity.status === 'mismatch'
          ? '<span class="badge badge-medium">不一致</span>'
          : '<span style="color:var(--text-muted);font-size:11px;">判定不能</span>'
        : '<span style="color:var(--text-muted);font-size:11px;">-</span>';

      let recommendation = '現状維持';
      if (t.advisories && t.advisories.length > 0) {
        recommendation = `脆弱性修正版（v${t.advisories[0].fixedVersion || '最新'}以上）への更新推奨`;
      } else if (t.supportStatus === 'EOL') {
        recommendation = 'EOLのため最新LTS系列への移行推奨';
      } else if (t.offlineMatchStatus === 'Unknown Version' && t.version) {
        recommendation = 'パッケージ固有版のため個別セキュリティ情報の確認を推奨';
      }

      return `
        <tr>
          <td><strong>${escapeHtml(t.technology)}</strong></td>
          <td>${t.version ? `v${escapeHtml(t.version)}` : '<span style="color:var(--text-muted);">不明</span>'}</td>
          <td>${escapeHtml(t.versionSource || '-')}</td>
          <td>${integrityBadge}</td>
          <td>${eolBadge} ${t.eolDate ? `<span style="font-size:11px;color:var(--text-muted);">(${t.eolDate})</span>` : ''}</td>
          <td>${cveBadge}</td>
          <td style="font-size:12px;color:var(--accent-color);">${escapeHtml(recommendation)}</td>
        </tr>
      `;
    })
    .join('');

  librarySecurityTableContainerEl.innerHTML = `
    <div class="table-responsive">
      <table class="data-table">
        <thead>
          <tr>
            <th>技術・ライブラリ名</th>
            <th>代表バージョン</th>
            <th>取得元</th>
            <th>CSS/JS整合性</th>
            <th>サポート状態 (EOL)</th>
            <th>既知脆弱性 (CVE)</th>
            <th>推奨対応</th>
          </tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
      </table>
    </div>
  `;
}

function renderFullTechnologies(techs: DetectedTechnology[]): void {
  if (techs.length === 0) {
    fullTechsContainerEl.innerHTML = '<div class="empty-state">明確な固有技術シグナルは検出されませんでした</div>';
    return;
  }

  fullTechsContainerEl.innerHTML = techs
    .map(
      (t) => `
    <div class="accordion-item">
      <div class="accordion-header">
        <div style="display:flex;align-items:center;gap:12px;">
          <span style="font-weight:700;font-size:15px;">${escapeHtml(t.technology)}</span>
          ${t.version ? `<span class="badge" style="background:var(--bg-hover);">v${escapeHtml(t.version)}</span>` : '<span style="font-size:11px;color:var(--text-muted);">バージョン不明</span>'}
          <span style="font-size:12px;color:var(--text-muted);">${escapeHtml(t.category)}</span>
        </div>
        <div style="display:flex;gap:6px;">
          ${t.supportStatus === 'EOL' ? '<span class="badge badge-eol">EOL</span>' : ''}
          ${t.advisories && t.advisories.length > 0 ? `<span class="badge badge-cve">CVE ${t.advisories.length}件</span>` : ''}
          <span class="badge ${t.confidenceLevel === 'high' ? 'badge-high' : 'badge-medium'}">確信度 ${t.confidence}</span>
        </div>
      </div>
      <div class="accordion-body">
        <div>${escapeHtml(t.description || '')}</div>
        ${t.website ? `<div>公式サイト: <a href="${t.website}" target="_blank" style="color:var(--accent-color);">${t.website}</a></div>` : ''}
        
        ${
          t.versionIntegrity
            ? `
          <div style="margin-top:8px;padding:8px;border:1px solid var(--border-color);border-radius:4px;background:var(--bg-surface);">
            <strong>CSS / JS バージョン整合性:</strong>
            <div>JavaScript: ${escapeHtml(t.versionIntegrity.jsVersion || '未検出')} / CSS: ${escapeHtml(t.versionIntegrity.cssVersion || '未検出')}</div>
            <div style="color:${t.versionIntegrity.status === 'match' ? 'var(--success-color)' : 'var(--warning-color)'};">${escapeHtml(t.versionIntegrity.detail)}</div>
          </div>
        `
            : ''
        }

        ${
          t.advisories && t.advisories.length > 0
            ? `
          <div style="margin-top:8px;">
            <strong style="color:var(--danger-color);">該当する既知脆弱性 (CVE / GHSA):</strong>
            <ul style="padding-left:18px;margin-top:4px;">
              ${t.advisories
                .map(
                  (adv) => `
                <li style="margin-bottom:6px;">
                  <strong>${escapeHtml(adv.id)}</strong> (${adv.title}) - 影響範囲: <code>${escapeHtml(adv.affectedRange)}</code>
                  ${adv.fixedVersion ? `<span style="color:var(--success-color);margin-left:6px;">修正版: v${escapeHtml(adv.fixedVersion)}</span>` : ''}
                </li>
              `
                )
                .join('')}
            </ul>
          </div>
        `
            : ''
        }

        <div style="font-weight:700;margin-top:8px;">判定根拠 (Evidence):</div>
        <ul style="padding-left:18px;">
          ${t.evidence
            .map(
              (e) => `
            <li>
              <strong>[${e.type}] ${escapeHtml(e.name)}:</strong>
              <code>${escapeHtml(e.value)}</code>
              ${e.detail ? `<span style="color:var(--text-muted);margin-left:6px;">(${escapeHtml(e.detail)})</span>` : ''}
            </li>
          `
            )
            .join('')}
        </ul>
      </div>
    </div>
  `
    )
    .join('');
}

function renderFullSecurity(checks: SecurityCheckResult[]): void {
  fullSecurityContainerEl.innerHTML = checks
    .map(
      (c) => `
    <div class="accordion-item">
      <div class="accordion-header">
        <div style="display:flex;align-items:center;gap:12px;">
          <span style="font-weight:700;font-size:14px;">${escapeHtml(c.name)}</span>
          <span style="font-size:11px;color:var(--text-muted);">${escapeHtml(c.checkId)}</span>
        </div>
        <span class="badge ${c.status === 'pass' ? 'sev-pass' : c.severity === 'high' ? 'sev-high' : 'sev-medium'}">${c.status === 'pass' ? 'PASS' : c.severity.toUpperCase()}</span>
      </div>
      <div class="accordion-body">
        <div><strong>観測値:</strong> <code>${escapeHtml(c.observed)}</code></div>
        <div><strong>セキュリティ上の影響:</strong> ${escapeHtml(c.description)}</div>
        <div style="color:var(--accent-color);"><strong>推奨対応:</strong> ${escapeHtml(c.recommendation)}</div>
        ${
          c.referenceUrls.length > 0
            ? `
          <div><strong>参考資料:</strong>
            ${c.referenceUrls
              .map((u) => `<a href="${u}" target="_blank" style="color:var(--accent-color);margin-left:8px;">${u}</a>`)
              .join(', ')}
          </div>
        `
            : ''
        }
      </div>
    </div>
  `
    )
    .join('');
}

function renderCookiesTable(cookies: any[]): void {
  if (!cookies || cookies.length === 0) {
    cookiesTableBodyEl.innerHTML = '<tr><td colspan="8" class="empty-state">Cookieは検出されませんでした</td></tr>';
    return;
  }

  cookiesTableBodyEl.innerHTML = cookies
    .map(
      (c) => `
    <tr>
      <td><strong>${escapeHtml(c.name)}</strong></td>
      <td>${escapeHtml(c.domain)}</td>
      <td>${escapeHtml(c.path)}</td>
      <td>${c.secure ? '✅' : '❌'}</td>
      <td>${c.httpOnly ? '✅' : '❌'}</td>
      <td>${escapeHtml(c.sameSite)}</td>
      <td>${c.session ? 'セッション' : '永続'}</td>
      <td style="color:${c.issues.length > 0 ? 'var(--warning-color)' : 'var(--text-muted)'};">${c.issues.length > 0 ? escapeHtml(c.issues.join(', ')) : 'なし'}</td>
    </tr>
  `
    )
    .join('');
}

function renderHistoryList(reports: InspectionReport[]): void {
  if (reports.length === 0) {
    historyListContainerEl.innerHTML = '<div class="empty-state">保存された履歴はありません</div>';
    return;
  }

  historyListContainerEl.innerHTML = reports
    .map(
      (r) => `
    <div style="display:flex;align-items:center;justify-content:space-between;padding:12px;border:1px solid var(--border-color);border-radius:var(--radius-sm);margin-bottom:8px;background:var(--bg-surface);">
      <div>
        <strong>${escapeHtml(r.hostname)}</strong>
        <span style="font-size:12px;color:var(--text-muted);margin-left:8px;">${new Date(r.inspectedAt).toLocaleString('ja-JP')}</span>
        <div style="font-size:12px;color:var(--text-sub);margin-top:2px;">
          技術: ${r.technologies.length}件 / 要確認: ${r.summary.requiresAttentionCount}件 / EOL: ${r.summary.librarySecurity?.eolCount ?? 0}件 / ${r.summary.isHttps ? 'HTTPS' : 'HTTP'}
        </div>
      </div>
      <div style="display:flex;gap:6px;">
        <button class="btn btn-secondary btn-sm" onclick="window.viewReport('${r.id}')">表示</button>
        <button class="btn btn-danger btn-sm" onclick="window.deleteReport('${r.id}')">削除</button>
      </div>
    </div>
  `
    )
    .join('');
}

(window as any).viewReport = (id: string) => {
  const target = allReportsList.find((r) => r.id === id);
  if (target) {
    currentReport = target;
    renderDashboard(target);
    document.querySelector('.nav-item[data-view="overviewView"]')?.dispatchEvent(new Event('click'));
  }
};

(window as any).deleteReport = async (id: string) => {
  if (confirm('この調査レポートを削除しますか？')) {
    await chrome.runtime.sendMessage({ type: 'DELETE_HISTORY_ITEM', id });
    await loadDashboardData();
  }
};

function populateCompareSelects(reports: InspectionReport[]): void {
  compareSelectA.innerHTML = '';
  compareSelectB.innerHTML = '';

  reports.forEach((r, idx) => {
    const optA = document.createElement('option');
    optA.value = r.id;
    optA.textContent = `${r.hostname} (${new Date(r.inspectedAt).toLocaleString('ja-JP')})`;
    compareSelectA.appendChild(optA);

    const optB = document.createElement('option');
    optB.value = r.id;
    optB.textContent = `${r.hostname} (${new Date(r.inspectedAt).toLocaleString('ja-JP')})`;
    if (idx === 1 || (idx === 0 && reports.length === 1)) optB.selected = true;
    compareSelectB.appendChild(optB);
  });
}

function handleCompare(): void {
  const idA = compareSelectA.value;
  const idB = compareSelectB.value;

  const repA = allReportsList.find((r) => r.id === idA);
  const repB = allReportsList.find((r) => r.id === idB);

  if (!repA || !repB) return;

  const diff = compareReports(repA, repB);

  compareResultContainer.innerHTML = `
    <div class="diff-box">
      <div class="diff-title">技術スタック & バージョンの差分</div>
      <div>新規検出された技術: <span class="diff-added">${diff.addedTechnologies.length > 0 ? diff.addedTechnologies.join(', ') : 'なし'}</span></div>
      <div>未検出となった技術: <span class="diff-removed">${diff.removedTechnologies.length > 0 ? diff.removedTechnologies.join(', ') : 'なし'}</span></div>
      ${
        diff.versionChanges.length > 0
          ? `
        <div style="margin-top:6px;">バージョン変化:</div>
        <ul>
          ${diff.versionChanges.map((v) => `<li>${v.technology}: ${v.before || '不明'} &rarr; <strong>${v.after || '不明'}</strong></li>`).join('')}
        </ul>
      `
          : '<div>バージョン変化: なし</div>'
      }
    </div>

    <div class="diff-box">
      <div class="diff-title">セキュリティ課題の差分</div>
      <div>新たに検出された課題: <span class="diff-removed">${diff.newSecurityIssues.length > 0 ? diff.newSecurityIssues.join(', ') : 'なし'}</span></div>
      <div>解消された課題: <span class="diff-added">${diff.resolvedSecurityIssues.length > 0 ? diff.resolvedSecurityIssues.join(', ') : 'なし'}</span></div>
    </div>
  `;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
