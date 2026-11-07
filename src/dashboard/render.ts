/**
 * Web Technology & Security Inspector
 * ダッシュボード描画純粋関数 (src/dashboard/render.ts) - IMPL-01, IMPL-03
 */

import {
  formatAdvisoryRecommendation,
  resolveTechAdvisoryDisplayInfo,
  sortAdvisoriesByPriority,
} from '../detection/advisory';
import { filterDisplayEvidences } from '../detection/engine';
import { formatCookieCategory, normalizeCookieCategory } from '../security/cookies';
import { escapeHtml, renderSafeExternalLink, safeHref } from '../shared/html';
import {
  getSecurityCheckDisplayBadge,
  isFindingExcludedByException,
  isRequiresAttention,
} from '../shared/security-status';
import {
  DetectedTechnology,
  ExternalConnectionsAnalysis,
  ExternalServiceCategory,
  InspectionReport,
  SecurityAdvisory,
  SecurityCheckResult,
} from '../shared/types';

export { escapeHtml, renderSafeExternalLink, safeHref };

export function formatCategory(cat: string): string {
  const map: Record<string, string> = {
    'web-server': 'Webサーバー',
    'programming-language': '開発言語・フレームワーク',
    'framework': 'バックエンドフレームワーク',
    'cms': 'CMS',
    'js-framework': 'JSフレームワーク',
    'js-css-library': 'JS / CSSライブラリ',
    'cdn-waf': 'CDN / WAF',
    'hosting-cloud': 'ホスティング / クラウド基盤',
    'analytics-tracking': 'アクセス解析 / タグ管理',
    'security-service': 'セキュリティ / 監視サービス',
  };
  return map[cat] || cat;
}

export function formatDetectionMethod(method?: string, isCandidateGroup?: boolean): string {
  if (isCandidateGroup || method === 'associated') {
    return '実行環境候補・関連技術';
  }
  if (method === 'inferred') {
    return '連動検知 (推論)';
  }
  return '直接検出';
}

export function formatImplicationType(type?: string): string {
  switch (type) {
    case 'framework-dependency':
      return 'フレームワーク基盤依存';
    case 'possible-runtime':
      return '実行環境の候補（静的配信等の代替構成あり）';
    case 'runtime-dependency':
      return '実行時依存';
    case 'technology-association':
      return '関連技術';
    default:
      return type || '連動';
  }
}

export function formatRuntimeStatus(status?: string): string {
  switch (status) {
    case 'confirmed':
      return '稼働確認済';
    case 'possible':
      return '稼働可能性あり';
    case 'unknown':
      return '稼働状態未確認';
    case 'not-applicable':
      return '該当なし (クライアント技術)';
    default:
      return '未確認';
  }
}

export function formatFixStatus(fixStatus?: string): string {
  switch (fixStatus) {
    case 'fixed':
      return '修正版あり (fixed)';
    case 'partial':
      return '一部系列のみ修正 (partial)';
    case 'none':
      return '公式修正版なし (none)';
    case 'unknown':
      return '修正版情報なし (unknown)';
    default:
      return fixStatus || '';
  }
}

export function getSeverityBadgeClass(severity?: string): string {
  const s = String(severity || '').toLowerCase();
  if (s === 'critical') return 'sev-critical';
  if (s === 'high') return 'sev-high';
  if (s === 'low') return 'sev-low';
  if (s === 'info') return 'sev-info';
  if (s === 'unknown') return 'sev-unknown';
  return 'sev-medium';
}

/**
 * 複数バージョン検出時の表示文字列を生成する (v1.7.0 T08 / SPEC-10)
 * 例: "1.12.4 / 3.7.1（2 つのバージョン）"
 */
export function formatMultiVersionSummary(tech: DetectedTechnology): string | null {
  if (!tech.instances || tech.instances.length < 2) return null;
  const vers = tech.instances.map((i) => i.version || '不明').join(' / ');
  return `${vers}（${tech.instances.length} つのバージョン）`;
}


/**
 * 調査履歴一覧のHTML文字列を生成する (IMPL-01)
 */
export function renderHistoryListHtml(reports: InspectionReport[]): string {
  if (reports.length === 0) {
    return '<div class="empty-state">保存された履歴はありません</div>';
  }

  return reports
    .map(
      (r) => `
    <div style="display:flex;align-items:center;justify-content:space-between;padding:12px;border:1px solid var(--border-color);border-radius:var(--radius-sm);margin-bottom:8px;background:var(--bg-surface);">
      <div>
        <strong>${escapeHtml(r.hostname)}</strong>
        <span style="font-size:12px;color:var(--text-muted);margin-left:8px;">${new Date(r.inspectedAt).toLocaleString('ja-JP')}</span>
        <div style="font-size:12px;color:var(--text-sub);margin-top:2px;">
          技術: ${(r.technologies || []).length}件 / 要確認: ${r.summary?.requiresAttentionCount ?? 0}件 / EOL: ${r.summary?.librarySecurity?.eolCount ?? 0}件 / ${r.summary?.isHttps ? 'HTTPS' : 'HTTP'}
        </div>
      </div>
      <div style="display:flex;gap:6px;">
        <button class="btn btn-secondary btn-sm history-view-btn" data-id="${escapeHtml(r.id)}">表示</button>
        <button class="btn btn-danger btn-sm history-delete-btn" data-id="${escapeHtml(r.id)}">削除</button>
      </div>
    </div>
  `
    )
    .join('');
}

/**
 * 概要ビュー: ライブラリセキュリティ注意一覧のHTML文字列を生成する
 */
export function renderOverviewLibrarySecHtml(techs: DetectedTechnology[]): string {
  const alerted = techs.filter(
    (t) =>
      t.supportStatus === 'EOL' ||
      (t.advisories && t.advisories.length > 0) ||
      t.versionIntegrity?.status === 'mismatch'
  );

  if (alerted.length === 0) {
    return '<div style="color:var(--success-color);padding:12px 0;">ライブラリのサポート終了や既知脆弱性は検出されませんでした。</div>';
  }

  return alerted
    .map((t) => {
      const issues: string[] = [];
      if (t.supportStatus === 'EOL') issues.push(`EOL (${t.eolDate || 'サポート終了'})`);
      if (t.advisories && t.advisories.length > 0) issues.push(`CVE ${t.advisories.length}件`);
      const hasKev = t.advisories?.some((a) => a.kev === true) ?? false;
      if (hasKev) issues.push('悪用確認済み（CISA KEV）');
      if (t.versionIntegrity?.status === 'mismatch') issues.push('CSS/JS不一致');
      const multiVerSummary = formatMultiVersionSummary(t);

      return `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border-color);">
          <div>
            <strong>${escapeHtml(t.technology)}${multiVerSummary ? ` ${escapeHtml(multiVerSummary)}` : ''}</strong>
            <span style="color:var(--text-muted);font-size:12px;margin-left:6px;">${multiVerSummary ? escapeHtml(multiVerSummary) : t.version ? (/^\d/.test(t.version) ? `v${escapeHtml(t.version)}` : escapeHtml(t.version)) : ''}</span>
            <div style="font-size:11px;color:var(--text-sub);">${escapeHtml(issues.join(' / '))}</div>
          </div>
          <div style="display:flex;gap:4px;align-items:center;">
            ${hasKev ? '<span class="badge badge-kev">悪用確認済み（CISA KEV）</span>' : ''}
            <span class="badge ${t.supportStatus === 'EOL' ? 'badge-eol' : 'badge-cve'}">要確認</span>
          </div>
        </div>
      `;
    })
    .join('');
}

/**
 * 概要ビュー: セキュリティ注意項目一覧のHTML文字列を生成する
 */
export function renderOverviewSecurityHtml(checks: SecurityCheckResult[]): string {
  const issues = checks.filter((c) => isRequiresAttention(c));
  if (issues.length === 0) {
    return '<div style="color:var(--success-color);padding:12px 0;">重大なセキュリティ設定不備は検出されませんでした。</div>';
  }

  return issues
    .slice(0, 5)
    .map(
      (c) => `
    <div style="padding:8px 0;border-bottom:1px solid var(--border-color);">
      <div style="display:flex;justify-content:space-between;">
        <strong>${escapeHtml(c.name)}</strong>
        <span class="badge ${getSeverityBadgeClass(c.severity)}">${escapeHtml(c.severity.toUpperCase())}</span>
      </div>
      <div style="font-size:12px;color:var(--text-sub);margin-top:2px;">${escapeHtml(c.description)}</div>
    </div>
  `
    )
    .join('');
}

/**
 * ライブラリセキュリティ表のHTML文字列を生成する
 */
export function renderLibrarySecurityTableHtml(techs: DetectedTechnology[]): string {
  if (techs.length === 0) {
    return '<div class="empty-state">技術情報がありません</div>';
  }

  const expandedRows: Array<{ tech: DetectedTechnology; multiVerSummary: string | null }> = [];
  for (const rawTech of techs) {
    const multiVerSummary = formatMultiVersionSummary(rawTech);
    if (rawTech.instances && rawTech.instances.length >= 2) {
      for (const inst of rawTech.instances) {
        expandedRows.push({
          tech: {
            ...rawTech,
            version: inst.version,
            versionSource: inst.versionSource || rawTech.versionSource,
            distroHint: inst.distroHint ?? rawTech.distroHint,
            evidence: inst.evidence || rawTech.evidence || [],
            advisories: inst.advisories,
            eolInfo: inst.eolInfo,
            supportStatus: inst.supportStatus,
            eolDate: inst.eolDate,
            advisoryMatchStatus: inst.advisoryMatchStatus,
            offlineMatchStatus: inst.offlineMatchStatus,
            advisoryStatusLabel: inst.advisoryStatusLabel,
            upstreamAdvisoriesCount: inst.upstreamAdvisoriesCount,
            maxCvss: inst.maxCvss,
          },
          multiVerSummary,
        });
      }
    } else {
      expandedRows.push({ tech: rawTech, multiVerSummary: null });
    }
  }

  const rows = expandedRows
    .map(({ tech: t, multiVerSummary }) => {
      const eolLabel = t.eolInfo?.label;
      const eolBadge =
        t.supportStatus === 'EOL'
          ? `<span class="badge badge-eol">${escapeHtml(eolLabel || 'EOL')}</span>`
          : t.supportStatus === 'Maintenance'
          ? `<span class="badge badge-medium">${escapeHtml(eolLabel || '保守')}</span>`
          : t.supportStatus === 'Supported'
          ? `<span class="badge badge-high">${escapeHtml(eolLabel || 'Supported')}</span>`
          : `<span class="badge" style="background:var(--bg-hover);">${escapeHtml(eolLabel || 'Unknown')}</span>`;

      const displayInfo = resolveTechAdvisoryDisplayInfo(t);
      let cveBadge = '';
      if (t.offlineMatchStatus === 'Matched' || (t.advisories && t.advisories.length > 0)) {
        const sortedAdvisories = sortAdvisoriesByPriority(t.advisories || []);
        const topAdvisories = sortedAdvisories.slice(0, 5);
        const restAdvisories = sortedAdvisories.slice(5);
        const hasKev = sortedAdvisories.some((a) => a.kev === true);
        const kevBadge = hasKev
          ? '<span class="badge badge-kev" style="margin-right:4px;">悪用確認済み（CISA KEV）</span>'
          : '';
        const fixStatuses = Array.from(
          new Set(sortedAdvisories.map((a) => a.fixStatus).filter(Boolean))
        );
        const fixBadge =
          fixStatuses.length > 0
            ? ` <span class="badge badge-fix-status">${escapeHtml(fixStatuses.join('/'))}</span>`
            : '';
        const topIdsHtml = topAdvisories
          .map((a) => `${escapeHtml(a.id)}${a.kev ? ' (KEV)' : ''}`)
          .join(', ');
        const restHtml =
          restAdvisories.length > 0
            ? `<details class="advisory-more" style="margin-top:2px;font-size:11px;"><summary style="cursor:pointer;color:var(--accent-color);">ほか ${restAdvisories.length} 件</summary><div>${restAdvisories.map((a) => escapeHtml(a.id)).join(', ')}</div></details>`
            : '';
        cveBadge = `${kevBadge}<span class="badge badge-cve">該当 ${sortedAdvisories.length}件 (CVSS ${escapeHtml(t.maxCvss || '6.1')})</span>${fixBadge}<div style="font-size:11px;color:var(--text-sub);margin-top:2px;">${topIdsHtml}</div>${restHtml}`;
      } else if (displayInfo.isDistro) {
        const upstreamRefHtml =
          typeof displayInfo.upstreamAdvisoriesCount === 'number'
            ? `<div style="font-size:11px;color:var(--text-sub);margin-top:2px;">参考: 上流版では ${displayInfo.upstreamAdvisoriesCount} 件該当（収録 ${displayInfo.count} 件・取得元: ${escapeHtml(displayInfo.sourcesText)}・dataVersion: ${escapeHtml(displayInfo.dataVersion)}）</div>`
            : '';
        cveBadge = `<span class="badge badge-medium" title="${escapeHtml(t.distroHint || 'Linux package')}">Needs Review: ディストリ版（バックポートの可能性）</span>${upstreamRefHtml}`;
      } else if (displayInfo.isZeroCoverage) {
        cveBadge = '<span style="color:var(--text-muted);font-size:11px;">この技術の脆弱性は収録していません</span>';
      } else if (t.offlineMatchStatus === 'Unknown Version' || t.advisoryMatchStatus === 'Needs Review' || !t.version) {
        cveBadge = `<span class="badge badge-medium">要確認 (Needs Review)</span><div style="font-size:11px;color:var(--text-muted);margin-top:2px;">収録 ${displayInfo.count} 件（取得元: ${escapeHtml(displayInfo.sourcesText)}・dataVersion: ${escapeHtml(displayInfo.dataVersion)}）</div>`;
      } else {
        cveBadge = `<span class="badge sev-pass">収録 DB 上は該当なし</span><div style="font-size:11px;color:var(--text-muted);margin-top:2px;">収録 ${displayInfo.count} 件（取得元: ${escapeHtml(displayInfo.sourcesText)}・dataVersion: ${escapeHtml(displayInfo.dataVersion)}）</div>`;
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
      if (t.isCandidateGroup) {
        recommendation = '稼働しているバックエンド環境の特定を推奨';
      } else if (t.advisories && t.advisories.length > 0) {
        recommendation = formatAdvisoryRecommendation(t.version, t.advisories, {
          isEol: t.supportStatus === 'EOL',
          technologyName: t.technology,
        });
      } else if (t.eolInfo?.note) {
        recommendation = t.eolInfo.note;
      } else if (t.supportStatus === 'EOL') {
        recommendation = 'EOLのため最新LTS系列への移行推奨';
      } else if (displayInfo.isDistro) {
        const upSuffix =
          typeof displayInfo.upstreamAdvisoriesCount === 'number'
            ? `（参考: 上流版では ${displayInfo.upstreamAdvisoriesCount} 件）`
            : '';
        recommendation = `${t.distroHint || 'Linux'} ディストリビューションのセキュリティ情報を確認${upSuffix}`;
      } else if (t.offlineMatchStatus === 'Unknown Version' && t.version) {
        recommendation = 'パッケージ固有版のため個別セキュリティ情報の確認を推奨';
      }

      const verDisplay = t.isCandidateGroup
        ? '<span class="badge" style="background:var(--bg-hover);font-size:11px;">いずれかの可能性</span>'
        : t.version
        ? /^\d/.test(t.version)
          ? `v${escapeHtml(t.version)}`
          : escapeHtml(t.version)
        : '<span style="color:var(--text-muted);">不明</span>';

      return `
        <tr>
          <td>
            <strong>${escapeHtml(t.technology)}</strong>
            ${multiVerSummary ? `<div style="font-size:11px;color:var(--text-muted);">${escapeHtml(t.technology)} ${escapeHtml(multiVerSummary)}</div>` : ''}
          </td>
          <td>${verDisplay}</td>
          <td>${escapeHtml(t.isCandidateGroup ? '推定候補' : (t.versionSource || '-'))}</td>
          <td>${integrityBadge}</td>
          <td>${eolBadge} ${t.eolDate ? `<span style="font-size:11px;color:var(--text-muted);">(${escapeHtml(t.eolDate)})</span>` : ''}</td>
          <td>${cveBadge}</td>
          <td style="font-size:12px;color:var(--accent-color);">${escapeHtml(recommendation)}</td>
        </tr>
      `;
    })
    .join('');

  return `
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

/**
 * 技術詳細アコーディオン一覧のHTML文字列を生成する
 */
export function renderFullTechnologiesHtml(techs: DetectedTechnology[], coverage?: any): string {
  const noticeHtml = (coverage && coverage.networkHeadersObserved === false)
    ? `<div style="background: rgba(245, 158, 11, 0.15); border: 1px solid var(--warning-color); border-radius: 6px; padding: 10px 14px; margin-bottom: 12px; font-size: 12px; color: var(--warning-color); line-height: 1.5;">
         ⚠️ <strong>HTTPレスポンスヘッダー未取得</strong>: 拡張機能起動前またはバックグラウンドスリープ中に開かれたタブです。サーバーや言語ヘッダーを診断するには、対象ページを再読み込み（リロード）して再調査してください。
       </div>`
    : '';

  if (techs.length === 0) {
    return noticeHtml + '<div class="empty-state">明確な固有技術シグナルは検出されませんでした</div>';
  }

  const itemsHtml = techs
    .map(
      (t) => {
        // 検出方式バッジ
        let methodBadgeHtml = '';
        if (t.isCandidateGroup || t.detectionMethod === 'associated') {
          methodBadgeHtml = '<span class="badge badge-associated">候補</span>';
        } else if (t.detectionMethod === 'inferred') {
          const srcText = t.inferredFrom ? ` · ${escapeHtml(t.inferredFrom)}` : '';
          methodBadgeHtml = `<span class="badge badge-inferred">連動${srcText}</span>`;
        } else {
          methodBadgeHtml = '<span class="badge badge-direct">直接</span>';
        }

        // ランタイム状態バッジ
        let runtimeBadgeHtml = '';
        if (t.runtimeStatus === 'unknown') {
          runtimeBadgeHtml = '<span class="badge badge-runtime-unknown">稼働未確認</span>';
        } else if (t.runtimeStatus === 'possible') {
          runtimeBadgeHtml = '<span class="badge badge-runtime-possible">稼働可能性</span>';
        }

        const websiteHtml = t.website
          ? `<div>公式サイト: ${renderSafeExternalLink(t.website, t.website, { style: 'color:var(--accent-color);' })}</div>`
          : '';

        const displayInfo = resolveTechAdvisoryDisplayInfo(t);
        const renderAdvLiHtml = (adv: SecurityAdvisory, liClass: string): string => {
          const sevClass = getSeverityBadgeClass(adv.severity);
          const sevText = escapeHtml(String(adv.severity || 'medium').toUpperCase());
          const kevBadge = adv.kev
            ? ` <span class="badge badge-kev">悪用確認済み（CISA KEV）${adv.kevDateAdded ? ` (${escapeHtml(adv.kevDateAdded)})` : ''}</span>`
            : '';
          const fixBadge = adv.fixStatus
            ? ` <span class="badge badge-fix-status">${escapeHtml(formatFixStatus(adv.fixStatus))}</span>`
            : '';
          return `
                <li class="${liClass}" style="margin-bottom:6px;">
                  <strong>${escapeHtml(adv.id)}</strong> <span class="badge ${sevClass}">${sevText}</span>${kevBadge} (${escapeHtml(adv.title)}) - 影響範囲: <code>${escapeHtml(adv.affectedRange)}</code>
                  ${adv.fixedVersion ? `<span style="color:var(--success-color);margin-left:6px;">修正版: v${escapeHtml(adv.fixedVersion)}</span>` : ''}${fixBadge}
                </li>
              `;
        };

        let advisoriesSectionHtml = '';
        if (t.advisories && t.advisories.length > 0) {
          const sortedAdvisories = sortAdvisoriesByPriority(t.advisories);
          const topAdvisories = sortedAdvisories.slice(0, 5);
          const restAdvisories = sortedAdvisories.slice(5);
          const recText = formatAdvisoryRecommendation(t.version, t.advisories, {
            isEol: t.supportStatus === 'EOL',
            technologyName: t.technology,
          });
          const moreDetailsHtml =
            restAdvisories.length > 0
              ? `
            <details class="advisory-more" style="margin-top:4px;">
              <summary style="cursor:pointer;font-size:12px;font-weight:600;color:var(--accent-color);">ほか ${restAdvisories.length} 件</summary>
              <ul style="padding-left:18px;margin-top:4px;">
                ${restAdvisories.map((adv) => renderAdvLiHtml(adv, 'advisory-card advisory-more-item')).join('')}
              </ul>
            </details>
          `
              : '';
          advisoriesSectionHtml = `
          <div style="margin-top:8px;">
            <strong style="color:var(--danger-color);">該当する既知脆弱性 (CVE / GHSA) (${t.advisories.length}件):</strong>
            <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">収録 ${displayInfo.count} 件・取得元: ${escapeHtml(displayInfo.sourcesText)}・dataVersion: ${escapeHtml(displayInfo.dataVersion)}</div>
            <div style="font-size:12px;color:var(--accent-color);margin-top:2px;">推奨対応: ${escapeHtml(recText)}</div>
            <ul class="advisory-list" style="padding-left:18px;margin-top:4px;">
              ${topAdvisories.map((adv) => renderAdvLiHtml(adv, 'advisory-card advisory-item')).join('')}
            </ul>
            ${moreDetailsHtml}
          </div>
        `;
        } else if (!t.isCandidateGroup) {
          advisoriesSectionHtml = `
          <div style="margin-top:8px;font-size:12px;">
            <strong>脆弱性照合状況:</strong> ${escapeHtml(displayInfo.statusLabel)}
          </div>
        `;
        }

        const multiVerSummary = formatMultiVersionSummary(t);
        const instancesHtml =
          t.instances && t.instances.length >= 2
            ? `
          <div class="multi-version-instances" style="margin-top:8px;padding:8px;border:1px solid var(--border-color);border-radius:4px;background:var(--bg-surface);">
            <strong>検出されたバージョン別インスタンス (${t.instances.length} 件):</strong>
            ${t.instances
              .map((inst) => {
                const instAdvs = inst.advisories || [];
                const instEolObj = inst.eolInfo ?? inst.eol;
                const instEol = instEolObj?.label || inst.supportStatus || instEolObj?.status || 'Unknown';
                const instCveText =
                  instAdvs.length > 0
                    ? `CVE ${instAdvs.length}件 (${instAdvs.map((a) => escapeHtml(a.id)).join(', ')})`
                    : escapeHtml(inst.advisoryStatusLabel || '該当脆弱性なし');
                const instEvHtml = (inst.evidence || [])
                  .map(
                    (e) =>
                      `<li><code>[${escapeHtml(e.type)}] ${escapeHtml(e.name)}: ${escapeHtml(e.value)}</code></li>`
                  )
                  .join('');
                return `
                  <div class="instance-item" style="margin-top:6px;padding-top:6px;border-top:1px dashed var(--border-color);">
                    <div><strong>v${escapeHtml(inst.version)}</strong> — EOL: ${escapeHtml(instEol)} / 脆弱性: ${instCveText}</div>
                    ${instEvHtml ? `<ul style="margin:4px 0 0 0;padding-left:18px;font-size:11px;">${instEvHtml}</ul>` : ''}
                  </div>
                `;
              })
              .join('')}
          </div>
        `
            : '';

        return `
    <div class="accordion-item">
      <div class="accordion-header">
        <div style="display:flex;align-items:center;gap:12px;">
          <span style="font-weight:700;font-size:15px;">${escapeHtml(t.technology)}${multiVerSummary ? ` ${escapeHtml(multiVerSummary)}` : ''}</span>
          ${methodBadgeHtml}
          ${runtimeBadgeHtml}
          ${
            t.isCandidateGroup
              ? '<span class="badge" style="background:var(--bg-hover);font-size:11px;">いずれかの可能性</span>'
              : multiVerSummary
              ? `<span class="badge" style="background:var(--bg-hover);">${escapeHtml(multiVerSummary)}</span>`
              : t.version
              ? `<span class="badge" style="background:var(--bg-hover);">v${escapeHtml(t.version)}</span>`
              : '<span style="font-size:11px;color:var(--text-muted);">バージョン不明</span>'
          }
          <span style="font-size:12px;color:var(--text-muted);">${escapeHtml(t.isCandidateGroup ? '言語・FW候補' : formatCategory(t.category))}</span>
        </div>
        <div style="display:flex;gap:6px;align-items:center;">
          ${t.distroHint ? `<span class="badge badge-medium" title="${escapeHtml(t.distroHint)}">ディストリ版（バックポートの可能性）</span>` : ''}
          ${t.supportStatus === 'EOL' ? `<span class="badge badge-eol">${escapeHtml(t.eolInfo?.label || 'EOL')}</span>` : t.eolInfo?.label ? `<span class="badge badge-medium">${escapeHtml(t.eolInfo.label)}</span>` : ''}
          ${t.advisories && t.advisories.some((a) => a.kev === true) ? '<span class="badge badge-kev">悪用確認済み（CISA KEV）</span>' : ''}
          ${t.advisories && t.advisories.length > 0 ? `<span class="badge badge-cve">CVE ${t.advisories.length}件</span>` : ''}
          <span class="badge ${t.confidenceLevel === 'high' ? 'badge-high' : 'badge-medium'}">確信度 ${t.confidence}</span>
        </div>
      </div>
      <div class="accordion-body">
        <div style="margin-bottom:8px;padding:8px 12px;border:1px solid var(--border-color);border-radius:4px;background:var(--bg-surface);">
          <div style="font-size:12px;margin-bottom:4px;">
            <strong>検出方式:</strong> ${escapeHtml(formatDetectionMethod(t.detectionMethod, t.isCandidateGroup))}
            ${t.inferredFrom ? ` / <strong>推論元:</strong> ${escapeHtml(t.inferredFrom)} (${escapeHtml(formatImplicationType(t.implicationType))})` : ''}
          </div>
          ${t.inferencePath && t.inferencePath.length > 1 ? `<div style="font-size:12px;margin-bottom:4px;"><strong>推論経路:</strong> <code>${escapeHtml(t.inferencePath.join(' → '))}</code></div>` : ''}
          <div style="font-size:12px;margin-bottom:4px;">
            <strong>ランタイム状態:</strong> ${escapeHtml(formatRuntimeStatus(t.runtimeStatus))}
            ${t.runtimeStatus === 'unknown' ? '<span style="font-size:11px;color:var(--text-muted);margin-left:6px;">(※サーバー内部の稼働状態を観測できないため断定を保留)</span>' : ''}
          </div>
          ${t.distroHint ? `<div style="font-size:12px;color:var(--warning-color);"><strong>ディストリビューション:</strong> ${escapeHtml(t.distroHint)}（セキュリティ修正バックポートの可能性があるため機械的断定を保留）</div>` : ''}
        </div>
        ${
          t.isCandidateGroup && t.candidateTechnologies
            ? `
          <div style="margin-bottom:8px;padding:8px;border:1px solid var(--border-color);border-radius:4px;background:var(--bg-surface);">
            <strong>推定候補フレームワーク:</strong>
            <div style="display:flex;gap:6px;margin-top:4px;flex-wrap:wrap;">
              ${t.candidateTechnologies.map((c) => `<span class="badge" style="background:var(--bg-hover);">${escapeHtml(c)}</span>`).join('')}
            </div>
          </div>
        `
            : ''
        }
        <div>${escapeHtml(t.description || '')}</div>
        ${websiteHtml}
        ${instancesHtml}
        
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
          t.eolInfo && (t.supportStatus === 'EOL' || t.eolInfo.label || t.eolInfo.note)
            ? `
          <div style="margin-top:8px;padding:8px;border:1px solid var(--border-color);border-radius:4px;background:var(--bg-surface);">
            <strong>サポート状況 (EOL):</strong> ${escapeHtml(t.eolInfo.label || t.eolInfo.status)}${t.eolInfo.eolDate ? ` (${escapeHtml(t.eolInfo.eolDate)})` : ''}
            <div style="font-size:12px;color:var(--text-sub);margin-top:2px;">${escapeHtml(t.eolInfo.note || t.eolInfo.recommendation)}</div>
          </div>
        `
            : ''
        }

        ${advisoriesSectionHtml}

        ${
          (t.wpPlugins && t.wpPlugins.length > 0) || (t.wpThemes && t.wpThemes.length > 0)
            ? `
          <div style="margin-top:8px;padding:8px;border:1px solid var(--border-color);border-radius:4px;background:var(--bg-surface);">
            <strong>WordPress プラグイン・テーマ:</strong>
            ${
              t.wpPlugins && t.wpPlugins.length > 0
                ? `<div style="font-size:12px;margin-top:4px;"><strong>プラグイン:</strong> ${t.wpPlugins
                    .map((p) =>
                      p.version
                        ? `<code>${escapeHtml(p.name)}</code> (ver: <code>${escapeHtml(p.version)}</code>)`
                        : `<code>${escapeHtml(p.name)}</code>`
                    )
                    .join(', ')}</div>`
                : ''
            }
            ${
              t.wpThemes && t.wpThemes.length > 0
                ? `<div style="font-size:12px;margin-top:4px;"><strong>テーマ:</strong> ${t.wpThemes
                    .map((th) =>
                      th.version
                        ? `<code>${escapeHtml(th.name)}</code> (ver: <code>${escapeHtml(th.version)}</code>)`
                        : `<code>${escapeHtml(th.name)}</code>`
                    )
                    .join(', ')}</div>`
                : ''
            }
          </div>
        `
            : ''
        }

        <div style="font-weight:700;margin-top:8px;">判定根拠 (Evidence):</div>
        <ul style="padding-left:18px;">
          ${(() => {
            const dispEv = filterDisplayEvidences(t.evidence || []);
            const visEv = dispEv.slice(0, 3);
            const remEv = dispEv.length - visEv.length;
            const itemsHtml = visEv
              .map(
                (e) => `
            <li>
              <strong>[${escapeHtml(e.type)}] ${escapeHtml(e.name)}:</strong>
              <code>${escapeHtml(e.value)}</code>
              ${e.detail ? `<span style="color:var(--text-muted);margin-left:6px;">(${escapeHtml(e.detail)})</span>` : ''}
            </li>
          `
              )
              .join('');
            const remHtml = remEv > 0 ? `<li style="color:var(--text-muted);">他 ${remEv} 件</li>` : '';
            return itemsHtml + remHtml;
          })()}
        </ul>
      </div>
    </div>
  `;
      }
    )
    .join('');

  return noticeHtml + itemsHtml;
}

/**
 * セキュリティ診断アコーディオン一覧のHTML文字列を生成する
 */
export function renderFullSecurityHtml(checks: SecurityCheckResult[]): string {
  return checks
    .map(
      (c) => {
        const isAccepted = isFindingExcludedByException(c);
        const exceptionBadge = isAccepted
          ? '<span class="badge" style="background:#4B5563;color:#E5E7EB;margin-right:6px;">許容済</span>'
          : '';

        const { badgeClass, dashLabel: badgeText } = getSecurityCheckDisplayBadge(c);

        const referencesHtml =
          c.referenceUrls && c.referenceUrls.length > 0
            ? `
          <div><strong>参考資料:</strong>
            ${c.referenceUrls
              .map((u) => renderSafeExternalLink(u, u, { style: 'color:var(--accent-color);margin-left:8px;' }))
              .join(', ')}
          </div>
        `
            : '';

        return `
    <div class="accordion-item">
      <div class="accordion-header">
        <div style="display:flex;align-items:center;gap:12px;">
          <span style="font-weight:700;font-size:14px;">${escapeHtml(c.name)}</span>
          <span style="font-size:11px;color:var(--text-muted);">${escapeHtml(c.checkId)}</span>
        </div>
        <div style="display:flex;align-items:center;gap:6px;">
          ${exceptionBadge}
          <span class="badge ${badgeClass}">${badgeText}</span>
        </div>
      </div>
      <div class="accordion-body">
        <div><strong>観測値:</strong> <code>${escapeHtml(c.observed)}</code></div>
        <div><strong>セキュリティ上の影響:</strong> ${escapeHtml(c.description)}</div>
        <div style="color:var(--accent-color);"><strong>推奨対応:</strong> ${escapeHtml(c.recommendation)}</div>
        ${
          c.exceptionReason
            ? `<div style="background:rgba(59,130,246,0.1);padding:6px 10px;border-radius:4px;margin-top:6px;font-size:12px;color:var(--accent-color);"><strong>許容理由:</strong> ${escapeHtml(c.exceptionReason)}</div>`
            : ''
        }
        ${referencesHtml}
      </div>
    </div>
  `;
      }
    )
    .join('');
}

/**
 * Cookie一覧テーブルのtbody HTML文字列を生成する (v1.7.1 T07)
 * v1.7.0 以前の履歴データ（category 未設定や旧用途のみ）および未知の用途値も安全に描画する。
 */
export function renderCookiesTableHtml(cookies: any[]): string {
  if (!cookies || cookies.length === 0) {
    return '<tr><td colspan="8" class="empty-state">Cookieは検出されませんでした</td></tr>';
  }

  return cookies
    .map((c) => {
      const catKey = normalizeCookieCategory(c?.category);
      const catLabel = formatCookieCategory(catKey);
      return `
    <tr>
      <td><strong>${escapeHtml(c.name)}</strong><div style="font-size:11px;color:var(--text-muted);">${escapeHtml(catLabel)} (${escapeHtml(catKey)})</div></td>
      <td>${escapeHtml(c.domain)}</td>
      <td>${escapeHtml(c.path)}</td>
      <td>${c.secure ? '✅' : '❌'}</td>
      <td>${c.httpOnly ? '✅' : '❌'}</td>
      <td>${escapeHtml(c.sameSite)}</td>
      <td>${c.session ? 'セッション' : '永続'}</td>
      <td style="color:${c.issues && c.issues.length > 0 ? 'var(--warning-color)' : 'var(--text-muted)'};">${c.issues && c.issues.length > 0 ? escapeHtml(c.issues.join(', ')) : 'なし'}</td>
    </tr>
  `;
    })
    .join('');
}

/**
 * 外部通信先・サードパーティドメイン分析ビューのHTML文字列を生成する（v1.7.1 T05）
 *
 * ページ本体および実際に読み込まれたサブリソース（Resource Timing API・script・stylesheet・画像等）の
 * 取得元ホスト（eTLD+1）を集計して表示します。alternate リンク、canonical、dns-prefetch、preconnect、
 * form の送信先（action）など読み込みを伴わない参照は通信先に含めません。
 */
export function renderExternalConnectionsHtml(analysis?: ExternalConnectionsAnalysis): string {
  if (!analysis || !analysis.connections || analysis.connections.length === 0) {
    return '<div class="empty-state">外部通信先情報はまだ解析されていません。</div>';
  }

  const catLabels: Record<ExternalServiceCategory, string> = {
    cdn: 'CDN・静的配信',
    analytics: 'アクセス解析',
    advertising: '広告・マーケティング',
    fonts: 'Webフォント',
    social: 'SNSウィジェット',
    security: 'セキュリティ・Bot対策',
    api: '外部API',
    other: 'その他',
  };

  const categoryChips = (Object.entries(analysis.categoryBreakdown) as [ExternalServiceCategory, number][])
    .filter(([_, count]) => count > 0)
    .map(
      ([cat, count]) =>
        `<span class="badge badge-medium" style="margin-right:6px;display:inline-block;margin-top:4px;">${escapeHtml(catLabels[cat] || cat)}: ${count}件</span>`
    )
    .join('');

  return `
    <div class="diff-box">
      <div class="diff-title">読み込まれたリソースの取得元ドメイン集計 (eTLD+1 / Public Suffix List 判定)</div>
      <div style="font-size:12px;color:var(--text-sub);margin-bottom:8px;">
        対象ページ本体および実際に読み込まれたサブリソース（Resource Timing API・スクリプト・スタイルシート・画像等）の取得元を集計しています。alternate リンク、canonical、dns-prefetch、preconnect、form の送信先（action）など読み込みを伴わない参照は通信先に含めません。
      </div>
      <div style="margin-bottom:8px;">
        検出ホスト数: <strong>${analysis.totalConnections} 件</strong>
        (自社/First-Party: <strong>${analysis.firstPartyCount}</strong>, 外部/Third-Party: <strong>${analysis.thirdPartyCount}</strong>)
      </div>
      <div>推定用途別内訳: ${categoryChips || '<span style="color:var(--text-muted);">-</span>'}</div>
    </div>

    <div class="diff-box">
      <div class="diff-title">読み込まれたリソースの取得元ホスト一覧</div>
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
