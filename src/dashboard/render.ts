/**
 * Web Technology & Security Inspector
 * ダッシュボード描画純粋関数 (src/dashboard/render.ts) - IMPL-01, IMPL-03
 */

import { resolveRecommendedVersion } from '../detection/advisory';
import { escapeHtml, renderSafeExternalLink, safeHref } from '../shared/html';
import {
  DetectedTechnology,
  InspectionReport,
  SecurityCheckResult,
} from '../shared/types';

export { escapeHtml, renderSafeExternalLink, safeHref };

export function formatCategory(cat: string): string {
  const map: Record<string, string> = {
    'web-server': 'Webサーバー',
    'programming-language': '開発言語・フレームワーク',
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
          技術: ${r.technologies.length}件 / 要確認: ${r.summary.requiresAttentionCount}件 / EOL: ${r.summary.librarySecurity?.eolCount ?? 0}件 / ${r.summary.isHttps ? 'HTTPS' : 'HTTP'}
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

/**
 * 概要ビュー: セキュリティ注意項目一覧のHTML文字列を生成する
 */
export function renderOverviewSecurityHtml(checks: SecurityCheckResult[]): string {
  const issues = checks.filter((c) => c.status === 'warning' || c.status === 'fail');
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
        <span class="badge ${c.severity === 'high' ? 'sev-high' : 'sev-medium'}">${escapeHtml(c.severity.toUpperCase())}</span>
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
      if (t.distroHint) {
        cveBadge = `<span class="badge badge-medium" title="${escapeHtml(t.distroHint)}">ディストリ版（バックポートの可能性）</span>`;
      } else if (t.offlineMatchStatus === 'Matched' || (t.advisories && t.advisories.length > 0)) {
        cveBadge = `<span class="badge badge-cve">該当 ${t.advisories?.length ?? 0}件 (CVSS ${escapeHtml(t.maxCvss || '6.1')})</span>`;
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
      if (t.isCandidateGroup) {
        recommendation = '稼働しているバックエンド環境の特定を推奨';
      } else if (t.advisories && t.advisories.length > 0) {
        const recVer = resolveRecommendedVersion(t.version, t.advisories);
        recommendation = recVer ? `脆弱性修正版（v${recVer}以上）への更新推奨` : '脆弱性修正版への更新推奨';
      } else if (t.supportStatus === 'EOL') {
        recommendation = 'EOLのため最新LTS系列への移行推奨';
      } else if (t.distroHint) {
        recommendation = `${t.distroHint} ディストリビューションのセキュリティ情報を確認`;
      } else if (t.offlineMatchStatus === 'Unknown Version' && t.version) {
        recommendation = 'パッケージ固有版のため個別セキュリティ情報の確認を推奨';
      }

      const verDisplay = t.isCandidateGroup
        ? '<span class="badge" style="background:var(--bg-hover);font-size:11px;">いずれかの可能性</span>'
        : t.version
        ? `v${escapeHtml(t.version)}`
        : '<span style="color:var(--text-muted);">不明</span>';

      return `
        <tr>
          <td><strong>${escapeHtml(t.technology)}</strong></td>
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

        return `
    <div class="accordion-item">
      <div class="accordion-header">
        <div style="display:flex;align-items:center;gap:12px;">
          <span style="font-weight:700;font-size:15px;">${escapeHtml(t.technology)}</span>
          ${methodBadgeHtml}
          ${runtimeBadgeHtml}
          ${
            t.isCandidateGroup
              ? '<span class="badge" style="background:var(--bg-hover);font-size:11px;">いずれかの可能性</span>'
              : t.version
              ? `<span class="badge" style="background:var(--bg-hover);">v${escapeHtml(t.version)}</span>`
              : '<span style="font-size:11px;color:var(--text-muted);">バージョン不明</span>'
          }
          <span style="font-size:12px;color:var(--text-muted);">${escapeHtml(t.isCandidateGroup ? '言語・FW候補' : formatCategory(t.category))}</span>
        </div>
        <div style="display:flex;gap:6px;align-items:center;">
          ${t.distroHint ? `<span class="badge badge-medium" title="${escapeHtml(t.distroHint)}">ディストリ版（バックポートの可能性）</span>` : ''}
          ${t.supportStatus === 'EOL' ? '<span class="badge badge-eol">EOL</span>' : ''}
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
                  <strong>${escapeHtml(adv.id)}</strong> (${escapeHtml(adv.title)}) - 影響範囲: <code>${escapeHtml(adv.affectedRange)}</code>
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
              <strong>[${escapeHtml(e.type)}] ${escapeHtml(e.name)}:</strong>
              <code>${escapeHtml(e.value)}</code>
              ${e.detail ? `<span style="color:var(--text-muted);margin-left:6px;">(${escapeHtml(e.detail)})</span>` : ''}
            </li>
          `
            )
            .join('')}
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
        const isAccepted =
          c.exceptionStatus === 'accepted' ||
          c.exceptionStatus === 'false-positive' ||
          c.exceptionStatus === 'muted';
        const exceptionBadge = isAccepted
          ? '<span class="badge" style="background:#4B5563;color:#E5E7EB;margin-right:6px;">許容済</span>'
          : '';

        let badgeClass = 'sev-medium';
        let badgeText = c.severity.toUpperCase();
        if (c.status === 'unknown') {
          badgeClass = 'sev-unknown';
          badgeText = '未観測';
        } else if (c.status === 'pass') {
          badgeClass = 'sev-pass';
          badgeText = 'PASS';
        } else if (c.severity === 'high') {
          badgeClass = 'sev-high';
          badgeText = 'HIGH';
        } else if (c.severity === 'medium') {
          badgeClass = 'sev-medium';
          badgeText = 'MEDIUM';
        } else if (c.severity === 'low') {
          badgeClass = 'sev-low';
          badgeText = 'LOW';
        } else if (c.severity === 'info') {
          badgeClass = 'sev-info';
          badgeText = 'INFO';
        }

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
 * Cookie一覧テーブルのtbody HTML文字列を生成する
 */
export function renderCookiesTableHtml(cookies: any[]): string {
  if (!cookies || cookies.length === 0) {
    return '<tr><td colspan="8" class="empty-state">Cookieは検出されませんでした</td></tr>';
  }

  return cookies
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
      <td style="color:${c.issues && c.issues.length > 0 ? 'var(--warning-color)' : 'var(--text-muted)'};">${c.issues && c.issues.length > 0 ? escapeHtml(c.issues.join(', ')) : 'なし'}</td>
    </tr>
  `
    )
    .join('');
}
