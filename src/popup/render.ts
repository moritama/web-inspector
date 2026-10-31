/**
 * Web Technology & Security Inspector
 * ポップアップ描画純粋関数 (src/popup/render.ts) - IMPL-03
 */

import { escapeHtml, renderSafeExternalLink, safeHref } from '../shared/html';
import {
  DetectedTechnology,
  InspectedCookieInfo,
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
    return '実行環境候補・関連技術 (使用を裏付ける直接証拠なし)';
  }
  if (method === 'inferred') {
    return '連動検知 (技術的依存関係に基づく推定)';
  }
  return '直接検出 (固有シグナルの観測あり)';
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
 * 技術詳細モーダルのHTML文字列を生成する
 */
export function renderTechModalHtml(tech: DetectedTechnology): string {
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
    const sourceLink = eol.sourceUrl
      ? `<div>出典: ${renderSafeExternalLink(eol.sourceUrl, eol.sourceUrl, { className: 'ref-link' })}</div>`
      : '';

    eolHtml = `
      <div>
        <div class="detail-section-title">サポート状況 (EOL)</div>
        <div>ステータス: <strong style="color:${statusColor};">${escapeHtml(eol.status)}</strong> ${eol.eolDate ? `(EOL日: ${escapeHtml(eol.eolDate)})` : ''}</div>
        <div style="font-size:11px;color:var(--accent-color);">${escapeHtml(eol.recommendation)}</div>
        ${sourceLink}
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
        <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px;">照合ステータス: <strong>${escapeHtml(statusLabel)}</strong></div>
        ${tech.advisories
          .map(
            (adv) => `
          <div class="advisory-card">
            <div style="display:flex;justify-content:space-between;align-items:center;">
              <strong>${escapeHtml(adv.id)}</strong>
              ${adv.cvssScore ? `<span class="badge sev-high">CVSS ${escapeHtml(adv.cvssScore)}</span>` : ''}
            </div>
            <div style="font-weight:600;margin-top:2px;">${escapeHtml(adv.title)}</div>
            <div style="font-size:11px;color:var(--text-secondary);margin-top:4px;">${escapeHtml(adv.summary)}</div>
            <div style="font-size:11px;margin-top:4px;">
              <span>影響範囲: <code>${escapeHtml(adv.affectedRange)}</code></span>
              ${adv.fixedVersion ? `<span style="margin-left:8px;color:var(--success-color);">修正版: <strong>v${escapeHtml(adv.fixedVersion)}</strong></span>` : ''}
            </div>
            ${
              adv.referenceUrls && adv.referenceUrls.length > 0
                ? `<div style="margin-top:4px;display:flex;flex-wrap:wrap;gap:8px;">${adv.referenceUrls
                    .map((url, idx) =>
                      renderSafeExternalLink(
                        url,
                        adv.referenceUrls.length === 1
                          ? '詳細情報 (NVD / GitHub)'
                          : `詳細情報 (${idx + 1})`,
                        { className: 'ref-link' }
                      )
                    )
                    .join('')}</div>`
                : ''
            }
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
      statusText = tech.distroHint
        ? `${tech.distroHint} のディストリビューション版です。セキュリティ修正がバックポートされている可能性があるため、バージョン番号だけでは脆弱性の有無を断定できません。`
        : 'バージョン不明、またはLinuxディストリビューション固有パッケージのため脆弱性断定を保留しています。';
    }
    cveHtml = `
      <div>
        <div class="detail-section-title">脆弱性照合状況 (オフラインDB) ${staleNotice}</div>
        <div style="font-size:12px;">ステータス: <strong>${escapeHtml(statusLabel)}</strong></div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">${escapeHtml(statusText)}</div>
      </div>
    `;
  }

  const candidateHtml = tech.isCandidateGroup && tech.candidateTechnologies
    ? `
      <div style="margin-bottom:12px;padding:10px;background:var(--bg-surface);border:1px solid var(--border-color);border-radius:6px;">
        <div style="font-weight:600;font-size:12px;color:var(--text-sub);margin-bottom:6px;">推定候補フレームワーク:</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;">
          ${tech.candidateTechnologies.map(c => `<span class="badge" style="background:var(--bg-hover);color:var(--text-main);font-size:12px;padding:3px 8px;">${escapeHtml(c)}</span>`).join('')}
        </div>
        <div style="font-size:11px;color:var(--text-muted);margin-top:8px;">
          ${escapeHtml(tech.description || '')}
        </div>
      </div>
    `
    : '';

  const websiteHtml = tech.website
    ? `<div>公式サイト: ${renderSafeExternalLink(tech.website, tech.website, { className: 'ref-link' })}</div>`
    : '';

  return `
    ${candidateHtml}
    <div>
      <div class="detail-section-title">基本情報</div>
      <div>確信度スコア: <strong>${tech.confidence}</strong> (${escapeHtml(tech.confidenceLevel.toUpperCase())})</div>
      <div>代表バージョン: <strong>${tech.isCandidateGroup ? 'いずれかの可能性あり' : escapeHtml(tech.version || '不明')}</strong> ${tech.versionSource ? `[取得元: ${escapeHtml(tech.versionSource)}]` : ''}</div>
      <div>カテゴリ: ${escapeHtml(tech.isCandidateGroup ? '言語・フレームワーク候補' : formatCategory(tech.category))}</div>
      <div>検出方式: <strong>${escapeHtml(formatDetectionMethod(tech.detectionMethod, tech.isCandidateGroup))}</strong></div>
      ${tech.inferredFrom ? `<div>推論元技術: <strong>${escapeHtml(tech.inferredFrom)}</strong> ${tech.implicationType ? `(${escapeHtml(formatImplicationType(tech.implicationType))})` : ''}</div>` : ''}
      ${tech.inferencePath && tech.inferencePath.length > 1 ? `<div>推論経路: <code>${escapeHtml(tech.inferencePath.join(' → '))}</code></div>` : ''}
      <div>ランタイム状態: <strong>${escapeHtml(formatRuntimeStatus(tech.runtimeStatus))}</strong></div>
      ${tech.runtimeStatus === 'unknown' ? '<div style="font-size:11px;color:var(--text-muted);margin-top:2px;">※受動的調査の原則に基づき、サーバー内部の稼働状態を観測できないため断定を保留しています。</div>' : ''}
      ${websiteHtml}
    </div>

    ${tech.isCandidateGroup ? '' : integrityHtml}
    ${tech.isCandidateGroup ? '' : eolHtml}
    ${tech.isCandidateGroup ? '' : cveHtml}

    <div>
      <div class="detail-section-title">判定根拠 (エビデンス)</div>
      ${tech.evidence
        .map(
          (e) => `
        <div class="evidence-item">
          <div><strong>[${escapeHtml(e.type)}]</strong> ${escapeHtml(e.name)}</div>
          <div class="detail-box">${escapeHtml(e.value)}</div>
          ${e.detail ? `<div style="font-size:11px;color:var(--text-muted);">${escapeHtml(e.detail)}</div>` : ''}
        </div>
      `
        )
        .join('')}
    </div>
  `;
}

/**
 * セキュリティチェック詳細モーダルのHTML文字列を生成する
 */
export function renderSecurityModalHtml(check: SecurityCheckResult): string {
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

  const referencesHtml =
    check.referenceUrls && check.referenceUrls.length > 0
      ? `
    <div>
      <div class="detail-section-title">参考資料</div>
      ${check.referenceUrls
        .map((url) => renderSafeExternalLink(url, url, { className: 'ref-link' }))
        .join('')}
    </div>
  `
      : '';

  return `
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

    ${referencesHtml}

    ${exceptionSectionHtml}
  `;
}

/**
 * Cookie詳細モーダルのHTML文字列を生成する
 */
export function renderCookieModalHtml(cookie: InspectedCookieInfo): string {
  return `
    <div>
      <div class="detail-section-title">属性詳細 (※値は除外)</div>
      <div>ドメイン: <strong>${escapeHtml(cookie.domain || '-')}</strong></div>
      <div>パス: <strong>${escapeHtml(cookie.path || '-')}</strong></div>
      <div>Secure: <strong>${cookie.secure ? '有効' : '無効'}</strong></div>
      <div>HttpOnly: <strong>${cookie.httpOnly ? '有効' : '無効'}</strong></div>
      <div>SameSite: <strong>${escapeHtml(cookie.sameSite || '-')}</strong></div>
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
}
