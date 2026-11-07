/**
 * Web Technology & Security Inspector
 * 包括的Markdown調査レポート生成モジュール (src/export/markdown.ts) - IMP-12
 * 
 * 改善仕様書 Rev.2.1（第11項）に完全準拠した15セクション構成のMarkdown報告書を生成・ダウンロードします。
 * Cookie値・機密ヘッダーは一切含めず、エビデンス保持・受動的解析の原則を堅持します。
 */

import {
  ADVISORY_DB_VERSION,
  formatAdvisoryRecommendation,
  getEffectiveFixStatus,
  resolveTechAdvisoryDisplayInfo,
} from '../detection/advisory';
import {
  DetailedDiffItem,
  DetectedTechnology,
  Evidence,
  FindingException,
  InspectedCookieInfo,
  InspectionReport,
  SecurityCheckResult,
} from '../shared/types';
import { isGenericClassEvidence } from '../detection/engine';
import {
  formatMarkdownStatusBadge,
  isRequiresAttention,
} from '../shared/security-status';
import { normalizeCookieCategory } from '../security/cookies';
import { evaluatePolicyIssuesWithIntersection } from '../security/csp-parser';
import { compareReportsEnhanced } from '../storage/diff';

/**
 * 複数バージョンインスタンスを持つ技術をインスタンス単位の配列に展開する (v1.7.0 T08 / SPEC-10)
 */
function expandTechnologyInstances(technologies: DetectedTechnology[]): DetectedTechnology[] {
  const expanded: DetectedTechnology[] = [];
  for (const rawTech of technologies) {
    if (rawTech.instances && rawTech.instances.length > 0) {
      for (const inst of rawTech.instances) {
        expanded.push({
          ...rawTech,
          version: inst.version,
          versionSource: inst.versionSource || rawTech.versionSource,
          distroHint: inst.distroHint ?? rawTech.distroHint,
          evidence: inst.evidence && inst.evidence.length > 0 ? inst.evidence : rawTech.evidence || [],
          advisories: inst.advisories,
          eolInfo: inst.eolInfo,
          supportStatus: inst.supportStatus,
          eolDate: inst.eolDate,
          advisoryMatchStatus: inst.advisoryMatchStatus,
          offlineMatchStatus: inst.offlineMatchStatus,
          advisoryStatusLabel: inst.advisoryStatusLabel,
          upstreamAdvisoriesCount: inst.upstreamAdvisoriesCount,
          maxCvss: inst.maxCvss,
        });
      }
    } else {
      expanded.push(rawTech);
    }
  }
  return expanded;
}

/**
 * URLから機密クエリパラメータ（token, secret, key, password等）を除去・マスクする
 */
export function sanitizeUrlForReport(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl);
    const sensitiveKeys = ['token', 'key', 'auth', 'secret', 'password', 'passwd', 'sig', 'signature', 'access_token', 'api_key'];
    for (const k of Array.from(parsed.searchParams.keys())) {
      if (sensitiveKeys.some((s) => k.toLowerCase().includes(s))) {
        parsed.searchParams.set(k, '***MASKED***');
      }
    }
    // 認証情報（username:password@）の除去
    parsed.username = '';
    parsed.password = '';
    return parsed.toString();
  } catch {
    return rawUrl;
  }
}

/**
 * Markdown特殊文字をエスケープする
 */
export function escapeMarkdown(text: string | null | undefined): string {
  if (!text) return '';
  return text
    .replace(/\\/g, '\\\\')
    .replace(/`/g, '\\`')
    .replace(/\*/g, '\\*')
    .replace(/_/g, '\\_')
    .replace(/\[/g, '\\[')
    .replace(/\]/g, '\\]')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\|/g, '\\|')
    .replace(/\r\n|\n|\r/g, ' ');
}

/**
 * Markdown表のセル内テキスト向けにパイプ文字と改行のみをエスケープする (v1.7.1 T02 / 指摘7)
 */
export function escapeMarkdownTableCell(text: string | null | undefined): string {
  if (!text) return '';
  return text
    .replace(/\r\n|\n|\r/g, ' ')
    .replace(/\|/g, '\\|');
}

/**
 * Markdownのコードスパン（インラインコード）を生成する (v1.7.1 T02 / 指摘7)
 * - コードスパン内では escapeMarkdown を使用しない（_ や [ ] 等にバックスラッシュを付けない）
 * - 値にバッククォートが含まれる場合は、連続するバッククォートの最大長+1個のバッククォートで囲む
 * - 表のセル内（inTable: true）では `|` だけを `\|` にエスケープする
 */
export function formatMarkdownCodeSpan(
  text: string | null | undefined,
  options?: { inTable?: boolean }
): string {
  const raw = (text ?? '').replace(/\r\n|\n|\r/g, ' ');
  const content = options?.inTable ? raw.replace(/\|/g, '\\|') : raw;

  const backtickMatches = content.match(/`+/g);
  const maxBackticks = backtickMatches
    ? Math.max(...backtickMatches.map((m) => m.length))
    : 0;
  const fence = '`'.repeat(maxBackticks + 1);

  const needsPadding =
    content.startsWith('`') ||
    content.endsWith('`') ||
    (content.length > 0 && content.startsWith(' ') && content.endsWith(' '));

  return needsPadding ? `${fence} ${content} ${fence}` : `${fence}${content}${fence}`;
}

/**
 * 脆弱性DBバージョン文字列を概要・注記共通の書式（YYYY-MM-DD）に整形する (v1.7.1 T02 / 指摘6)
 */
function formatAdvisoryDbVersion(rawVersion?: string): string {
  const ver = rawVersion || ADVISORY_DB_VERSION || '2026-10-31';
  if (/^\d{8}$/.test(ver)) {
    return `${ver.slice(0, 4)}-${ver.slice(4, 6)}-${ver.slice(6, 8)}`;
  }
  return ver;
}

/**
 * 公式にLTS（Long Term Support）リリース系列を持つ技術かどうかを判定する (v1.7.1 T02 / 指摘6)
 */
function hasLtsRelease(technology: string): boolean {
  const normalized = (technology || '').toLowerCase().trim();
  const ltsTechnologies = new Set([
    'node.js',
    'nodejs',
    'node',
    'angular',
    'laravel',
    'django',
    'java',
    'spring boot',
    'ubuntu',
    'debian',
  ]);
  return ltsTechnologies.has(normalized);
}

/**
 * 推奨対応文（recommendation）から1文目を抽出する (v1.7.1 T02 / E3)
 */
function extractFirstRecommendationSentence(recommendation: string | null | undefined): string {
  const trimmed = (recommendation || '').replace(/\r\n|\n|\r/g, ' ').trim();
  if (!trimmed) return '設定および構成の見直しを検討してください。';
  const periodIdx = trimmed.indexOf('。');
  if (periodIdx !== -1) {
    return trimmed.slice(0, periodIdx + 1).trim();
  }
  return trimmed;
}

/**
 * 観測されたCookieが親ドメイン（上位ドメインまたはドメイン指定スコープ）のCookieかどうかを判定する (v1.7.1 T02 / 指摘5)
 */
function isParentDomainCookie(cookie: InspectedCookieInfo, pageHostname: string): boolean {
  if (!cookie.domain || cookie.domain === '-') return false;
  const cleanCookieDomain = cookie.domain.replace(/^\.+/, '').toLowerCase();
  const cleanPageHost = (pageHostname || '').toLowerCase();
  if (!cleanCookieDomain) return false;
  if (cookie.domain.startsWith('.') || cookie.hostOnly === false) return true;
  return cleanPageHost !== cleanCookieDomain && cleanPageHost.endsWith(`.${cleanCookieDomain}`);
}

/**
 * 要確認のセキュリティ診断項目から推奨対応ロードマップのMarkdown本文を組み立てる (v1.7.1 T02 / E3)
 */
function buildRoadmapSectionBody(securityChecks: readonly SecurityCheckResult[]): string {
  const attentionChecks = (securityChecks || []).filter((c) => isRequiresAttention(c));
  if (attentionChecks.length === 0) {
    return '> 対応が必要な項目はありません。';
  }

  const urgentChecks = attentionChecks.filter(
    (c) => c.severity === 'critical' || c.severity === 'high'
  );
  const plannedChecks = attentionChecks.filter((c) => c.severity === 'medium');
  const lowChecks = attentionChecks.filter(
    (c) => c.severity !== 'critical' && c.severity !== 'high' && c.severity !== 'medium'
  );

  const groups: Array<{ title: string; items: SecurityCheckResult[] }> = [
    { title: '至急対応 (CRITICAL / HIGH)', items: urgentChecks },
    { title: '計画的対応 (MEDIUM)', items: plannedChecks },
    { title: '継続的改善 (LOW)', items: lowChecks },
  ].filter((g) => g.items.length > 0);

  if (groups.length === 0) {
    return '> 対応が必要な項目はありません。';
  }

  return groups
    .map((group, idx) => {
      const lines = group.items.map((c) => {
        const firstSentence = extractFirstRecommendationSentence(c.recommendation);
        return `   - **${escapeMarkdownTableCell(c.name)}**: ${escapeMarkdownTableCell(firstSentence)}`;
      });
      return `${idx + 1}. **${group.title}:**\n${lines.join('\n')}`;
    })
    .join('\n');
}

/**
 * 調査レポートから Rev.2.1 準拠の 15セクション Markdown ドキュメントを生成する (Rev.2.1 IMP-12 / 11.3)
 *
 * @param report 今回の調査レポート
 * @param previousReport 前回の調査レポート（差分分析用・任意）
 * @param exceptions 登録された許容設定リスト（任意）
 * @returns Markdown文字列
 */
export function generateMarkdownReport(
  report: InspectionReport,
  previousReport?: InspectionReport | null,
  exceptions: FindingException[] = []
): string {
  const sanitizedUrl = sanitizeUrlForReport(report.url);
  const hostname = report.hostname;
  const inspectedDate = new Date(report.inspectedAt).toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo' });
  const extVer = report.extensionVersion || '1.7.0';
  const advDbVer = formatAdvisoryDbVersion(report.advisoryDatabaseVersion);

  // 差分分析の計算
  const diff = previousReport ? compareReportsEnhanced(previousReport, report) : null;

  const sections: string[] = [];

  // タイトル
  sections.push(`# Web Technology & Security Inspection Report\n\n**対象ホスト:** ${formatMarkdownCodeSpan(hostname)}  \n**調査実施日時:** ${inspectedDate} (JST)  \n**Inspector バージョン:** v${extVer} (Manifest V3)  \n**解析方式:** 受動的解析 (Passive Inspection) / 完全ローカル突合  \n\n---`);

  // 1. 調査概要
  sections.push(`## 1. 調査概要

| 項目 | 内容 |
|---|---|
| 対象URL | ${formatMarkdownCodeSpan(sanitizedUrl, { inTable: true })} |
| ホスト名 | ${formatMarkdownCodeSpan(hostname, { inTable: true })} |
| プロトコル | ${report.summary.isHttps ? 'HTTPS (暗号化通信)' : 'HTTP (非暗号化)'} |
| 診断ルールバージョン | ${escapeMarkdownTableCell(report.rulesVersion)} |
| オフライン脆弱性DBバージョン | ${escapeMarkdownTableCell(advDbVer)} |
| 要確認項目数 | **${report.summary.requiresAttentionCount} 件** |
| 検出技術スタック数 | **${report.summary.totalTechnologies} 件** |
`);

  // 2. 調査範囲・完全性 (IMP-08 / v1.7.1 T06)
  const cov = report.coverage;
  const statusLabel =
    cov?.overallStatus === 'complete'
      ? '完全 (Complete)'
      : cov?.overallStatus === 'partial'
      ? '一部制限あり (Partial)'
      : '未取得 (Unavailable)';
  const partialReasonsLine =
    cov?.overallStatus !== 'complete' &&
    cov?.details?.partialReasons &&
    cov.details.partialReasons.length > 0
      ? `\n- **部分的となった理由:** ${cov.details.partialReasons.map((r) => escapeMarkdownTableCell(r)).join(' / ')}`
      : '';
  sections.push(`## 2. 調査範囲・完全性 (Coverage)

- **完全性ステータス:** **${statusLabel}**${partialReasonsLine}
- **DOM / HTML解析:** ${cov?.dom === 'complete' ? '✅ 取得成功' : '⚠️ 一部または未取得'}
- **HTTPレスポンスヘッダー:** ${cov?.headers === 'complete' ? '✅ 取得成功' : '⚠️ 未取得 (キャッシュ/事前スキャンなし)'}
- **Cookie属性情報:** ${cov?.cookies === 'complete' ? `✅ 取得成功 (${report.cookies.length} 個観測)` : '⚠️ 権限なし/未取得'}
- **ネットワーク・通信解析:** ${cov?.network === 'complete' ? '✅ 取得成功' : '⚠️ 一部制限あり'}
${
  cov?.details?.missingPermissions && cov.details.missingPermissions.length > 0
    ? `\n> [!NOTE]\n> **未付与の権限:** ${cov.details.missingPermissions.map((s) => formatMarkdownCodeSpan(s)).join(', ')}\n`
    : ''
}
`);

  // 3. 調査結果サマリー
  sections.push(`## 3. 調査結果サマリー

### セキュリティ指摘レベル内訳
| 重大度 | 指摘件数 | 説明 |
|:---:|:---:|---|
| **CRITICAL (緊急)** | **${report.summary.securityFindings.critical ?? 0}** | 悪用確認済み脆弱性（CISA KEV）または緊急度の高い深刻な脆弱性 |
| **HIGH (危険)** | **${report.summary.securityFindings.high}** | 直ちに対応・修正が推奨される設定不備・脆弱性 |
| **MEDIUM (警告)** | **${report.summary.securityFindings.medium}** | セキュリティ基準に抵触、またはサポート終了の技術 |
| **LOW (注意)** | **${report.summary.securityFindings.low}** | 改善が望ましい設定上の軽微な不備 |
| **INFO (情報)** | **${report.summary.securityFindings.info}** | 参考情報・問題のない項目 |
`);

  const expandedTechnologies = expandTechnologyInstances(report.technologies || []);

  // 4. 検出技術スタック
  sections.push(`## 4. 検出技術スタック

> [!NOTE]
> **受動的調査の原則と推定関係:** 固有シグナルから直接検出された技術と、依存関係から連動検知された技術を明確に区分しています。外部からの受動観測ではサーバー内部の実行状態を直接観測できない技術は「稼働未確認」として記録しています。

| 技術名 | カテゴリ | バージョン | ディストリ版 | 検出方式 | 連動元 / 種別 | ランタイム状態 | 確信度 | 整合性 |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
${expandedTechnologies.length > 0 ? expandedTechnologies.map((t) => {
  const ver = t.isCandidateGroup ? 'いずれかの可能性' : t.version ? (/^\d/.test(t.version) ? `v${t.version}` : t.version) : '不明';
  const distro = t.distroHint ? formatMarkdownCodeSpan(t.distroHint, { inTable: true }) : '-';
  const method = t.isCandidateGroup || t.detectionMethod === 'associated' ? '候補・関連' : t.detectionMethod === 'inferred' ? '連動検知' : '直接検出';
  const relation = t.inferredFrom ? `${t.inferredFrom} (${t.implicationType || '連動'})` : '-';
  const runtime = t.runtimeStatus === 'confirmed' ? '稼働確認済' : t.runtimeStatus === 'possible' ? '稼働可能性あり' : t.runtimeStatus === 'unknown' ? '稼働未確認' : '-';
  const integrity = t.versionIntegrity?.status === 'mismatch' ? '⚠️ 不一致' : t.versionIntegrity?.status === 'match' ? '一致' : '-';
  return `| **${escapeMarkdownTableCell(t.technology)}** | ${escapeMarkdownTableCell(t.category)} | ${formatMarkdownCodeSpan(ver, { inTable: true })} | ${distro} | ${method} | ${escapeMarkdownTableCell(relation)} | ${runtime} | ${t.confidenceLevel} (${t.confidence}%) | ${integrity} |`;
}).join('\n') : '| なし | - | - | - | - | - | - | - | - |'}
`);

  // 5. セキュリティ診断結果
  sections.push(`## 5. セキュリティ診断結果

| 診断項目 | ステータス | 重大度 | 観測値 | 許容状態 |
|---|:---:|:---:|---|:---:|
${report.securityChecks.length > 0 ? report.securityChecks.map((c) => {
  const statBadge = formatMarkdownStatusBadge(c.status);
  const exBadge = c.exceptionStatus === 'accepted' ? '🛡️ 許容済' : c.exceptionStatus === 'false-positive' ? '❌ 誤検知除外' : '-';
  return `| ${escapeMarkdownTableCell(c.name)} | ${statBadge} | ${c.severity.toUpperCase()} | ${formatMarkdownCodeSpan(c.observed, { inTable: true })} | ${exBadge} |`;
}).join('\n') : '| なし | - | - | - | - |'}
`);

  // 6. EOL・既知脆弱性情報 (IMP-06 / SPEC-13)
  sections.push(`## 6. EOL・既知脆弱性情報 (ライブラリセキュリティ)

> [!IMPORTANT]
> オフライン脆弱性DBスナップショット (${escapeMarkdownTableCell(advDbVer)}) とのローカル突合結果です。未登録の技術は「安全」を意味するものではありません。

| 対象技術 | バージョン | ディストリ版 | サポート状況 (EOL) | 照合ステータス | 該当CVE/GHSA | 修正状況 (fixStatus) | CISA KEV | 推奨対応 |
|---|:---:|:---:|:---:|:---:|---|---|:---:|---|
${expandedTechnologies.length > 0 ? expandedTechnologies.map((t) => {
  const displayInfo = resolveTechAdvisoryDisplayInfo(t);
  const eol = t.eolInfo?.label
    ? escapeMarkdownTableCell(t.eolInfo.label)
    : t.supportStatus === 'EOL'
    ? `**EOL (${t.eolDate || '終了'})**`
    : t.supportStatus || 'Unknown';
  const matchStatus = escapeMarkdownTableCell(displayInfo.statusLabel);
  const distro = t.distroHint ? formatMarkdownCodeSpan(t.distroHint, { inTable: true }) : '-';
  const cveList = t.advisories && t.advisories.length > 0
    ? t.advisories.map((a) => {
        const advUrl = /^CVE-\d{4}-\d+$/i.test(a.id)
          ? `https://nvd.nist.gov/vuln/detail/${a.id}`
          : /^GHSA-[a-z0-9-]+$/i.test(a.id)
            ? `https://github.com/advisories/${a.id}`
            : a.referenceUrls?.find((u) => !(u.includes('nvd.nist.gov') && /\/GHSA-/i.test(u))) || '';
        const linkPart = advUrl ? `[${escapeMarkdownTableCell(a.id)}](${advUrl})` : escapeMarkdownTableCell(a.id);
        return `${linkPart} (${escapeMarkdownTableCell(String(a.severity).toLowerCase())})`;
      }).join(', ')
    : '-';
  const fixStatusCol = t.advisories && t.advisories.length > 0
    ? Array.from(new Set(t.advisories.map((a) => getEffectiveFixStatus(a)))).map((s) => formatMarkdownCodeSpan(s, { inTable: true })).join(', ')
    : '-';
  const kevIds = t.advisories
    ? t.advisories.filter((a) => a.kev === true).map((a) => escapeMarkdownTableCell(a.id))
    : [];
  const kevCol = t.advisories && t.advisories.length > 0
    ? kevIds.length > 0
      ? `**CISA KEV: ${kevIds.join(', ')}**`
      : 'なし'
    : '-';
  const isUnknownVersion =
    !t.version ||
    t.version.trim() === '' ||
    t.offlineMatchStatus === 'Unknown Version' ||
    (t.advisoryMatchStatus === 'Needs Review' && !displayInfo.isDistro);
  const recRaw = t.advisories && t.advisories.length > 0
    ? formatAdvisoryRecommendation(t.version, t.advisories, {
        isEol: t.supportStatus === 'EOL',
        technologyName: t.technology,
      })
    : t.eolInfo?.note
    ? t.eolInfo.note
    : t.supportStatus === 'EOL'
    ? hasLtsRelease(t.technology)
      ? '最新LTS系列への移行'
      : 'サポート中のメジャーバージョンへの移行'
    : displayInfo.isDistro
    ? `${t.distroHint || 'Linux'} ディストリビューションのセキュリティ情報を確認${typeof displayInfo.upstreamAdvisoriesCount === 'number' ? `（参考: 上流版では ${displayInfo.upstreamAdvisoriesCount} 件）` : ''}`
    : isUnknownVersion
    ? '評価不可（バージョン不明）'
    : displayInfo.isZeroCoverage
    ? '評価不可（収録対象外）'
    : '現状維持';
  const rec = escapeMarkdownTableCell(recRaw);
  return `| **${escapeMarkdownTableCell(t.technology)}** | ${formatMarkdownCodeSpan(t.version || '不明', { inTable: true })} | ${distro} | ${eol} | ${matchStatus} | ${cveList} | ${fixStatusCol} | ${kevCol} | ${rec} |`;
}).join('\n') : '| なし | - | - | - | - | - | - | - | - |'}
`);

  // 7. Cookie属性診断 (IMP-01 / IMP-04)
  const parentCookies = (report.cookies || []).filter((c) => isParentDomainCookie(c, hostname));
  const parentCookieNote =
    parentCookies.length > 0
      ? `※ **親ドメインのCookieに関する注記:** 親ドメインをスコープとするCookie（${parentCookies.map((c) => formatMarkdownCodeSpan(c.name)).join(', ')}）は、同一ドメイン配下の別サイト・別ページで発行された可能性があり、このページが設定したとは限らない点にご留意ください。`
      : '※ **親ドメインのCookieに関する注記:** 親ドメイン（上位ドメイン）をスコープとするCookieが含まれる場合、同一ドメイン配下の別サイト・別ページで発行された可能性があり、このページが設定したとは限らない点にご留意ください。';

  sections.push(`## 7. Cookie属性診断

※ **セキュリティ保護:** Cookieの値（Value）および認証シークレットは一切収集・出力していません。
${parentCookieNote}

| Cookie名 | ドメイン | パス | 用途分類 | Secure | HttpOnly | SameSite | CHIPS (Partitioned) |
|---|---|---|:---:|:---:|:---:|:---:|:---:|
${report.cookies.length > 0 ? report.cookies.map((c) => {
  return `| ${formatMarkdownCodeSpan(c.name, { inTable: true })} | ${formatMarkdownCodeSpan(c.domain || '-', { inTable: true })} | ${formatMarkdownCodeSpan(c.path || '-', { inTable: true })} | ${escapeMarkdownTableCell(normalizeCookieCategory(c.category))} | ${c.secure ? 'Yes' : '**No**'} | ${c.httpOnly ? 'Yes' : '**No**'} | ${formatMarkdownCodeSpan(c.sameSite || '-', { inTable: true })} | ${c.partitioned ? 'Yes' : 'No'} |`;
}).join('\n') : '| なし | - | - | - | - | - | - | - |'}
`);

  // 8. CSP診断 (IMP-02 / IMP-05 / v1.7.1 T10: ポリシーごとの問題点の表)
  const allCspPolicies = report.cspPolicies || [];
  const hasValidXfo = (report.securityChecks || []).some(
    (c) => c.checkId.startsWith('SEC-XFO-') && c.status === 'pass'
  );
  sections.push(`## 8. CSP（Content Security Policy）診断

- **CSPポリシー保持件数:** ${allCspPolicies.length} 件
${allCspPolicies.length > 0 ? allCspPolicies.map((p, idx) => {
  const policyIssues = evaluatePolicyIssuesWithIntersection(p, allCspPolicies, hasValidXfo);
  const issueBlock = policyIssues.length > 0
    ? `| ディレクティブ | 重大度 | 内容 | 推奨 |\n|---|:---:|---|---|\n${policyIssues.map((issue) => `| ${formatMarkdownCodeSpan(issue.directive, { inTable: true })} | ${issue.severity.toUpperCase()} | ${escapeMarkdownTableCell(issue.description)} | ${escapeMarkdownTableCell(issue.recommendation)} |`).join('\n')}`
    : '> このポリシーに検出された問題点はありません。';
  return `
#### ポリシー #${idx + 1} [取得元: ${p.source}, モード: ${p.mode}]
\`\`\`text
${p.rawValue}
\`\`\`

${issueBlock}
`;
}).join('\n') : '> CSPヘッダーまたはmetaタグによるCSPは設定されていません。'}
`);

  // 9. 外部通信先・サードパーティ分析 (IMP-11 / v1.7.1 T05: 読み込まれたリソースの取得元)
  const ext = report.externalConnections;
  sections.push(`## 9. 外部通信先・サードパーティ分析（読み込まれたリソースの取得元 / eTLD+1）

※ **集計対象:** ページ本体および実際に読み込まれたサブリソース（Performance Resource Timing API・DOMの \`script\` / \`stylesheet\` / \`preload\` / \`modulepreload\` / \`icon\` / \`manifest\` / 画像・メディア等）の取得元ホストを集計しています（\`alternate\`・\`canonical\`・\`dns-prefetch\`・\`preconnect\`・フォームの \`action\` 送信先など、読み込みを伴わない参照は含みません）。

- **総通信先ホスト数:** ${ext?.totalConnections ?? 0} 件
- **First-Party (同一組織・自社ドメイン):** ${ext?.firstPartyCount ?? 0} 件
- **Third-Party (外部サービス通信先):** ${ext?.thirdPartyCount ?? 0} 件

| 接続先ホスト名 | 登録可能ドメイン (eTLD+1) | 所属種別 | 推定カテゴリ | 観測リソース数 |
|---|---|:---:|:---:|:---:|
${ext && ext.connections.length > 0 ? ext.connections.map((item) => {
  const partyBadge = item.partyType === 'first-party' ? 'First-Party' : item.partyType === 'third-party' ? '**Third-Party**' : 'Local';
  return `| ${formatMarkdownCodeSpan(item.hostname, { inTable: true })} | ${formatMarkdownCodeSpan(item.registrableDomain, { inTable: true })} | ${partyBadge} | ${formatMarkdownCodeSpan(item.category, { inTable: true })} | ${item.resourceCount} |`;
}).join('\n') : '| 外部通信先は観測されませんでした | - | - | - | - |'}
`);

  // 10. 前回との差分 (IMP-09)
  sections.push(`## 10. 前回調査との差分 (Diff)

${diff ? `
- **前回調査日時:** ${new Date(diff.reportA.inspectedAt).toLocaleString('ja-JP')}
- **今回調査日時:** ${new Date(diff.reportB.inspectedAt).toLocaleString('ja-JP')}
- **新規検出技術:** ${diff.addedTechnologies.length > 0 ? diff.addedTechnologies.map((t) => formatMarkdownCodeSpan(t)).join(', ') : 'なし'}
- **消失技術:** ${diff.removedTechnologies.length > 0 ? diff.removedTechnologies.map((t) => formatMarkdownCodeSpan(t)).join(', ') : 'なし'}
- **新規発生した指摘:** ${diff.newSecurityIssues.length > 0 ? diff.newSecurityIssues.map((s) => formatMarkdownCodeSpan(s)).join(', ') : 'なし'}
- **解消された指摘:** ${diff.resolvedSecurityIssues.length > 0 ? diff.resolvedSecurityIssues.map((s) => formatMarkdownCodeSpan(s)).join(', ') : 'なし'}
` : '> 前回調査レポートとの比較は実行されていません（初回調査または単一レポート出力）。'}
`);

  // 11. 差分発生原因 (IMP-09)
  sections.push(`## 11. 差分発生原因の推定分析

${!diff
  ? '> 比較未実行のため対象外です（前回調査レポートとの比較は実行されていません）。'
  : diff.diffItems.length > 0
  ? `
| 変化項目 | 差分種別 | 推定原因 | 変化内容 | 詳細解説 |
|---|:---:|:---:|---|---|
${diff.diffItems.map((item: DetailedDiffItem) => {
  return `| **${escapeMarkdownTableCell(item.target)}** | ${formatMarkdownCodeSpan(item.diffType, { inTable: true })} | ${formatMarkdownCodeSpan(item.diffCause, { inTable: true })} | ${formatMarkdownCodeSpan(item.before || '-', { inTable: true })} &rarr; ${formatMarkdownCodeSpan(item.after || '-', { inTable: true })} | ${escapeMarkdownTableCell(item.causeExplanation)} |`;
}).join('\n')}
`
  : '> 分析対象の有意な差分変化はありません。'}
`);

  // 12. 許容・除外設定 (IMP-10)
  sections.push(`## 12. 診断項目の許容・除外設定 (Finding Exceptions)

${exceptions.length > 0 ? `
| 状態 | 対象安定ID (FindingId) | 適用スコープ | 許容理由 | 登録日 |
|:---:|---|---|---|:---:|
${exceptions.map((ex) => {
  const stLabel = ex.status === 'accepted' ? 'リスク許容' : ex.status === 'false-positive' ? '誤検知' : '通知抑制';
  return `| **${stLabel}** | ${formatMarkdownCodeSpan(ex.findingId, { inTable: true })} | ${formatMarkdownCodeSpan(ex.targetUrl || '全体適用', { inTable: true })} | ${escapeMarkdownTableCell(ex.reason)} | ${ex.createdAt ? ex.createdAt.slice(0, 10) : '-'} |`;
}).join('\n')}
` : '> 現在適用されている許容・除外設定はありません。'}
`);

  // 13. 推奨対応ロードマップ
  sections.push(`## 13. 推奨対応ロードマップ

${buildRoadmapSectionBody(report.securityChecks)}
`);

  // 14. 検出根拠 (エビデンス)
  const formatTechEvidenceSection = (t: DetectedTechnology): string => {
    const rawEvidences: Evidence[] = Array.isArray(t.evidence) ? t.evidence : [];
    const hasNonGeneric = rawEvidences.some((e) => !isGenericClassEvidence(e));
    const displayEvidences = hasNonGeneric
      ? rawEvidences.filter((e) => !isGenericClassEvidence(e))
      : rawEvidences;

    const visibleEvidences = displayEvidences.slice(0, 3);
    const remainingCount = displayEvidences.length - visibleEvidences.length;
    const evidenceLines = visibleEvidences.map(
      (e) =>
        `- **[${e.type}]** ${formatMarkdownCodeSpan(e.name)}: ${formatMarkdownCodeSpan(e.value)} ${e.detail ? `(${escapeMarkdown(e.detail)})` : ''}`
    );
    if (remainingCount > 0) {
      evidenceLines.push(`- 他 ${remainingCount} 件`);
    }

    if (t.wpPlugins && t.wpPlugins.length > 0) {
      const pluginList = t.wpPlugins
        .map((p) =>
          p.version
            ? `${formatMarkdownCodeSpan(p.name)} (ver: ${formatMarkdownCodeSpan(p.version)})`
            : formatMarkdownCodeSpan(p.name)
        )
        .join(', ');
      evidenceLines.push(`- **検出されたプラグイン:** ${pluginList}`);
    }

    if (t.wpThemes && t.wpThemes.length > 0) {
      const themeList = t.wpThemes
        .map((th) =>
          th.version
            ? `${formatMarkdownCodeSpan(th.name)} (ver: ${formatMarkdownCodeSpan(th.version)})`
            : formatMarkdownCodeSpan(th.name)
        )
        .join(', ');
      evidenceLines.push(`- **検出されたテーマ:** ${themeList}`);
    }

    return `\n### ${t.technology} (確信度: ${t.confidenceLevel} - ${t.confidence}%)\n${evidenceLines.join('\n')}\n`;
  };

  sections.push(`## 14. 検出根拠 (エビデンス詳細)

${report.technologies.map(formatTechEvidenceSection).join('\n')}
`);

  // 15. 調査上の制限事項
  sections.push(`## 15. 調査上の制限事項・免責事項

1. **受動的解析のスコープ:**
   本拡張機能は、ブラウザが通常のWeb閲覧時に受信したHTML、CSS、JavaScript、HTTPヘッダー、Cookie属性のみを受動的に解析（Passive Inspection）しています。外部サーバーへの攻撃的なリクエスト送信や内部ソースコードの監査は行っていません。
2. **脆弱性DBの網羅性:**
   オフライン脆弱性DBに未収録のライブラリや独自フレームワークについて「脆弱性なし」と判定されていても、安全性を完全に保証するものではありません。
3. **認証後ページの扱い:**
   ログインや特定セッションを必要とする深層ページは、閲覧した範囲に限定して診断されます。
4. **機密情報の非保持:**
   Cookieの値、認証トークン、Authorizationヘッダーなどのシークレット情報はメモリ保持およびレポート出力から完全に除外されています。
5. **TLS/SSL証明書の検証対象外:**
   本拡張機能は通信プロトコル（HTTPS/HTTP）およびヘッダー設定を確認しますが、TLS/SSL証明書の有効期限や信頼性（失効状態・発行元認証局の妥当性など）は診断しないため、証明書の有効性は対象外です。
`);

  return sections.join('\n\n');
}

/**
 * 生成したMarkdownレポートをブラウザからファイルとしてダウンロードする
 */
export function downloadMarkdownReport(
  report: InspectionReport,
  previousReport?: InspectionReport | null,
  exceptions: FindingException[] = []
): void {
  const content = generateMarkdownReport(report, previousReport, exceptions);
  const blob = new Blob([content], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);

  const cleanHost = report.hostname.replace(/[^a-zA-Z0-9.-]/g, '_');
  const dateStr = new Date(report.inspectedAt).toISOString().slice(0, 10);
  const filename = `web-inspector-report-${cleanHost}-${dateStr}.md`;

  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
